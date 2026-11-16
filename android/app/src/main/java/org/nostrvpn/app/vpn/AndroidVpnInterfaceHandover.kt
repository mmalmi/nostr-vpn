package org.nostrvpn.app.vpn

import android.os.Handler
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import org.nostrvpn.app.AndroidConfigChangeObserver
import java.io.File

/**
 * Keeps the VPN interface of a running tunnel in step with the routes and
 * resolvers the native runtime applies.
 *
 * The runtime applies signed roster updates in-process and saves the config
 * afterwards. A changed member set changes the routes, so the service
 * re-establishes the interface itself, also while the app is closed.
 * Establishing a second interface is Android's handover: the current
 * interface keeps routing until the replacement is up, then outgoing packets
 * move to the replacement and the previous interface goes down.
 */
internal class AndroidVpnInterfaceHandover(
    private val handler: Handler,
    private val configFile: File,
    private val tunnel: Tunnel,
) {
    interface Tunnel {
        /** Interface settings the running tunnel applies; null when none runs. */
        fun interfaceSettingsJson(): String?

        fun establishInterface(config: JSONObject): ParcelFileDescriptor?

        fun replaceInterface(fd: Int): Boolean

        fun restart()
    }

    // Config the current VPN interface was built from.
    private var interfaceConfig: JSONObject? = null
    private var configChangeObserver: AndroidConfigChangeObserver? = null
    private val refreshRunnable = Runnable { refresh() }

    // An established VPN interface that nothing reads. It is held while the
    // tunnel recovers from a failed handover, so its routes keep traffic off
    // the device network until a working interface replaces it.
    private var blockingInterface: ParcelFileDescriptor? = null
    private val recoverRunnable = Runnable {
        if (blockingInterface != null) {
            tunnel.restart()
        }
    }

    val recovering: Boolean
        get() = blockingInterface != null

    /** Follows the settings of a tunnel that now runs on the interface built from [config]. */
    fun watch(config: JSONObject) {
        releaseBlockingInterface()
        stopWatching()
        interfaceConfig = config
        configChangeObserver = AndroidConfigChangeObserver(configFile) {
            handler.removeCallbacks(refreshRunnable)
            handler.postDelayed(refreshRunnable, REFRESH_DEBOUNCE_MILLIS)
        }.also { it.start() }
        // Catch a roster the runtime applied while the interface was built.
        handler.post(refreshRunnable)
    }

    fun stopWatching() {
        configChangeObserver?.stop()
        configChangeObserver = null
        handler.removeCallbacks(refreshRunnable)
        interfaceConfig = null
    }

    private fun refresh() {
        val baseConfig = interfaceConfig
        if (baseConfig == null || blockingInterface != null) {
            return
        }
        val settingsJson = tunnel.interfaceSettingsJson() ?: return
        val settings = runCatching { JSONObject(settingsJson) }.getOrNull()
        if (settings == null || settings.optString("error").isNotBlank()) {
            Log.w(TAG, "Native interface settings unavailable: $settingsJson")
            return
        }
        if (fingerprint(settings) == fingerprint(baseConfig)) {
            return
        }
        val config = JSONObject(baseConfig.toString())
        for (key in SETTINGS_KEYS) {
            config.put(key, settings.get(key))
        }
        val descriptor = runCatching { tunnel.establishInterface(config) }.getOrElse { error ->
            Log.w(TAG, "Invalid updated VPN interface settings", error)
            null
        }
        if (descriptor == null) {
            // The current interface and its routes stay in place, so a
            // selected exit keeps carrying the device's traffic.
            Log.w(TAG, "Keeping the current VPN interface; updated routes could not be installed")
            handler.removeCallbacks(refreshRunnable)
            handler.postDelayed(refreshRunnable, RETRY_MILLIS)
            return
        }
        if (!handToNative(descriptor, tunnel::replaceInterface)) {
            // Android already moved routing to the replacement and took the
            // previous interface down. Keep the replacement open so its
            // routes block until the restarted tunnel has an interface.
            Log.w(TAG, "Native tunnel rejected the replacement VPN interface; restarting")
            holdBlockingInterface(descriptor)
            tunnel.restart()
            return
        }
        interfaceConfig = config
        Log.i(TAG, "VPN interface re-established with routes ${settings.optJSONArray("routeTargets")}")
    }

    /**
     * Native code owns the descriptor it is handed and closes it when it
     * rejects it. It gets a duplicate, so an established interface outlives
     * a rejection.
     */
    fun handToNative(descriptor: ParcelFileDescriptor, attach: (Int) -> Boolean): Boolean {
        val attached = runCatching { attach(descriptor.dup().detachFd()) }.getOrElse { error ->
            Log.w(TAG, "VPN interface descriptor could not be duplicated", error)
            false
        }
        if (attached) {
            descriptor.close()
        }
        return attached
    }

    /**
     * Establishing an interface takes the blocking interface down, so an
     * interface the restarted tunnel rejects has to block in its place.
     */
    fun holdOrCloseRejectedInterface(descriptor: ParcelFileDescriptor) {
        if (blockingInterface != null) {
            holdBlockingInterface(descriptor)
        } else {
            descriptor.close()
        }
    }

    /** A restart during recovery failed: stay behind the blocking interface and try again. */
    fun retryRecovery() {
        handler.removeCallbacks(recoverRunnable)
        handler.postDelayed(recoverRunnable, RETRY_MILLIS)
    }

    fun releaseBlockingInterface() {
        handler.removeCallbacks(recoverRunnable)
        runCatching { blockingInterface?.close() }
        blockingInterface = null
    }

    private fun holdBlockingInterface(descriptor: ParcelFileDescriptor) {
        runCatching { blockingInterface?.close() }
        blockingInterface = descriptor
    }

    private fun fingerprint(config: JSONObject): String =
        SETTINGS_KEYS.joinToString("\n") { key -> config.opt(key)?.toString().orEmpty() }

    private companion object {
        const val TAG = "NostrVpnService"
        const val REFRESH_DEBOUNCE_MILLIS = 500L
        const val RETRY_MILLIS = 15_000L
        val SETTINGS_KEYS = listOf("routeTargets", "dnsServers", "magicDnsServer", "dnsMatchDomains")
    }
}
