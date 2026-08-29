package org.nostrvpn.app.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import org.json.JSONObject
import org.nostrvpn.app.AndroidLegacyPackageMigration
import org.nostrvpn.app.TunnelConfigRefreshPolicy
import org.nostrvpn.app.appCoreDataDir
import org.nostrvpn.app.core.NativeCore
import org.nostrvpn.app.seedMobileConfig
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class NostrVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private val tunnelStartGeneration = AtomicLong()
    private val tunnelStartExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "nvpn-mobile-start")
    }
    private var tunnelHandle: Long = 0
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private val underlyingNetworkHandler = Handler(Looper.getMainLooper())
    private var underlyingNetworkFingerprint: String? = null
    private var retryUnderlyingNetworkFingerprint: String? = null
    private var underlyingNetworkRetryCount = 0
    private var pendingUnderlyingNetworkRefreshDelayMillis: Long? = null
    private var queuedApprovalRestartPending = false
    private var queuedApprovalRestartDeadlineMillis = 0L
    private var queuedApprovalRestartForegroundStarted = false
    private val refreshUnderlyingNetworksRunnable = Runnable {
        pendingUnderlyingNetworkRefreshDelayMillis = null
        refreshUnderlyingNetworks(resetRetryBudget = true)
    }
    private val refreshNativeNetworkPathsRunnable = Runnable {
        refreshUnderlyingNetworks(resetRetryBudget = false)
    }
    private val drainQueuedApprovalBeforeRestartRunnable = Runnable {
        continueTunnelRestartAfterQueuedApprovalDrain()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val foregroundRequired =
            AndroidVpnServiceStartContract.requiresImmediateForeground(intent?.action)
        val foregroundStarted = foregroundRequired && startServiceForeground()
        if (foregroundRequired && !foregroundStarted) {
            tunnelOwnedInProcess.set(false)
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_DISCONNECT) {
            val conflicts = AndroidLegacyPackageMigration.packagesToRemove(this)
            if (conflicts.isNotEmpty()) {
                Log.e(
                    "NostrVpnService",
                    "Refusing Android VPN start while conflicting nVPN packages remain: " +
                        conflicts.joinToString(),
                )
                VpnStartState.setUserWantsVpn(this, false)
                tunnelOwnedInProcess.set(false)
                tunnelStartGeneration.incrementAndGet()
                stopTunnel()
                stopServiceForeground()
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        return when (intent?.action) {
            ACTION_DISCONNECT -> {
                VpnStartState.setUserWantsVpn(this, false)
                tunnelOwnedInProcess.set(false)
                tunnelStartGeneration.incrementAndGet()
                stopTunnel()
                stopServiceForeground()
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                VpnStartState.setUserWantsVpn(this, true)
                startTunnelAsync(
                    intent.getStringExtra(EXTRA_CONFIG_JSON).orEmpty(),
                    foregroundStarted = foregroundStarted,
                ).stickyResult()
            }
            ACTION_RESTORE -> {
                if (!VpnStartState.userWantsVpn(this)) {
                    tunnelOwnedInProcess.set(false)
                    stopServiceForeground()
                    stopSelf()
                    START_NOT_STICKY
                } else {
                    startTunnelAsync(
                        persistedTunnelConfigJson(),
                        foregroundStarted = foregroundStarted,
                    ).stickyResult()
                }
            }
            VpnService.SERVICE_INTERFACE -> {
                // Android starts the service with this action for OS Always-on VPN.
                val configJson = persistedTunnelConfigJson()
                if (!AndroidVpnRoutingPolicy.supportsAlwaysOnVpn(configJson)) {
                    VpnStartState.setUserWantsVpn(this, false)
                    tunnelOwnedInProcess.set(false)
                    tunnelStartGeneration.incrementAndGet()
                    publishAlwaysOnSplitUnsupportedNotification()
                    stopSelf()
                    return START_NOT_STICKY
                }
                VpnStartState.setUserWantsVpn(this, true)
                startTunnelAsync(
                    configJson,
                    foregroundStarted = foregroundStarted,
                ).stickyResult()
            }
            else -> {
                if (VpnStartState.userWantsVpn(this)) {
                    startTunnelAsync(
                        persistedTunnelConfigJson(),
                        foregroundStarted = foregroundStarted,
                    ).stickyResult()
                } else {
                    tunnelOwnedInProcess.set(false)
                    stopServiceForeground()
                    stopSelf(startId)
                    START_NOT_STICKY
                }
            }
        }
    }

    override fun onDestroy() {
        tunnelOwnedInProcess.set(false)
        tunnelStartGeneration.incrementAndGet()
        tunnelStartExecutor.shutdownNow()
        stopTunnel()
        stopServiceForeground()
        super.onDestroy()
    }

    override fun onRevoke() {
        VpnStartState.setUserWantsVpn(this, false)
        tunnelOwnedInProcess.set(false)
        tunnelStartGeneration.incrementAndGet()
        stopTunnel()
        stopServiceForeground()
        super.onRevoke()
    }

    private fun startTunnelAsync(
        configJson: String,
        foregroundStarted: Boolean,
        allowQueuedApprovalDeferral: Boolean = true,
    ): Boolean {
        tunnelOwnedInProcess.set(true)
        if (configJson.isBlank()) {
            return failStart(foregroundStarted, "VPN config is empty")
        }
        NativeCore.initializeAndroidContext(applicationContext)

        val config = try {
            JSONObject(configJson)
        } catch (error: Exception) {
            return failStart(foregroundStarted, "VPN config JSON could not be parsed", error)
        }
        val configError = config.optString("error")
        if (configError.isNotBlank()) {
            return failStart(foregroundStarted, configError)
        }
        val lockdownActive = currentLockdownActive()
        VpnStartState.setLockdownActive(this, lockdownActive)
        if (lockdownActive && !AndroidVpnRoutingPolicy.hasDefaultRoute(config)) {
            Log.w(
                "NostrVpnService",
                "Android VPN lockdown is active without a default internet route; non-nvpn internet will be blocked",
            )
        }
        val tunnelConfigJson = config.toString()
        if (
            allowQueuedApprovalDeferral &&
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = running.get(),
                configJson = tunnelConfigJson,
            )
        ) {
            deferTunnelRestartUntilQueuedApprovalDrains(foregroundStarted)
            return true
        }

        cancelQueuedApprovalRestart()
        stopTunnel()
        val generation = tunnelStartGeneration.incrementAndGet()
        return runCatching {
            tunnelStartExecutor.execute {
                val handle = NativeCore.mobileTunnelNew(tunnelConfigJson)
                if (
                    generation != tunnelStartGeneration.get() ||
                    !VpnStartState.userWantsVpn(this)
                ) {
                    if (handle != 0L) {
                        NativeCore.mobileTunnelFree(handle)
                    }
                    return@execute
                }
                if (!underlyingNetworkHandler.post {
                        finishTunnelStart(
                            generation = generation,
                            handle = handle,
                            config = config,
                            foregroundStarted = foregroundStarted,
                        )
                    }
                ) {
                    if (handle != 0L) {
                        NativeCore.mobileTunnelFree(handle)
                    }
                }
            }
        }.onFailure { error ->
            failStart(foregroundStarted, "Android VPN startup worker failed", error)
        }.isSuccess
    }

    private fun deferTunnelRestartUntilQueuedApprovalDrains(foregroundStarted: Boolean) {
        if (!queuedApprovalRestartPending) {
            queuedApprovalRestartDeadlineMillis =
                SystemClock.elapsedRealtime() + QUEUED_APPROVAL_RESTART_MAX_DELAY_MILLIS
        }
        queuedApprovalRestartPending = true
        queuedApprovalRestartForegroundStarted =
            queuedApprovalRestartForegroundStarted || foregroundStarted
        underlyingNetworkHandler.removeCallbacks(drainQueuedApprovalBeforeRestartRunnable)
        underlyingNetworkHandler.postDelayed(
            drainQueuedApprovalBeforeRestartRunnable,
            QUEUED_APPROVAL_RESTART_POLL_MILLIS,
        )
    }

    private fun continueTunnelRestartAfterQueuedApprovalDrain() {
        if (!queuedApprovalRestartPending) {
            return
        }
        val latestConfigJson = persistedTunnelConfigJson()
        val deadlineReached =
            SystemClock.elapsedRealtime() >= queuedApprovalRestartDeadlineMillis
        if (
            !deadlineReached &&
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = running.get(),
                configJson = latestConfigJson,
            )
        ) {
            underlyingNetworkHandler.postDelayed(
                drainQueuedApprovalBeforeRestartRunnable,
                QUEUED_APPROVAL_RESTART_POLL_MILLIS,
            )
            return
        }
        val foregroundStarted = queuedApprovalRestartForegroundStarted
        cancelQueuedApprovalRestart()
        startTunnelAsync(
            latestConfigJson,
            foregroundStarted,
            allowQueuedApprovalDeferral = !deadlineReached,
        )
    }

    private fun cancelQueuedApprovalRestart() {
        underlyingNetworkHandler.removeCallbacks(drainQueuedApprovalBeforeRestartRunnable)
        queuedApprovalRestartPending = false
        queuedApprovalRestartDeadlineMillis = 0L
        queuedApprovalRestartForegroundStarted = false
    }

    private fun finishTunnelStart(
        generation: Long,
        handle: Long,
        config: JSONObject,
        foregroundStarted: Boolean,
    ) {
        if (
            generation != tunnelStartGeneration.get() ||
            !VpnStartState.userWantsVpn(this)
        ) {
            if (handle != 0L) {
                NativeCore.mobileTunnelFree(handle)
            }
            return
        }
        if (handle == 0L) {
            failStart(foregroundStarted, "Native mobile tunnel failed to start")
            return
        }
        if (!foregroundStarted) {
            publishTunnelNotification()
        }
        reconcileMulticastLock(config)
        val descriptor = buildVpnInterface(config) ?: run {
            NativeCore.mobileTunnelFree(handle)
            releaseMulticastLock()
            failStart(foregroundStarted, "Android VPN interface could not be established")
            return
        }

        // If the user has WG upstream enabled, the boringtun runtime
        // owns a UDP socket that talks to the Mullvad/Proton server.
        // That socket has to escape the VPN tun (otherwise the
        // encrypted UDP loops back into our own tunnel), which on
        // Android means calling VpnService.protect(socketFd). The
        // Rust side exposes the fd via the JNI binding below; -1 means
        // WG upstream isn't running so there's nothing to protect.
        val wgSocketFd = NativeCore.mobileTunnelWgSocketFd(handle)
        Log.i(
            "NostrVpnService",
            "WG upstream socket fd from native runtime: $wgSocketFd (-1 means WG upstream not running)",
        )
        if (wgSocketFd >= 0) {
            val protected_ = protect(wgSocketFd)
            Log.i(
                "NostrVpnService",
                "VpnService.protect(wgSocketFd=$wgSocketFd) returned $protected_",
            )
            if (!protected_) {
                descriptor.close()
                NativeCore.mobileTunnelFree(handle)
                releaseMulticastLock()
                failStart(
                    foregroundStarted,
                    "VpnService.protect(wgSocketFd=$wgSocketFd) failed; aborting VPN start",
                )
                return
            }
        }

        val tunFd = descriptor.detachFd()
        if (!NativeCore.mobileTunnelAttachTunFd(handle, tunFd)) {
            NativeCore.mobileTunnelFree(handle)
            releaseMulticastLock()
            failStart(foregroundStarted, "Native mobile tunnel rejected Android TUN fd")
            return
        }

        tunnelHandle = handle
        running.set(true)
        registerUnderlyingNetworkUpdates()
    }

    private fun Boolean.stickyResult(): Int =
        if (this) START_STICKY else START_NOT_STICKY

    private fun failStart(
        foregroundStarted: Boolean,
        message: String,
        error: Throwable? = null,
    ): Boolean {
        if (error == null) {
            Log.w("NostrVpnService", message)
        } else {
            Log.w("NostrVpnService", message, error)
        }
        if (!running.get()) {
            tunnelOwnedInProcess.set(false)
            if (foregroundStarted) {
                stopServiceForeground()
            } else {
                clearTunnelNotification()
            }
            stopSelf()
        }
        return false
    }

    private fun persistedTunnelConfigJson(): String {
        NativeCore.initializeAndroidContext(applicationContext)
        val dataDir = appCoreDataDir(this)
        seedMobileConfig(dataDir)
        return NativeCore.mobileTunnelConfigJson(dataDir.absolutePath)
    }

    private fun buildVpnInterface(config: JSONObject): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Nostr VPN")
            .setConfigureIntent(AndroidVpnNotifications.configureIntent(this))
            .setMtu(config.optInt("mtu", 1150))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val wireGuardExitActive = config.optJSONObject("wireguardExit") != null
        val underlyingNetworks = currentUnderlyingNetworks()
        if (!wireGuardExitActive && underlyingNetworks.isNotEmpty()) {
            builder.setUnderlyingNetworks(underlyingNetworks)
        }
        // The WG transport socket is protected after native startup. Keeping
        // this process inside the VPN lets app-owned secure DNS use the exit;
        // FIPS/direct/split transports still need the process-level escape.
        if (AndroidVpnRoutingPolicy.excludesOwnProcess(wireGuardExitActive)) {
            excludeOwnProcess(builder)
        }

        val local = parseCidr(config.optString("localAddress", "10.44.0.1/32")) ?: return null
        builder.addAddress(local.address, local.prefix)

        val routeTargets = AndroidVpnRoutingPolicy.routeTargets(config)
        if (AndroidVpnRoutingPolicy.requiresBypass(routeTargets)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                // Always-on VPN ignores allowBypass(). Explicitly excluding
                // both internet defaults keeps unmatched traffic on the
                // device network while the more-specific mesh routes below
                // still enter the tunnel.
                for (route in AndroidVpnRoutingPolicy.excludedDeviceInternetRoutes(routeTargets)) {
                    AndroidVpnRoutingPolicy.parseIpPrefix(route)?.let(builder::excludeRoute)
                }
            } else {
                // On older Android releases this is the available split-VPN
                // mechanism. Always-on without lockdown may still choose the
                // device network for unmatched routes.
                builder.allowBypass()
            }
        }
        for (target in routeTargets) {
            val route = parseCidr(target)
            if (route != null) {
                builder.addRoute(route.address, route.prefix)
            }
        }
        addDnsServers(builder, config, routeTargets)

        // When WG upstream or a Nostr peer exit is on, the Rust runtime
        // expanded routeTargets to 0.0.0.0/0 so all traffic enters the tun.
        // Android doesn't have an `excludedRoutes` equivalent — we
        // rely on `protect(socketFd)` for WG upstream instead (called below
        // after the tunnel handle is created). The excludedRoutes JSON field
        // is therefore informational on Android for that mode; the actual
        // escape mechanism is the protected socket.

        return runCatching {
            builder.establish()
        }.onFailure { error ->
            Log.w("NostrVpnService", "Failed to establish Android VPN interface", error)
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun currentUnderlyingNetworks(): Array<Network> {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return emptyArray()
        val candidates = linkedSetOf<Network>()
        connectivity.activeNetwork?.let { candidates.add(it) }
        candidates.addAll(connectivity.allNetworks)
        return candidates.filter { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@filter false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }.toTypedArray()
    }

    private fun excludeOwnProcess(builder: Builder) {
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            // The package must exist for a running service; ignore impossible platform races.
        }
    }

    private fun addDnsServers(
        builder: Builder,
        config: JSONObject,
        routeTargets: List<String>,
    ) {
        // VpnService has no suffix-scoped DNS API. Installing the MagicDNS
        // stub while only mesh routes are captured makes it Android's global
        // resolver and can break ordinary Internet even though no exit is
        // selected. Direct/split mode must retain the device resolver.
        if (!AndroidVpnRoutingPolicy.installsVpnDns(routeTargets)) {
            return
        }
        val servers = config.optJSONArray("dnsServers") ?: return
        val magicDnsServer = config.optString("magicDnsServer").trim()
        val selected = mutableListOf<String>()
        for (index in 0 until servers.length()) {
            val server = servers.optString(index).trim()
            if (server.isEmpty()) continue
            selected.add(server)
        }
        val effectiveServers = if (magicDnsServer.isNotEmpty() && selected.any { it == magicDnsServer }) {
            listOf(magicDnsServer)
        } else {
            selected
        }
        for (server in effectiveServers) {
            runCatching {
                builder.addDnsServer(server)
            }.onFailure { error ->
                Log.w("NostrVpnService", "Ignoring invalid VPN DNS server: $server", error)
            }
        }
    }

    private fun currentLockdownActive(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && runCatching {
            isLockdownEnabled
        }.getOrDefault(false)

    private fun registerUnderlyingNetworkUpdates() {
        unregisterUnderlyingNetworkUpdates()
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scheduleUnderlyingNetworkRefresh(immediate = true)
            }

            override fun onLost(network: Network) {
                scheduleUnderlyingNetworkRefresh()
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                scheduleUnderlyingNetworkRefresh()
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: LinkProperties,
            ) {
                scheduleUnderlyingNetworkRefresh(
                    immediate = linkProperties.routes.any { it.isDefaultRoute } &&
                        connectivity.getNetworkCapabilities(network)
                            ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) != true,
                )
            }
        }
        try {
            refreshUnderlyingNetworks(resetRetryBudget = true)
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            connectivity.registerNetworkCallback(request, callback, underlyingNetworkHandler)
            networkCallback = callback
        } catch (_: RuntimeException) {
            networkCallback = null
            resetUnderlyingNetworkRefreshState()
        }
    }

    private fun unregisterUnderlyingNetworkUpdates() {
        underlyingNetworkHandler.removeCallbacks(refreshUnderlyingNetworksRunnable)
        underlyingNetworkHandler.removeCallbacks(refreshNativeNetworkPathsRunnable)
        resetUnderlyingNetworkRefreshState()
        val callback = networkCallback ?: return
        networkCallback = null
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        try {
            connectivity.unregisterNetworkCallback(callback)
        } catch (_: RuntimeException) {
            // The callback may already be gone during service teardown.
        }
    }

    private fun reconcileMulticastLock(config: JSONObject) {
        if (!shouldHoldMulticastLock(config)) {
            releaseMulticastLock()
            return
        }
        acquireMulticastLock()
    }

    private fun shouldHoldMulticastLock(config: JSONObject): Boolean {
        if (!config.optBoolean("shareLocalCandidates", false)) return false
        if (!config.optBoolean("nostrDiscoveryEnabled", false)) return false
        val hasPeers = (config.optJSONArray("peers")?.length() ?: 0) > 0
        val joinRequestsEnabled = config.optBoolean("joinRequestsEnabled", false)
        val pendingJoinRequest =
            config.optString("pendingJoinRequestRecipient").isNotBlank() &&
                config.optLong("pendingJoinRequestedAt", 0) != 0L
        return hasPeers || joinRequestsEnabled || pendingJoinRequest
    }

    private fun acquireMulticastLock() {
        if (multicastLock != null) return
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        multicastLock = wifi.createMulticastLock("nostr-vpn-lan-discovery").apply {
            setReferenceCounted(false)
            runCatching { acquire() }
        }
    }

    private fun releaseMulticastLock() {
        val lock = multicastLock ?: return
        multicastLock = null
        runCatching {
            if (lock.isHeld) {
                lock.release()
            }
        }
    }

    private fun scheduleUnderlyingNetworkRefresh(immediate: Boolean = false) {
        val pendingDelayMillis = pendingUnderlyingNetworkRefreshDelayMillis
        val delayMillis = AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(
            pendingDelay = pendingDelayMillis,
            immediate = immediate,
            delayedRefresh = UNDERLAY_NETWORK_CHANGE_DEBOUNCE_MILLIS,
        ) ?: return
        if (pendingUnderlyingNetworkRefreshDelayMillis != null) {
            underlyingNetworkHandler.removeCallbacks(refreshUnderlyingNetworksRunnable)
        }
        pendingUnderlyingNetworkRefreshDelayMillis = delayMillis
        if (delayMillis == 0L) {
            underlyingNetworkHandler.post(refreshUnderlyingNetworksRunnable)
        } else {
            underlyingNetworkHandler.postDelayed(
                refreshUnderlyingNetworksRunnable,
                delayMillis,
            )
        }
    }

    private fun refreshUnderlyingNetworks(resetRetryBudget: Boolean) {
        val handle = tunnelHandle
        if (!running.get() || handle == 0L) return
        val wireGuardSocketFd = NativeCore.mobileTunnelWgSocketFd(handle)
        val candidates = currentUnderlyingNetworks()
        val wireGuardNetwork =
            if (wireGuardSocketFd >= 0) {
                preferredWireGuardUnderlyingNetwork(candidates)
            } else {
                null
            }
        val reportedNetworks =
            if (wireGuardSocketFd >= 0) {
                wireGuardNetwork?.let { arrayOf(it) } ?: emptyArray()
            } else {
                candidates
            }
        val fingerprint = currentUnderlyingNetworkFingerprint(reportedNetworks)
        val previousFingerprint = underlyingNetworkFingerprint
        if (fingerprint == previousFingerprint) {
            clearUnderlyingNetworkRetry()
            return
        }
        val physicalNetworkChanged = AndroidVpnRoutingPolicy.isPhysicalNetworkChange(
            previousFingerprint = previousFingerprint,
            currentFingerprint = fingerprint,
        )
        if (resetRetryBudget || retryUnderlyingNetworkFingerprint != fingerprint) {
            retryUnderlyingNetworkFingerprint = fingerprint
            underlyingNetworkRetryCount = 0
        }

        if (wireGuardSocketFd >= 0) {
            if (wireGuardNetwork == null) {
                if (setUnderlyingNetworks(emptyArray())) {
                    markUnderlyingNetworkApplied(fingerprint)
                }
                return
            }
            if (!bindWireGuardUpstreamToNetwork(wireGuardSocketFd, wireGuardNetwork)) {
                scheduleNativeNetworkPathRetry(fingerprint)
                return
            }
            if (!setUnderlyingNetworks(arrayOf(wireGuardNetwork))) {
                scheduleNativeNetworkPathRetry(fingerprint)
                return
            }
        } else {
            setUnderlyingNetworks(reportedNetworks.takeIf { it.isNotEmpty() })
            if (underlyingNetworkFingerprint == null) {
                markUnderlyingNetworkApplied(fingerprint)
                return
            }
        }

        if (!physicalNetworkChanged) {
            if (!NativeCore.mobileTunnelWireGuardUnderlayReady(handle)) {
                Log.w(
                    "NostrVpnService",
                    "Initial WireGuard underlay handshake refresh failed",
                )
                scheduleNativeNetworkPathRetry(fingerprint)
                return
            }
            markUnderlyingNetworkApplied(fingerprint)
            return
        }

        if (!NativeCore.mobileTunnelNetworkChanged(handle)) {
            Log.w("NostrVpnService", "Physical network changed; live network-path refresh failed")
            if (wireGuardNetwork != null) scheduleNativeNetworkPathRetry(fingerprint)
            return
        }

        markUnderlyingNetworkApplied(fingerprint)
        val wg = if (wireGuardSocketFd >= 0) "; WireGuard refreshed fd=$wireGuardSocketFd" else ""
        Log.i(
            "NostrVpnService",
            "Physical network changed; live FIPS carriers refreshed$wg",
        )
    }

    private fun markUnderlyingNetworkApplied(fingerprint: String) {
        underlyingNetworkFingerprint = fingerprint
        clearUnderlyingNetworkRetry()
    }

    private fun scheduleNativeNetworkPathRetry(fingerprint: String) {
        if (retryUnderlyingNetworkFingerprint != fingerprint) {
            retryUnderlyingNetworkFingerprint = fingerprint
            underlyingNetworkRetryCount = 0
        }
        if (underlyingNetworkRetryCount >= UNDERLAY_NETWORK_MAX_RETRIES) return
        underlyingNetworkRetryCount += 1
        underlyingNetworkHandler.removeCallbacks(refreshNativeNetworkPathsRunnable)
        underlyingNetworkHandler.postDelayed(
            refreshNativeNetworkPathsRunnable, UNDERLAY_NETWORK_RETRY_MILLIS,
        )
    }

    private fun clearUnderlyingNetworkRetry() {
        retryUnderlyingNetworkFingerprint = null
        underlyingNetworkRetryCount = 0
        underlyingNetworkHandler.removeCallbacks(refreshNativeNetworkPathsRunnable)
    }

    private fun resetUnderlyingNetworkRefreshState() {
        pendingUnderlyingNetworkRefreshDelayMillis = null
        underlyingNetworkFingerprint = null
        clearUnderlyingNetworkRetry()
    }

    private fun bindWireGuardUpstreamToNetwork(
        socketFd: Int,
        network: Network,
    ): Boolean {
        return try {
            ParcelFileDescriptor.fromFd(socketFd).use { network.bindSocket(it.fileDescriptor) }
            Log.i(
                "NostrVpnService",
                "WireGuard upstream socket fd=$socketFd rebound to network ${network.networkHandle}",
            )
            true
        } catch (error: Exception) {
            Log.w(
                "NostrVpnService",
                "Failed to bind WireGuard upstream to network ${network.networkHandle}",
                error,
            )
            false
        }
    }

    private fun preferredWireGuardUnderlyingNetwork(
        candidates: Array<Network>,
    ): Network? {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return null
        val activeNetwork = connectivity.activeNetwork
        val preferredHandle = AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(
            candidates.map { network ->
                underlyingNetworkCandidate(connectivity, network, activeNetwork)
            },
        ) ?: return null
        return candidates.firstOrNull { it.networkHandle == preferredHandle }
    }

    private fun underlayTransportPreference(capabilities: NetworkCapabilities?): Int = when {
        capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 0
        capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 1
        capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 2
        else -> 3
    }

    private fun currentUnderlyingNetworkFingerprint(networks: Array<Network>): String {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return ""
        val candidateHandles = networks.map(Network::getNetworkHandle).toSet()
        val activeHandle = connectivity.activeNetwork
            ?.getNetworkHandle()
            ?.takeIf(candidateHandles::contains)
            ?: 0L
        return buildString {
            append("active=")
            append(activeHandle)
            for (network in networks.sortedBy(Network::getNetworkHandle)) {
                val capabilities = connectivity.getNetworkCapabilities(network)
                val properties = connectivity.getLinkProperties(network)
                append("|network=")
                append(network.networkHandle)
                append(";transports=")
                append(
                    listOf(
                        NetworkCapabilities.TRANSPORT_WIFI,
                        NetworkCapabilities.TRANSPORT_CELLULAR,
                        NetworkCapabilities.TRANSPORT_ETHERNET,
                    ).filter { capabilities?.hasTransport(it) == true }.joinToString(","),
                )
                append(";validated=")
                append(
                    capabilities
                        ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
                )
                append(";interface=")
                append(properties?.interfaceName.orEmpty())
                append(";addresses=")
                append(
                    properties?.linkAddresses
                        ?.map { it.toString() }
                        ?.sorted()
                        ?.joinToString(",")
                        .orEmpty(),
                )
                append(";routes=")
                append(
                    properties?.routes
                        ?.map { it.toString() }
                        ?.sorted()
                        ?.joinToString(",")
                        .orEmpty(),
                )
                append(";dns=")
                append(
                    properties?.dnsServers
                        ?.map { it.toString() }
                        ?.sorted()
                        ?.joinToString(",")
                        .orEmpty(),
                )
            }
        }
    }

    private fun underlyingNetworkCandidate(
        connectivity: ConnectivityManager,
        network: Network,
        activeNetwork: Network?,
    ): AndroidVpnRoutingPolicy.UnderlayNetworkCandidate {
        val capabilities = connectivity.getNetworkCapabilities(network)
        val properties = connectivity.getLinkProperties(network)
        return AndroidVpnRoutingPolicy.UnderlayNetworkCandidate(
            handle = network.networkHandle,
            active = network == activeNetwork,
            validated = capabilities
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
            usable = properties?.routes?.any { it.isDefaultRoute } == true &&
                capabilities
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) != true,
            transportPreference = underlayTransportPreference(capabilities),
        )
    }

    private fun stopTunnel() {
        cancelQueuedApprovalRestart()
        unregisterUnderlyingNetworkUpdates()
        running.set(false)
        releaseMulticastLock()
        val handle = tunnelHandle
        tunnelHandle = 0
        if (handle != 0L) {
            NativeCore.mobileTunnelFree(handle)
        }
    }

    private fun parseCidr(value: String): Cidr? {
        val parts = value.trim().split("/", limit = 2)
        val address = parts.firstOrNull()?.takeIf { it.isNotBlank() } ?: return null
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: 32
        if (prefix !in 0..32) {
            return null
        }
        return Cidr(address, prefix)
    }

    private fun startServiceForeground(): Boolean {
        AndroidVpnNotifications.createChannel(this)
        val notification = AndroidVpnNotifications.tunnel(this)
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    VPN_NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(VPN_NOTIFICATION_ID, notification)
            }
        }.onFailure { error ->
            Log.w("NostrVpnService", "Failed to start foreground VPN notification", error)
        }.isSuccess
    }

    private fun publishTunnelNotification() {
        AndroidVpnNotifications.publishTunnel(this)
    }

    private fun publishAlwaysOnSplitUnsupportedNotification() {
        AndroidVpnNotifications.publishAlwaysOnSplitUnsupported(this)
    }

    private fun stopServiceForeground() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        clearTunnelNotification()
    }

    private fun clearTunnelNotification() {
        AndroidVpnNotifications.clear(this)
    }

    private data class Cidr(val address: String, val prefix: Int)
    companion object {
        const val ACTION_CONNECT = "fi.siriusbusiness.nvpn.vpn.CONNECT"
        const val ACTION_DISCONNECT = "fi.siriusbusiness.nvpn.vpn.DISCONNECT"
        const val ACTION_RESTORE = "fi.siriusbusiness.nvpn.vpn.RESTORE"
        const val EXTRA_CONFIG_JSON = "configJson"
        private const val UNDERLAY_NETWORK_CHANGE_DEBOUNCE_MILLIS = 250L
        private const val UNDERLAY_NETWORK_RETRY_MILLIS = 250L
        private const val UNDERLAY_NETWORK_MAX_RETRIES = 2
        private const val QUEUED_APPROVAL_RESTART_POLL_MILLIS = 250L
        private const val QUEUED_APPROVAL_RESTART_MAX_DELAY_MILLIS = 12_000L
        private val tunnelOwnedInProcess = AtomicBoolean(false)

        internal fun isTunnelOwnedInProcess(): Boolean = tunnelOwnedInProcess.get()

        fun startRestore(context: Context) {
            val intent = Intent(context, NostrVpnService::class.java)
                .setAction(ACTION_RESTORE)
            context.startForegroundService(intent)
        }
    }
}

internal object AndroidVpnServiceStartContract {
    fun requiresImmediateForeground(action: String?): Boolean =
        action != NostrVpnService.ACTION_DISCONNECT &&
            action != VpnService.SERVICE_INTERFACE
}
