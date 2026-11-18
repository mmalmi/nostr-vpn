package org.nostrvpn.app

import android.content.Intent
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.nostrvpn.app.core.AppCoreClient
import org.nostrvpn.app.core.NativeActions
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

internal data class AndroidDebugRequest(
    val action: String? = null,
    val exitNode: String? = null,
    val networkName: String? = null,
    val wireGuardConfig: String? = null,
    val exitDnsPatch: String? = null,
    val networkProbe: String? = null,
) {
    companion object {
        private const val PACKAGE_PREFIX = "fi.siriusbusiness.nvpn"
        private const val EXTRA_ACTION = "$PACKAGE_PREFIX.DEBUG_ACTION"
        private const val EXTRA_EXIT_NODE = "$PACKAGE_PREFIX.DEBUG_EXIT_NODE"
        private const val EXTRA_NETWORK_NAME = "$PACKAGE_PREFIX.DEBUG_NETWORK_NAME"
        private const val EXTRA_WIREGUARD_CONFIG = "$PACKAGE_PREFIX.DEBUG_WIREGUARD_CONFIG"
        private const val EXTRA_WIREGUARD_CONFIG_BASE64 =
            "$PACKAGE_PREFIX.DEBUG_WIREGUARD_CONFIG_BASE64"
        private const val EXTRA_EXIT_DNS_PATCH_BASE64 =
            "$PACKAGE_PREFIX.DEBUG_EXIT_DNS_PATCH_BASE64"
        private const val EXTRA_NETWORK_PROBE_BASE64 =
            "$PACKAGE_PREFIX.DEBUG_NETWORK_PROBE_BASE64"
        fun from(intent: Intent?): AndroidDebugRequest =
            AndroidDebugRequest(
                action = intent?.getStringExtra(EXTRA_ACTION),
                exitNode = intent?.getStringExtra(EXTRA_EXIT_NODE),
                networkName = intent?.getStringExtra(EXTRA_NETWORK_NAME),
                wireGuardConfig = wireGuardConfig(intent),
                exitDnsPatch = decodedExtra(intent, EXTRA_EXIT_DNS_PATCH_BASE64),
                networkProbe = decodedExtra(intent, EXTRA_NETWORK_PROBE_BASE64),
            )

        private fun wireGuardConfig(intent: Intent?): String? {
            val inline = intent
                ?.getStringExtra(EXTRA_WIREGUARD_CONFIG)
                ?.takeIf { it.isNotBlank() }
            return inline ?: decodedExtra(intent, EXTRA_WIREGUARD_CONFIG_BASE64)
        }

        private fun decodedExtra(intent: Intent?, key: String): String? {
            val encoded = intent
                ?.getStringExtra(key)
                ?.takeIf { it.isNotBlank() }
                ?: return null
            return runCatching {
                String(Base64.decode(encoded, Base64.DEFAULT), Charsets.UTF_8)
            }.getOrNull()
        }
    }
}

internal object AndroidDebugAutomation {
    private const val ACTION_CONNECT = "connect"
    private const val ACTION_DISCONNECT = "disconnect"
    private const val ACTION_SET_FIPS_EXIT = "set_fips_exit"
    private const val ACTION_ADD_NETWORK = "add_network"
    private const val ACTION_CLEAR_EXIT = "clear_exit"
    private const val ACTION_SET_WIREGUARD_EXIT = "set_wireguard_exit"
    private const val ACTION_SET_EXIT_DNS = "set_exit_dns"
    private const val ACTION_NETWORK_PROBE = "network_probe"
    private const val EXIT_DNS_RESULT_FILE = "debug-exit-dns-state.json"
    private const val NETWORK_PROBE_RESULT_FILE = "debug-network-probe.json"

    suspend fun run(
        request: AndroidDebugRequest,
        core: AppCoreClient,
        dataDir: File,
        dispatch: (JSONObject) -> Unit,
    ) {
        if (!BuildConfig.DEBUG) {
            return
        }
        when (request.action) {
            ACTION_CONNECT -> dispatch(NativeActions.connectVpn())
            ACTION_DISCONNECT -> dispatch(NativeActions.disconnectVpn())
            ACTION_SET_FIPS_EXIT -> setFipsExit(request.exitNode, dispatch)
            ACTION_ADD_NETWORK -> dispatch(
                NativeActions.addNetwork(
                    request.networkName.orEmpty().trim().ifBlank { "Android smoke" },
                ),
            )
            ACTION_CLEAR_EXIT -> dispatch(
                NativeActions.updateSettings(
                    "internetSource" to "direct",
                    "exitNode" to "",
                    "wireguardExitEnabled" to false,
                    "exitNodeLeakProtection" to false,
                ),
            )
            ACTION_SET_WIREGUARD_EXIT -> setWireGuardExit(
                request.wireGuardConfig,
                dispatch,
            )
            ACTION_SET_EXIT_DNS -> setExitDns(request.exitDnsPatch, core, dataDir, dispatch)
            ACTION_NETWORK_PROBE -> runNetworkProbe(request.networkProbe, dataDir)
        }
    }

    private fun setFipsExit(
        rawExitNode: String?,
        dispatch: (JSONObject) -> Unit,
    ) {
        val exitNode = rawExitNode.orEmpty().trim()
        if (exitNode.isEmpty()) {
            return
        }
        dispatch(
            NativeActions.updateSettings(
                "exitNode" to exitNode,
                "wireguardExitEnabled" to false,
                "exitNodeLeakProtection" to true,
            ),
        )
    }

    private fun setWireGuardExit(
        rawConfig: String?,
        dispatch: (JSONObject) -> Unit,
    ) {
        val config = rawConfig.orEmpty().trim()
        if (config.isEmpty()) {
            return
        }
        dispatch(
            NativeActions.updateSettings(
                "internetSource" to "wireguard",
                "wireguardExitConfig" to config,
                "wireguardExitEnabled" to true,
                "exitNode" to "",
            ),
        )
    }

    private suspend fun setExitDns(
        rawPatch: String?,
        core: AppCoreClient,
        dataDir: File,
        dispatch: (JSONObject) -> Unit,
    ) {
        val requested = runCatching {
            JSONObject(rawPatch.orEmpty())
        }.getOrNull() ?: return
        val settings = mutableListOf<Pair<String, Any?>>(
            "exitDnsMode" to requested.optString("exitDnsMode"),
            "exitDnsDohProvider" to requested.optString("exitDnsDohProvider"),
            "exitDnsCustomDohUrl" to requested.optString("exitDnsCustomDohUrl"),
            "exitDnsCustomDohBootstrapIps" to
                requested.optString("exitDnsCustomDohBootstrapIps"),
            "exitDnsThroughExitServers" to
                requested.optString("exitDnsThroughExitServers"),
        )
        for (key in listOf("internetSource", "exitNode")) {
            if (requested.has(key)) {
                settings += key to requested.optString(key)
            }
        }
        for (key in listOf("wireguardExitEnabled", "exitNodeLeakProtection")) {
            if (requested.has(key)) {
                settings += key to requested.optBoolean(key)
            }
        }
        dispatch(NativeActions.updateSettings(*settings.toTypedArray()))
        delay(500)
        // Core refresh can block on network round trips; keep it off main.
        val current = withContext(Dispatchers.IO) { core.refresh() }
        val result = JSONObject()
            .put("probeId", requested.optString("probeId"))
            .put("error", current.error)
            .put("vpnEnabled", current.vpnEnabled)
            .put("internetSource", current.internetSource)
            .put("wireguardExitEnabled", current.wireguardExitEnabled)
            .put("exitDnsMode", current.exitDnsMode)
            .put("exitDnsDohProvider", current.exitDnsDohProvider)
            .put("exitDnsCustomDohUrl", current.exitDnsCustomDohUrl)
            .put(
                "exitDnsCustomDohBootstrapIps",
                current.exitDnsCustomDohBootstrapIps,
            )
            .put(
                "exitDnsThroughExitServers",
                current.exitDnsThroughExitServers,
            )
        writeResult(dataDir, EXIT_DNS_RESULT_FILE, result)
    }

    private suspend fun runNetworkProbe(rawRequest: String?, dataDir: File) {
        val requested = runCatching {
            JSONObject(rawRequest.orEmpty())
        }.getOrNull() ?: return
        val result = withContext(Dispatchers.IO) {
            networkProbe(requested)
        }
        writeResult(dataDir, NETWORK_PROBE_RESULT_FILE, result)
    }

    private fun networkProbe(requested: JSONObject): JSONObject {
        val probeId = requested.optString("probeId")
        val host = requested.optString("host").trim()
        val url = requested.optString("url").trim()
        val result = JSONObject()
            .put("probeId", probeId)
            .put("host", host)
            .put("url", url)
        if (host.isEmpty() || url.isEmpty()) {
            return result.put("error", "network probe requires a host and URL")
        }

        val resolved = runCatching {
            InetAddress.getAllByName(host)
                .mapNotNull { it.hostAddress }
                .distinct()
        }.onFailure { error ->
            result.put(
                "resolveError",
                error.message.orEmpty().ifBlank { error.javaClass.simpleName },
            )
        }.getOrDefault(emptyList())
        result.put("resolvedAddresses", JSONArray(resolved))

        runCatching {
            val connection = URL(url).openConnection() as HttpURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.requestMethod = "GET"
                result.put("statusCode", connection.responseCode)
            } finally {
                connection.disconnect()
            }
        }.onFailure { error ->
            result.put(
                "fetchError",
                error.message.orEmpty().ifBlank { error.javaClass.simpleName },
            )
        }
        return result
    }

    private fun writeResult(
        dataDir: File,
        fileName: String,
        value: JSONObject,
    ) {
        val destination = dataDir.resolve(fileName)
        val temporary = dataDir.resolve("$fileName.tmp")
        temporary.writeText(value.toString(2) + "\n", Charsets.UTF_8)
        check(temporary.renameTo(destination)) {
            "failed to publish debug result $fileName"
        }
    }
}
