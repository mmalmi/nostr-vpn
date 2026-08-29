package org.nostrvpn.app

import org.json.JSONArray
import org.json.JSONObject
import org.nostrvpn.app.core.AppState

internal enum class AndroidRefreshTrigger {
    PERIODIC,
    CONFIG_CHANGED,
}

internal object AndroidRefreshPolicy {
    fun shouldRefreshTunnelConfig(trigger: AndroidRefreshTrigger): Boolean =
        trigger == AndroidRefreshTrigger.CONFIG_CHANGED

    fun shouldReplaceState(current: AppState, refreshed: AppState): Boolean =
        current.copy(rev = refreshed.rev) != refreshed
}

internal object TunnelRefreshPolicy {
    private val tunnelStartingActions = setOf(
        "add_network",
        "import_join_request",
    )

    private val networkActions = setOf(
        "import_join_request",
        "manual_add_network",
        "add_network",
        "rename_network",
        "remove_network",
        "set_network_enabled",
        "set_network_mesh_id",
        "set_network_join_requests_enabled",
        "add_participant",
        "add_admin",
        "remove_participant",
        "remove_admin",
        "accept_join_request",
        "set_manual_paid_exit_provider",
        "clear_manual_paid_exit_provider",
        "set_participant_alias",
        "set_participant_endpoint_hints",
    )

    private val tunnelSettingKeys = setOf(
        "internetSource",
        "listenPort",
        "endpoint",
        "relays",
        "disabledRelays",
        "exitNode",
        "exitNodeLeakProtection",
        "exitDnsMode",
        "exitDnsDohProvider",
        "exitDnsCustomDohUrl",
        "exitDnsCustomDohBootstrapIps",
        "exitDnsThroughExitServers",
        "advertiseExitNode",
        "advertisedRoutes",
        "wireguardExitEnabled",
        "wireguardExitInterface",
        "wireguardExitAddress",
        "wireguardExitPrivateKey",
        "wireguardExitPeerPublicKey",
        "wireguardExitPeerPresharedKey",
        "wireguardExitEndpoint",
        "wireguardExitAllowedIps",
        "wireguardExitDns",
        "wireguardExitMtu",
        "wireguardExitPersistentKeepaliveSecs",
        "wireguardExitConfig",
    )

    fun requiresTunnelRefresh(type: String, updateSettingKeys: Set<String> = emptySet()): Boolean =
        type in networkActions ||
            (type == "update_settings" && updateSettingKeys.any(tunnelSettingKeys::contains))

    fun shouldStartTunnelAfterAction(type: String, vpnEnabled: Boolean): Boolean =
        !vpnEnabled && type in tunnelStartingActions
}

internal object TunnelConfigRefreshPolicy {
    private val restartFields = listOf(
        "identityNsec",
        "nodeName",
        "networkId",
        "joinSecret",
        "localAddress",
        "listenPort",
        "mtu",
        "peers",
        "bootstrapPeers",
        "routeTargets",
        "nostrRelays",
        "websocketSeedUrls",
        "stunServers",
        "shareLocalCandidates",
        "connectToNonRosterFipsPeers",
        "nostrDiscoveryEnabled",
        "webrtcEnabled",
        "excludedRoutes",
        "dnsServers",
        "magicDnsServer",
        "dnsMatchDomains",
        "exitDns",
        "wireguardExit",
        "joinRequestsEnabled",
        "deviceApprovalPending",
        "pendingJoinRequestRecipient",
        "pendingJoinSecret",
    )

    fun requiresAsyncRefresh(
        vpnEnabled: Boolean,
        observedConfigJson: String,
        currentConfigJson: String,
    ): Boolean =
        vpnEnabled &&
            currentConfigJson.isNotBlank() &&
            stableFingerprint(currentConfigJson) != stableFingerprint(observedConfigJson)

    fun shouldDeferRestartForQueuedApproval(
        tunnelRunning: Boolean,
        configJson: String,
    ): Boolean =
        tunnelRunning &&
            runCatching {
                JSONObject(configJson).optJSONArray("queuedJoinRosters")?.length() ?: 0
            }.getOrDefault(0) > 0

    internal fun stableFingerprint(configJson: String): String =
        runCatching {
            val config = JSONObject(configJson)
            val selected = JSONObject()
            for (field in restartFields) {
                if (config.has(field)) {
                    selected.put(field, config.get(field))
                }
            }
            canonicalJson(selected)
        }.getOrDefault(configJson)

    private fun canonicalJson(value: Any?): String =
        when (value) {
            null, JSONObject.NULL -> "null"
            is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(
                prefix = "{",
                postfix = "}",
            ) { key ->
                "${JSONObject.quote(key)}:${canonicalJson(value.get(key))}"
            }
            is JSONArray -> (0 until value.length()).joinToString(
                prefix = "[",
                postfix = "]",
            ) { index -> canonicalJson(value.get(index)) }
            is String -> JSONObject.quote(value)
            is Number, is Boolean -> value.toString()
            else -> JSONObject.quote(value.toString())
        }
}

internal enum class TunnelServiceCommand {
    NONE,
    CONNECT,
    DISCONNECT,
}

internal object TunnelServiceCommandPolicy {
    fun commandAfterActivityStart(
        vpnEnabled: Boolean,
        tunnelOwnedInProcess: Boolean,
    ): TunnelServiceCommand =
        if (vpnEnabled && !tunnelOwnedInProcess) {
            TunnelServiceCommand.DISCONNECT
        } else {
            TunnelServiceCommand.NONE
        }

    fun commandAfterAction(
        actionType: String,
        wasEnabled: Boolean,
        isEnabled: Boolean,
        requiresRefresh: Boolean,
    ): TunnelServiceCommand =
        when {
            actionType == "disconnect_vpn" -> TunnelServiceCommand.DISCONNECT
            actionType == "connect_vpn" && isEnabled -> TunnelServiceCommand.CONNECT
            !wasEnabled && isEnabled -> TunnelServiceCommand.CONNECT
            wasEnabled && !isEnabled -> TunnelServiceCommand.DISCONNECT
            wasEnabled && isEnabled && requiresRefresh -> TunnelServiceCommand.CONNECT
            else -> TunnelServiceCommand.NONE
        }
}
