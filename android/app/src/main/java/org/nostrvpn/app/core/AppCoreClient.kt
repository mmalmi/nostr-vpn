package org.nostrvpn.app.core

import org.json.JSONObject
import org.json.JSONArray

class AppCoreClient(private val dataDir: String, appVersion: String) : AutoCloseable {
    private var handle: Long = NativeCore.appNew(dataDir, appVersion)

    fun state(): AppState = parseAppState(NativeCore.stateJson(requireHandle()))

    fun refresh(): AppState = parseAppState(NativeCore.refreshJson(requireHandle()))

    fun dispatch(action: JSONObject): AppState =
        parseAppState(NativeCore.dispatchJson(requireHandle(), action.toString()))

    fun qrMatrix(text: String): JSONObject = JSONObject(NativeCore.qrMatrixJson(text))

    fun decodeQrImage(path: String): JSONObject = JSONObject(NativeCore.decodeQrImageJson(path))

    fun mobileTunnelConfigJson(): String = NativeCore.mobileTunnelConfigJson(dataDir)

    override fun close() {
        val current = handle
        if (current != 0L) {
            NativeCore.appFree(current)
            handle = 0
        }
    }

    private fun requireHandle(): Long {
        check(handle != 0L) { "native app core is closed" }
        return handle
    }
}

object NativeActions {
    fun connectVpn() = action("connect_vpn")
    fun disconnectVpn() = action("disconnect_vpn")
    fun importJoinRequest(request: String) = action("import_join_request", "request" to request)
    fun manualAddNetwork(adminNpub: String, meshNetworkId: String) =
        action("manual_add_network", "adminNpub" to adminNpub, "meshNetworkId" to meshNetworkId)

    fun addNetwork(name: String) = action("add_network", "name" to name)
    fun setNetworkEnabled(networkId: String, enabled: Boolean) =
        action("set_network_enabled", "networkId" to networkId, "enabled" to enabled)

    fun addParticipant(networkId: String, npub: String, alias: String? = null) =
        action("add_participant", "networkId" to networkId, "npub" to npub, "alias" to alias)

    fun removeNetwork(networkId: String) = action("remove_network", "networkId" to networkId)

    fun removeParticipant(networkId: String, npub: String) =
        action("remove_participant", "networkId" to networkId, "npub" to npub)

    fun setParticipantEndpointHints(npub: String, endpointHints: List<String>) =
        action("set_participant_endpoint_hints", "npub" to npub, "endpointHints" to endpointHints)

    fun addPaidRouteWalletMint(url: String, label: String?) =
        action("add_paid_route_wallet_mint", "url" to url, "label" to label)

    fun removePaidRouteWalletMint(url: String) =
        action("remove_paid_route_wallet_mint", "url" to url)

    fun setPaidRouteDefaultMint(url: String) =
        action("set_paid_route_default_mint", "url" to url)

    fun refreshPaidRouteWallet(refresh: Boolean = true) =
        action("refresh_paid_route_wallet", "refresh" to refresh)

    fun topUpPaidRouteWallet(mintUrl: String?, amountSat: Long) =
        action("top_up_paid_route_wallet", "mintUrl" to mintUrl, "amountSat" to amountSat)

    fun receivePaidRouteWalletToken(token: String) =
        action("receive_paid_route_wallet_token", "token" to token)

    fun previewPaidRouteWalletToken(token: String) =
        action("preview_paid_route_wallet_token", "token" to token)

    fun sendPaidRouteWalletToken(mintUrl: String?, amountSat: Long) =
        action("send_paid_route_wallet_token", "mintUrl" to mintUrl, "amountSat" to amountSat)

    fun withdrawPaidRouteWalletLightning(mintUrl: String?, invoice: String) =
        action("withdraw_paid_route_wallet_lightning", "mintUrl" to mintUrl, "invoice" to invoice)

    fun buyPaidRouteOffer(offerKey: String, mintUrl: String? = null, channelCapacitySat: Long? = null) =
        action(
            "buy_paid_route_offer",
            "offerKey" to offerKey,
            "mintUrl" to mintUrl,
            "channelCapacitySat" to channelCapacitySat,
        )

    fun setManualPaidExitProvider(provider: String) =
        action("set_manual_paid_exit_provider", "provider" to provider)

    fun clearManualPaidExitProvider() = action("clear_manual_paid_exit_provider")

    fun selectPaidRouteSession(sessionId: String, connect: Boolean) =
        action("select_paid_route_session", "sessionId" to sessionId, "connect" to connect)

    fun reselectPaidExit() = action("reselect_paid_exit")

    fun ratePaidExit(sellerNpub: String, rating: Long) =
        action("rate_paid_exit").put("sellerNpub", sellerNpub).put("rating", rating)

    fun probePaidRouteSession(sessionId: String, timeoutSecs: Long) =
        action("probe_paid_route_session", "sessionId" to sessionId, "timeoutSecs" to timeoutSecs)

    fun openPaidRouteChannelFromWallet(
        sessionId: String,
        mintUrl: String? = null,
        paidMsat: Long? = null,
        maxAmountPerOutput: Long? = null,
        keysetId: String? = null,
    ) = action(
        "open_paid_route_channel_from_wallet",
        "sessionId" to sessionId,
        "mintUrl" to mintUrl,
        "paidMsat" to paidMsat,
        "maxAmountPerOutput" to maxAmountPerOutput,
        "keysetId" to keysetId,
    )

    fun signPaidRoutePaymentEnvelopeFromWallet(
        sessionId: String,
        kind: String = "balance-update",
        deliveredUnits: Long? = null,
        paidMsat: Long? = null,
    ) = action(
        "sign_paid_route_payment_envelope_from_wallet",
        "sessionId" to sessionId,
        "kind" to kind,
        "deliveredUnits" to deliveredUnits,
        "paidMsat" to paidMsat,
    )

    fun closePaidRouteChannelFromWallet(sessionId: String, publish: Boolean = true) =
        action("close_paid_route_channel_from_wallet", "sessionId" to sessionId, "publish" to publish)

    fun sendPaidRoutePaymentEnvelope(envelopeJson: String) =
        action("send_paid_route_payment_envelope", "envelopeJson" to envelopeJson)

    fun streamPaidRoutePayments(publish: Boolean = true, minIncrementMsat: Long = 1, limit: Long = 0) =
        action(
            "stream_paid_route_payments",
            "publish" to publish,
            "minIncrementMsat" to minIncrementMsat,
            "limit" to limit,
        )

    fun receivePaidRoutePayments(durationSecs: Long = 5) =
        action("receive_paid_route_payments", "durationSecs" to durationSecs)

    fun collectDuePaidExitChannels() = action("collect_due_paid_exit_channels")

    fun setPaidRouteMarketFilter(
        query: String = "",
        countryCode: String = "",
        mintUrl: String = "",
        requireIpv4: Boolean = false,
        requireIpv6: Boolean = false,
        sort: String = "quality",
    ) = action(
        "set_paid_route_market_filter",
        "query" to query,
        "countryCode" to countryCode,
        "mintUrl" to mintUrl,
        "requireIpv4" to requireIpv4,
        "requireIpv6" to requireIpv6,
        "sort" to sort,
    )

    fun discoverPaidRouteOffers(durationSecs: Long = 5) =
        action("discover_paid_route_offers", "durationSecs" to durationSecs)

    fun updateSettings(vararg settings: Pair<String, Any?>): JSONObject =
        JSONObject()
            .put("type", "update_settings")
            .put(
                "patch",
                JSONObject().apply {
                    settings.forEach { (key, value) ->
                        put(key, if (value is List<*>) JSONArray(value) else value)
                    }
                },
            )

    private fun action(type: String, vararg fields: Pair<String, Any?>): JSONObject =
        JSONObject().put("type", type).apply {
            fields.forEach { (key, value) -> put(key, if (value is List<*>) JSONArray(value) else value) }
        }
}
