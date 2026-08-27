namespace NostrVpn.Windows.Core;

public static class NativeActions
{
    public static string Tick() => AppCoreClient.Action(new { type = "tick" });
    public static string ConnectVpn() => AppCoreClient.Action(new { type = "connect_vpn" });
    public static string DisconnectVpn() => AppCoreClient.Action(new { type = "disconnect_vpn" });
    public static string InstallCli() => AppCoreClient.Action(new { type = "install_cli" });
    public static string InstallSystemService() => AppCoreClient.Action(new { type = "install_system_service" });
    public static string EnableSystemService() => AppCoreClient.Action(new { type = "enable_system_service" });
    public static string DisableSystemService() => AppCoreClient.Action(new { type = "disable_system_service" });
    public static string UninstallSystemService() => AppCoreClient.Action(new { type = "uninstall_system_service" });
    public static string AddNetwork(string name) => AppCoreClient.Action(new { type = "add_network", name });
    public static string RenameNetwork(string networkId, string name) => AppCoreClient.Action(new { type = "rename_network", networkId, name });
    public static string RemoveNetwork(string networkId) => AppCoreClient.Action(new { type = "remove_network", networkId });
    public static string SetNetworkMeshId(string networkId, string meshId) => AppCoreClient.Action(new { type = "set_network_mesh_id", networkId, meshId });
    public static string SetNetworkEnabled(string networkId, bool enabled) => AppCoreClient.Action(new { type = "set_network_enabled", networkId, enabled });
    public static string ImportJoinRequest(string request) => AppCoreClient.Action(new { type = "import_join_request", request });
    public static string ManualAddNetwork(string adminNpub, string meshNetworkId) => AppCoreClient.Action(new { type = "manual_add_network", adminNpub, meshNetworkId });
    public static string AcceptJoinRequest(string networkId, string requesterNpub) => AppCoreClient.Action(new { type = "accept_join_request", networkId, requesterNpub });
    public static string AddParticipant(string networkId, string npub, string? alias) => AppCoreClient.Action(new { type = "add_participant", networkId, npub, alias });
    public static string RemoveParticipant(string networkId, string npub) => AppCoreClient.Action(new { type = "remove_participant", networkId, npub });
    public static string AddAdmin(string networkId, string npub) => AppCoreClient.Action(new { type = "add_admin", networkId, npub });
    public static string RemoveAdmin(string networkId, string npub) => AppCoreClient.Action(new { type = "remove_admin", networkId, npub });
    public static string SetParticipantAlias(string npub, string alias) => AppCoreClient.Action(new { type = "set_participant_alias", npub, alias });
    public static string SetParticipantEndpointHints(string npub, List<string> endpointHints) => AppCoreClient.Action(new { type = "set_participant_endpoint_hints", npub, endpointHints });
    public static string AddPaidRouteWalletMint(string url, string? label = null) => AppCoreClient.Action(new { type = "add_paid_route_wallet_mint", url, label });
    public static string RemovePaidRouteWalletMint(string url) => AppCoreClient.Action(new { type = "remove_paid_route_wallet_mint", url });
    public static string SetPaidRouteDefaultMint(string url) => AppCoreClient.Action(new { type = "set_paid_route_default_mint", url });
    public static string RefreshPaidRouteWallet(bool refresh = true) => AppCoreClient.Action(new { type = "refresh_paid_route_wallet", refresh });
    public static string TopUpPaidRouteWallet(string? mintUrl, ulong amountSat) => AppCoreClient.Action(new { type = "top_up_paid_route_wallet", mintUrl, amountSat });
    public static string ReceivePaidRouteWalletToken(string token) => AppCoreClient.Action(new { type = "receive_paid_route_wallet_token", token });
    public static string PreviewPaidRouteWalletToken(string token) => AppCoreClient.Action(new { type = "preview_paid_route_wallet_token", token });
    public static string SendPaidRouteWalletToken(string? mintUrl, ulong amountSat) => AppCoreClient.Action(new { type = "send_paid_route_wallet_token", mintUrl, amountSat });
    public static string WithdrawPaidRouteWalletLightning(string? mintUrl, string invoice) => AppCoreClient.Action(new { type = "withdraw_paid_route_wallet_lightning", mintUrl, invoice });
    public static string BuyPaidRouteOffer(string offerKey, string? mintUrl = null, ulong? channelCapacitySat = null) => AppCoreClient.Action(new { type = "buy_paid_route_offer", offerKey, mintUrl, channelCapacitySat });
    public static string SetManualPaidExitProvider(string provider) => AppCoreClient.Action(new { type = "set_manual_paid_exit_provider", provider });
    public static string ClearManualPaidExitProvider() => AppCoreClient.Action(new { type = "clear_manual_paid_exit_provider" });
    public static string SelectPaidRouteSession(string sessionId, bool connect) => AppCoreClient.Action(new { type = "select_paid_route_session", sessionId, connect });
    public static string ProbePaidRouteSession(string sessionId, ulong timeoutSecs = 5) => AppCoreClient.Action(new { type = "probe_paid_route_session", sessionId, timeoutSecs });
    public static string OpenPaidRouteChannelFromWallet(string sessionId, string? mintUrl = null, ulong? paidMsat = null, ulong? maxAmountPerOutput = null, string? keysetId = null) => AppCoreClient.Action(new { type = "open_paid_route_channel_from_wallet", sessionId, mintUrl, paidMsat, maxAmountPerOutput, keysetId });
    public static string SignPaidRoutePaymentEnvelopeFromWallet(string sessionId, string kind = "balance-update", ulong? deliveredUnits = null, ulong? paidMsat = null) => AppCoreClient.Action(new { type = "sign_paid_route_payment_envelope_from_wallet", sessionId, kind, deliveredUnits, paidMsat });
    public static string ClosePaidRouteChannelFromWallet(string sessionId, bool publish = true) => AppCoreClient.Action(new { type = "close_paid_route_channel_from_wallet", sessionId, publish });
    public static string SendPaidRoutePaymentEnvelope(string envelopeJson) => AppCoreClient.Action(new { type = "send_paid_route_payment_envelope", envelopeJson });
    public static string StreamPaidRoutePayments(bool publish = true, ulong minIncrementMsat = 1, ulong limit = 0) => AppCoreClient.Action(new { type = "stream_paid_route_payments", publish, minIncrementMsat, limit });
    public static string ReceivePaidRoutePayments(ulong durationSecs = 5) => AppCoreClient.Action(new { type = "receive_paid_route_payments", durationSecs });
    public static string CollectDuePaidExitChannels() => AppCoreClient.Action(new { type = "collect_due_paid_exit_channels" });
    public static string SetPaidRouteMarketFilter(string countryCode, bool requireIpv4, bool requireIpv6, string sort) => AppCoreClient.Action(new
    {
        type = "set_paid_route_market_filter",
        query = "",
        countryCode,
        mintUrl = "",
        requireIpv4,
        requireIpv6,
        sort,
    });
    public static string DiscoverPaidRouteOffers(ulong durationSecs = 5) => AppCoreClient.Action(new { type = "discover_paid_route_offers", durationSecs });
    public static string UpdateSettings(SettingsPatch patch) => AppCoreClient.Action(new { type = "update_settings", patch });
}

public sealed class SettingsPatch
{
    public string? NodeName { get; set; }
    public string? Endpoint { get; set; }
    public string? TunnelIp { get; set; }
    public ushort? ListenPort { get; set; }
    public List<string>? Relays { get; set; }
    public List<string>? DisabledRelays { get; set; }
    public string? InternetSource { get; set; }
    public string? ExitNode { get; set; }
    public bool? ExitNodeLeakProtection { get; set; }
    public string? ExitDnsMode { get; set; }
    public string? ExitDnsDohProvider { get; set; }
    public string? ExitDnsCustomDohUrl { get; set; }
    public string? ExitDnsCustomDohBootstrapIps { get; set; }
    public string? ExitDnsThroughExitServers { get; set; }
    public bool? AdvertiseExitNode { get; set; }
    public string? AdvertisedRoutes { get; set; }
    public bool? WireguardExitEnabled { get; set; }
    public string? WireguardExitInterface { get; set; }
    public string? WireguardExitAddress { get; set; }
    public string? WireguardExitPrivateKey { get; set; }
    public string? WireguardExitPeerPublicKey { get; set; }
    public string? WireguardExitPeerPresharedKey { get; set; }
    public string? WireguardExitEndpoint { get; set; }
    public string? WireguardExitAllowedIps { get; set; }
    public string? WireguardExitDns { get; set; }
    public ushort? WireguardExitMtu { get; set; }
    public ushort? WireguardExitPersistentKeepaliveSecs { get; set; }
    public string? WireguardExitConfig { get; set; }
    public bool? WalletFiatEnabled { get; set; }
    public string? WalletFiatCurrency { get; set; }
    public bool? PaidExitEnabled { get; set; }
    public string? PaidExitUpstream { get; set; }
    public ulong? PaidExitPriceMsatPerGb { get; set; }
    public string? PaidExitAcceptedMints { get; set; }
    public ulong? PaidExitMaxChannelCapacitySat { get; set; }
    public ulong? PaidExitChannelExpirySecs { get; set; }
    public ulong? PaidExitFreeProbeUnits { get; set; }
    public ulong? PaidExitGraceUnits { get; set; }
    public string? PaidExitCountryCode { get; set; }
    public string? PaidExitAsn { get; set; }
    public bool? PaidExitIpv4 { get; set; }
    public bool? PaidExitIpv6 { get; set; }
    public bool? FipsHostTunnelEnabled { get; set; }
    public bool? ConnectToNonRosterFipsPeers { get; set; }
    public bool? FipsNostrDiscoveryEnabled { get; set; }
    public bool? FipsBootstrapEnabled { get; set; }
    public string? FipsHostInboundTcpPorts { get; set; }
    public bool? Autoconnect { get; set; }
    public bool? LaunchOnStartup { get; set; }
    public bool? CloseToTrayOnClose { get; set; }
}
