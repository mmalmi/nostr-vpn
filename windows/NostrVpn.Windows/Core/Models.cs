namespace NostrVpn.Windows.Core;

public sealed class NativeUpdateResult
{
    public bool Available { get; set; }
    public string CurrentVersion { get; set; } = "";
    public string LatestVersion { get; set; } = "";
    public string Tag { get; set; } = "";
    public string Asset { get; set; } = "";
    public string Source { get; set; } = "";
    public bool Verified { get; set; }
    public string? Url { get; set; }
    public string? Path { get; set; }
    public string Error { get; set; } = "";
}

public sealed class NativeAppState
{
    public ulong Rev { get; set; }
    public string Platform { get; set; } = "";
    public bool Mobile { get; set; }
    public bool VpnControlSupported { get; set; }
    public bool CliInstallSupported { get; set; }
    public bool StartupSettingsSupported { get; set; }
    public bool TrayBehaviorSupported { get; set; }
    public string RuntimeStatusDetail { get; set; } = "";
    public string AppVersion { get; set; } = "";
    public string ConfigPath { get; set; } = "";
    public string Error { get; set; } = "";
    public bool CliInstalled { get; set; }
    public bool ServiceSupported { get; set; }
    public bool ServiceEnablementSupported { get; set; }
    public bool ServiceInstalled { get; set; }
    public bool ServiceDisabled { get; set; }
    public bool ServiceRunning { get; set; }
    public string ServiceStatusDetail { get; set; } = "";
    public bool DaemonRunning { get; set; }
    public bool VpnEnabled { get; set; }
    public bool VpnActive { get; set; }
    public string VpnStatus { get; set; } = "";
    public string DaemonBinaryVersion { get; set; } = "";
    public string ServiceBinaryVersion { get; set; } = "";
    public string OwnNpub { get; set; } = "";
    public string OwnPubkeyHex { get; set; } = "";
    public string NodeId { get; set; } = "";
    public string NodeName { get; set; } = "";
    public string SelfMagicDnsName { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public string TunnelIp { get; set; } = "";
    public uint ListenPort { get; set; }
    public List<NativeRelayState> Relays { get; set; } = [];
    public string NetworkId { get; set; } = "";
    public string JoinRequestQrCodeOrLink { get; set; } = "";
    public string InternetSource { get; set; } = "direct";
    public string ExitNode { get; set; } = "";
    public bool ExitNodeLeakProtection { get; set; } = true;
    public bool ExitNodeActive { get; set; }
    public bool ExitNodeBlocked { get; set; }
    public string ExitNodeStatusText { get; set; } = "";
    public string ExitDnsMode { get; set; } = "automatic";
    public string ExitDnsDohProvider { get; set; } = "cloudflare";
    public string ExitDnsCustomDohUrl { get; set; } = "";
    public string ExitDnsCustomDohBootstrapIps { get; set; } = "";
    public string ExitDnsThroughExitServers { get; set; } = "";
    public bool AdvertiseExitNode { get; set; }
    public List<string> AdvertisedRoutes { get; set; } = [];
    public List<string> EffectiveAdvertisedRoutes { get; set; } = [];
    public bool WireguardExitEnabled { get; set; }
    public bool WireguardExitConfigured { get; set; }
    public string WireguardExitInterface { get; set; } = "";
    public string WireguardExitAddress { get; set; } = "";
    public string WireguardExitPrivateKey { get; set; } = "";
    public string WireguardExitPeerPublicKey { get; set; } = "";
    public string WireguardExitPeerPresharedKey { get; set; } = "";
    public string WireguardExitEndpoint { get; set; } = "";
    public string WireguardExitAllowedIps { get; set; } = "";
    public string WireguardExitDns { get; set; } = "";
    public ushort WireguardExitMtu { get; set; }
    public ushort WireguardExitPersistentKeepaliveSecs { get; set; }
    public string WireguardExitConfig { get; set; } = "";
    public bool WalletFiatEnabled { get; set; } = true;
    public string WalletFiatCurrency { get; set; } = "USD";
    public NativePaidExitSellerState PaidExitSeller { get; set; } = new();
    public NativePaidRouteMarketState PaidRouteMarket { get; set; } = new();
    public bool FipsHostTunnelEnabled { get; set; }
    public bool ConnectToNonRosterFipsPeers { get; set; }
    public bool FipsNostrDiscoveryEnabled { get; set; }
    public bool FipsBootstrapEnabled { get; set; }
    public string FipsHostInboundTcpPorts { get; set; } = "";
    public string MagicDnsSuffix { get; set; } = "";
    public string MagicDnsStatus { get; set; } = "";
    public bool Autoconnect { get; set; }
    public bool LaunchOnStartup { get; set; }
    public bool CloseToTrayOnClose { get; set; }
    public ulong ConnectedPeerCount { get; set; }
    public ulong ExpectedPeerCount { get; set; }
    public ulong FipsConnectedPeerCount { get; set; }
    public ulong FipsRosterPeerCount { get; set; }
    public ulong NonFipsRosterPeerCount { get; set; }
    public bool MeshReady { get; set; }
    public List<NativeHealthIssue> Health { get; set; } = [];
    public NativeNetworkSummary Network { get; set; } = new();
    public NativePortMappingStatus PortMapping { get; set; } = new();
    public List<NativeNetworkState> Networks { get; set; } = [];
}

public sealed class NativeRelayState
{
    public string Url { get; set; } = "";
    public string Status { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool Connected => Enabled && string.Equals(Status, "connected", StringComparison.OrdinalIgnoreCase);
}

public sealed class NativePaidExitSellerState
{
    public bool Supported { get; set; }
    public bool Enabled { get; set; }
    public string StatusText { get; set; } = "";
    public string ProviderLink { get; set; } = "";
    public string Upstream { get; set; } = "";
    public string PrivateVpnAccess { get; set; } = "";
    public string InternetText { get; set; } = "";
    public string PublicIpText { get; set; } = "";
    public string PriceText { get; set; } = "";
    public ulong PriceMsatPerGb { get; set; }
    public List<string> AcceptedMints { get; set; } = [];
    public ulong MaxChannelCapacitySat { get; set; }
    public ulong ChannelExpirySecs { get; set; }
    public string ChannelExpiryText { get; set; } = "";
    public string SettlementText { get; set; } = "";
    public ulong FreeProbeUnits { get; set; }
    public string FreeProbeText { get; set; } = "";
    public ulong GraceUnits { get; set; }
    public string GraceText { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public uint Asn { get; set; }
    public bool Ipv4 { get; set; }
    public bool Ipv6 { get; set; }
    public ulong ChannelCreditMsat { get; set; }
    public string ChannelCreditText { get; set; } = "";
    public string ChannelCreditTitleText { get; set; } = "";
    public string ChannelCreditHelpText { get; set; } = "";
    public ulong CurrentConnectionCount { get; set; }
    public ulong PastConnectionCount { get; set; }
    public ulong TotalBillableBytes { get; set; }
    public string TotalTrafficText { get; set; } = "";
    public ulong TotalPaidMsat { get; set; }
    public string TotalPaidText { get; set; } = "";
    public ulong TotalDueMsat { get; set; }
    public string TotalDueText { get; set; } = "";
    public ulong TotalUnpaidMsat { get; set; }
    public string TotalUnpaidText { get; set; } = "";
    public List<NativePaidRouteChannelState> Channels { get; set; } = [];
    public List<NativePaidRouteSessionState> Sessions { get; set; } = [];
}

public sealed class NativePaidRouteWalletMintState
{
    public string Url { get; set; } = "";
    public string Label { get; set; } = "";
    public bool IsDefault { get; set; }
    public bool BalanceKnown { get; set; }
    public ulong BalanceMsat { get; set; }
    public string BalanceText { get; set; } = "";
    public ulong LastCheckedUnix { get; set; }
}

public sealed class NativePaidRouteWalletState
{
    public string DefaultMint { get; set; } = "";
    public bool BalanceKnown { get; set; }
    public ulong TotalBalanceMsat { get; set; }
    public string TotalBalanceText { get; set; } = "";
    public string NavigationBalanceText { get; set; } = "";
    public string FiatCurrency { get; set; } = "";
    public string FiatBalanceText { get; set; } = "";
    public string ExchangeRateText { get; set; } = "";
    public string ExchangeRateStatus { get; set; } = "";
    public string ExchangeRateSources { get; set; } = "";
    public bool ExchangeRateStale { get; set; }
    public ulong ExchangeRateUpdatedAtUnix { get; set; }
    public List<NativePaidRouteWalletMintState> Mints { get; set; } = [];
    public NativePaidRouteWalletActionState LastAction { get; set; } = new();
}

public sealed class NativePaidRouteWalletActionState
{
    public string Kind { get; set; } = "";
    public string StatusText { get; set; } = "";
    public string MintUrl { get; set; } = "";
    public ulong AmountSat { get; set; }
    public string AmountText { get; set; } = "";
    public ulong FeeSat { get; set; }
    public string FeeText { get; set; } = "";
    public string QuoteId { get; set; } = "";
    public string PaymentRequest { get; set; } = "";
    public string Token { get; set; } = "";
    public string OperationId { get; set; } = "";
    public ulong ExpiresAtUnix { get; set; }
    public string Preimage { get; set; } = "";
    public string TokenState { get; set; } = "";
    public bool TokenRedeemable { get; set; }
    public string TokenMemo { get; set; } = "";
    public string DisplayStatusText => string.IsNullOrWhiteSpace(StatusText)
        ? NativeDisplayText.WalletActionTitle(Kind)
        : StatusText;
}

public sealed class NativePaidRoutePaymentActionState
{
    public string Kind { get; set; } = "";
    public string StatusText { get; set; } = "";
    public string PayloadType { get; set; } = "";
    public string SessionId { get; set; } = "";
    public string LeaseId { get; set; } = "";
    public string ChannelId { get; set; } = "";
    public string BuyerNpub { get; set; } = "";
    public string SellerNpub { get; set; } = "";
    public string EnvelopeJson { get; set; } = "";
    public ulong PaidMsat { get; set; }
    public string PaidText { get; set; } = "";
    public ulong DeliveredUnits { get; set; }
    public string DeliveredUsageText { get; set; } = "";
    public ulong AmountDueMsat { get; set; }
    public string AmountDueText { get; set; } = "";
    public ulong UnpaidMsat { get; set; }
    public string UnpaidText { get; set; } = "";
    public bool AllowRouting { get; set; }
    public string DisplayStatusText => string.IsNullOrWhiteSpace(StatusText)
        ? NativeDisplayText.PaymentActionTitle(Kind)
        : StatusText;
}

public sealed class NativePaidRouteOfferState
{
    public string Key { get; set; } = "";
    public string OfferId { get; set; } = "";
    public string SellerNpub { get; set; } = "";
    public string StatusText { get; set; } = "";
    public string PriceText { get; set; } = "";
    public ulong PriceMsatPerGb { get; set; }
    public List<string> AcceptedMints { get; set; } = [];
    public ulong MaxChannelCapacitySat { get; set; }
    public ulong ChannelExpirySecs { get; set; }
    public ulong FreeProbeUnits { get; set; }
    public string FreeProbeText { get; set; } = "";
    public ulong GraceUnits { get; set; }
    public string GraceText { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public uint Asn { get; set; }
    public bool Ipv4 { get; set; }
    public bool Ipv6 { get; set; }
    public bool HasQuality { get; set; }
    public string QualityText { get; set; } = "";
    public string BandwidthText { get; set; } = "";
    public uint LatencyMs { get; set; }
    public uint JitterMs { get; set; }
    public uint PacketLossPpm { get; set; }
    public ulong DownBps { get; set; }
    public ulong UpBps { get; set; }
    public ulong UptimeSecs { get; set; }
    public ulong FirstSeenUnix { get; set; }
    public ulong LastSeenUnix { get; set; }
    public List<string> RelayUrls { get; set; } = [];
    public string DisplayCountry => string.IsNullOrWhiteSpace(CountryCode) ? "Unknown country" : CountryCode.ToUpperInvariant();
    public string DisplayPrice => PriceText;
    public string DisplayMetricText => NativeDisplayText.MetricText(QualityText, BandwidthText);
}

public sealed class NativePaidRouteChannelState
{
    public string ChannelId { get; set; } = "";
    public string OfferId { get; set; } = "";
    public string Role { get; set; } = "";
    public string Status { get; set; } = "";
    public string MintUrl { get; set; } = "";
    public string CounterpartyNpub { get; set; } = "";
    public ulong CapacitySat { get; set; }
    public string CapacityText { get; set; } = "";
    public ulong PaidMsat { get; set; }
    public string PaidText { get; set; } = "";
    public ulong UpdatedAtUnix { get; set; }
    public ulong ExpiresAtUnix { get; set; }
    public string Error { get; set; } = "";
}

public sealed class NativePaidRouteSessionState
{
    public string SessionId { get; set; } = "";
    public string LeaseId { get; set; } = "";
    public string ChannelId { get; set; } = "";
    public string StatusText { get; set; } = "";
    public string LifecycleStatus { get; set; } = "";
    public string AccessState { get; set; } = "";
    public string TitleText { get; set; } = "";
    public string DetailText { get; set; } = "";
    public string SettlementText { get; set; } = "";
    public string CollectActionText { get; set; } = "";
    public string CollectActionHelpText { get; set; } = "";
    public bool PaymentChannelReady { get; set; }
    public bool AllowRouting { get; set; }
    public ulong DeliveredUnits { get; set; }
    public string UsageText { get; set; } = "";
    public ulong AmountDueMsat { get; set; }
    public string AmountDueText { get; set; } = "";
    public ulong PaidMsat { get; set; }
    public string PaidText { get; set; } = "";
    public ulong UnpaidMsat { get; set; }
    public string UnpaidText { get; set; } = "";
    public ulong ActiveMillis { get; set; }
    public ulong Bytes { get; set; }
    public ulong Packets { get; set; }
    public string RealizedExitIp { get; set; } = "";
    public string ClaimedCountryCode { get; set; } = "";
    public string ObservedCountryCode { get; set; } = "";
    public string CountryClaimStatus { get; set; } = "";
    public string LocationText { get; set; } = "";
    public uint ObservedAsn { get; set; }
    public bool HasQuality { get; set; }
    public string QualityText { get; set; } = "";
    public string BandwidthText { get; set; } = "";
    public uint LatencyMs { get; set; }
    public uint JitterMs { get; set; }
    public uint PacketLossPpm { get; set; }
    public ulong DownBps { get; set; }
    public ulong UpBps { get; set; }
    public ulong UpdatedAtUnix { get; set; }
    public ulong ExpiresAtUnix { get; set; }
    public string DisplayTitle
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(TitleText))
            {
                return TitleText;
            }
            if (AllowRouting)
            {
                return "Ready";
            }
            if (UnpaidMsat > 0)
            {
                return "Payment needed";
            }
            if (!PaymentChannelReady)
            {
                return "Needs funds";
            }
            return NativeDisplayText.PlainStatus(
                string.IsNullOrWhiteSpace(StatusText) ? LifecycleStatus : StatusText,
                "Session");
        }
    }
    public string DisplayDetail
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(DetailText))
            {
                return DetailText;
            }
            var access = NativeDisplayText.AccessTitle(AccessState, string.IsNullOrWhiteSpace(LifecycleStatus) ? "session" : LifecycleStatus);
            var usage = !string.IsNullOrWhiteSpace(UsageText)
                ? UsageText
                : Bytes > 0
                ? $"{NativeDisplayText.FormatBytes(Bytes)} used"
                : Packets > 0
                    ? $"{Packets} packets"
                    : $"{DeliveredUnits} units";
            var due = string.IsNullOrWhiteSpace(AmountDueText)
                ? $"{NativeDisplayText.FormatMsat(AmountDueMsat)} due"
                : AmountDueText;
            return $"{access}, {usage}, {due}";
        }
    }
    public string DisplayLocationText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(LocationText))
            {
                return LocationText;
            }
            var claim = NativeDisplayText.CountryClaimText(ClaimedCountryCode, ObservedCountryCode, CountryClaimStatus);
            if (!string.IsNullOrWhiteSpace(RealizedExitIp) && !string.IsNullOrWhiteSpace(claim))
            {
                return $"{RealizedExitIp} · {claim}";
            }
            return !string.IsNullOrWhiteSpace(RealizedExitIp) ? RealizedExitIp : claim;
        }
    }
    public string DisplayPaidText => string.IsNullOrWhiteSpace(PaidText) ? $"{NativeDisplayText.FormatMsat(PaidMsat)} paid" : PaidText;
    public string DisplayBehindText => string.IsNullOrWhiteSpace(UnpaidText)
        ? UnpaidMsat > 0 ? $"{NativeDisplayText.FormatMsat(UnpaidMsat)} behind" : ""
        : UnpaidText;
    public string DisplayMetricText => NativeDisplayText.MetricText(QualityText, BandwidthText);
    public string DisplaySettlementText => SettlementText;
    public bool CanOpenChannel => !string.IsNullOrWhiteSpace(SessionId) && !PaymentChannelReady;
    public bool CanPay => !string.IsNullOrWhiteSpace(SessionId) && PaymentChannelReady && UnpaidMsat > 0;
    public bool CanSettleChannel => !string.IsNullOrWhiteSpace(SessionId)
        && PaymentChannelReady
        && !string.Equals(LifecycleStatus, "closed", System.StringComparison.Ordinal)
        && !string.Equals(LifecycleStatus, "expired", System.StringComparison.Ordinal);
}

public sealed class NativePaidRouteMarketFilterState
{
    public string Query { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string MintUrl { get; set; } = "";
    public bool RequireIpv4 { get; set; }
    public bool RequireIpv6 { get; set; }
    public string Sort { get; set; } = "quality";
}

public sealed class NativePaidRouteMarketState
{
    public bool Supported { get; set; }
    public string StatusText { get; set; } = "";
    public string ManualProviderLink { get; set; } = "";
    public string ManualProviderStatusText { get; set; } = "";
    public string StorePath { get; set; } = "";
    public NativePaidRouteWalletState Wallet { get; set; } = new();
    public NativePaidRoutePaymentActionState LastPaymentAction { get; set; } = new();
    public NativePaidRouteMarketFilterState Filter { get; set; } = new();
    public List<NativePaidRouteOfferState> Offers { get; set; } = [];
    public List<NativePaidRouteOfferState> VisibleOffers { get; set; } = [];
    public ulong HiddenOfferCount { get; set; }
    public List<string> CountryOptions { get; set; } = [];
    public List<NativePaidRouteChannelState> Channels { get; set; } = [];
    public List<NativePaidRouteSessionState> Sessions { get; set; } = [];
}

public sealed class NativeNetworkState
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public string NetworkId { get; set; } = "";
    public bool LocalIsAdmin { get; set; }
    public bool JoinRequestsEnabled { get; set; }
    public string JoinRequestAdminNpub { get; set; } = "";
    public List<string> AdminNpubs { get; set; } = [];
    public NativeOutboundJoinRequestState? OutboundJoinRequest { get; set; }
    public List<NativeInboundJoinRequestState> InboundJoinRequests { get; set; } = [];
    public ulong OnlineCount { get; set; }
    public ulong ExpectedCount { get; set; }
    public List<string> Admins { get; set; } = [];
    public List<NativeParticipantState> Participants { get; set; } = [];
}

public sealed class NativeParticipantState
{
    public string Npub { get; set; } = "";
    public string PubkeyHex { get; set; } = "";
    public string Alias { get; set; } = "";
    public string MagicDnsAlias { get; set; } = "";
    public string MagicDnsName { get; set; } = "";
    public string TunnelIp { get; set; } = "";
    public bool IsAdmin { get; set; }
    public bool RosterAccepted { get; set; }
    public bool Reachable { get; set; }
    public ulong TxBytes { get; set; }
    public ulong RxBytes { get; set; }
    public List<string> AdvertisedRoutes { get; set; } = [];
    public bool OffersExitNode { get; set; }
    public string FipsEndpointNpub { get; set; } = "";
    public List<string> FipsEndpointHints { get; set; } = [];
    public string FipsTransportAddr { get; set; } = "";
    public string FipsTransportType { get; set; } = "";
    public ulong FipsSrttMs { get; set; }
    public ulong FipsSrttAgeMs { get; set; }
    public ulong FipsPacketsSent { get; set; }
    public ulong FipsPacketsRecv { get; set; }
    public ulong FipsBytesSent { get; set; }
    public ulong FipsBytesRecv { get; set; }
    public bool FipsDirectProbePending { get; set; }
    public ulong FipsDirectProbeAfterMs { get; set; }
    public uint FipsDirectProbeRetryCount { get; set; }
    public bool FipsDirectProbeAutoReconnect { get; set; }
    public ulong FipsDirectProbeExpiresAtMs { get; set; }
    public string State { get; set; } = "";
    public string MeshState { get; set; } = "";
    public string StatusText { get; set; } = "";
    public string LastFipsControlSeenText { get; set; } = "";
    public string LastFipsDataSeenText { get; set; } = "";
    public string LastSeenText { get; set; } = "";
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsSelf { get; set; }
    [System.Text.Json.Serialization.JsonIgnore]
    public string SelectionKey => string.IsNullOrWhiteSpace(PubkeyHex) ? Npub : PubkeyHex;
    [System.Text.Json.Serialization.JsonIgnore]
    public string AcceptedRosterAutomationId =>
        RosterAccepted ? $"RosterParticipantAccepted-{Npub}" : "";
    public string DisplayName => FirstNonEmpty(
        MagicDnsName,
        Alias,
        MagicDnsAlias,
        ShortText(Npub, 12, 6));
    public string CleanTunnelIp => TunnelIp.Split('/')[0].Trim();
    public string MagicDnsDisplay => FirstNonEmpty(MagicDnsName, MagicDnsAlias, "-");
    public string LastSeenDisplay => string.IsNullOrWhiteSpace(LastSeenText) ? "-" : LastSeenText;
    public string LastFipsControlSeenDisplay => string.IsNullOrWhiteSpace(LastFipsControlSeenText) ? "-" : LastFipsControlSeenText;
    public string LastFipsDataSeenDisplay => string.IsNullOrWhiteSpace(LastFipsDataSeenText) ? "-" : LastFipsDataSeenText;
    public string FipsSrttAgeDisplay => FipsSrttAgeMs == 0 ? "-" : NativeDisplayText.FormatDurationMs(FipsSrttAgeMs);
    public string TxBytesDisplay => FormatBytes(TxBytes);
    public string RxBytesDisplay => FormatBytes(RxBytes);
    public string RoleText
    {
        get
        {
            var roles = new List<string>();
            if (IsSelf)
            {
                roles.Add("This device");
            }
            if (IsAdmin)
            {
                roles.Add("Admin");
            }
            if (OffersExitNode)
            {
                roles.Add("Shares internet");
            }
            return roles.Count == 0 ? "Member" : string.Join(", ", roles);
        }
    }
    public string ConnectivityStateText
    {
        get
        {
            return State.ToLowerInvariant() switch
            {
                "off" => "Off",
                "local" or "online" or "present" => "Online",
                "pending" => "Connecting",
                "offline" => "Offline",
                _ when Reachable => "Online",
                _ => "Unknown",
            };
        }
    }
    public string StatusDetailText => string.IsNullOrWhiteSpace(StatusText) ? ConnectivityStateText : StatusText;
    public bool IsFipsDirect => Reachable
        && !string.Equals(State, "local", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(FipsTransportAddr);
    public bool IsFipsRouted => Reachable
        && !string.Equals(State, "local", StringComparison.OrdinalIgnoreCase)
        && string.IsNullOrWhiteSpace(FipsTransportAddr);
    public string FipsPathText
    {
        get
        {
            if (string.Equals(State, "local", StringComparison.OrdinalIgnoreCase))
            {
                return "This device";
            }
            if (IsFipsDirect)
            {
                var transport = string.IsNullOrWhiteSpace(FipsTransportType) ? "" : $" ({FipsTransportType.ToUpperInvariant()})";
                return FipsSrttMs > 0 ? $"Direct connection{transport}, {FipsSrttMs} ms" : $"Direct connection{transport}";
            }
            if (IsFipsRouted)
            {
                return FipsSrttMs > 0 ? $"Via mesh, {FipsSrttMs} ms" : "Via mesh";
            }
            if (string.Equals(State, "pending", StringComparison.OrdinalIgnoreCase))
            {
                return "Connecting";
            }
            return "Offline";
        }
    }
    public string FipsEndpointHintsText => FipsEndpointHints.Count == 0 ? "-" : string.Join(", ", FipsEndpointHints);
    public string FipsEndpointHintsEditText => string.Join(", ", FipsEndpointHints);

    private static string FirstNonEmpty(params string[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }
        return "";
    }

    private static string ShortText(string value, int prefix, int suffix)
    {
        if (value.Length <= prefix + suffix + 3)
        {
            return value;
        }
        return $"{value[..prefix]}...{value[^suffix..]}";
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }
        if (unitIndex == 0)
        {
            return $"{bytes} B";
        }
        return Math.Abs(value - Math.Round(value)) < 0.05
            ? $"{value:0} {units[unitIndex]}"
            : $"{value:0.0} {units[unitIndex]}";
    }
}

internal static class NativeDisplayText
{
    public static string FormatMsat(ulong msat)
    {
        if (msat == 0)
        {
            return "0 sat";
        }
        var whole = msat / 1_000;
        var remainder = msat % 1_000;
        return remainder == 0 ? $"{whole} sat" : $"{whole}.{remainder:D3} sat";
    }

    public static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var index = 0;
        while (value >= 1024 && index < units.Length - 1)
        {
            value /= 1024;
            index++;
        }
        if (index == 0)
        {
            return $"{bytes} B";
        }
        return Math.Abs(value - Math.Round(value)) < 0.05
            ? $"{value:0} {units[index]}"
            : $"{value:0.0} {units[index]}";
    }

    public static string TrafficUnitText(ulong units) => FormatBytes(units);

    public static string MetricText(string qualityText, string bandwidthText)
    {
        var parts = new List<string>();
        foreach (var value in new[] { qualityText, bandwidthText })
        {
            var text = value.Trim();
            if (!string.IsNullOrWhiteSpace(text)
                && !string.Equals(text, "Quality unmeasured", StringComparison.OrdinalIgnoreCase))
            {
                parts.Add(text);
            }
        }
        return string.Join(" · ", parts);
    }

    public static string PaidExitUpstreamTitle(string value) => value switch
    {
        "wireguard_exit" or "wireguard" or "wg" or "upstream_vpn" or "vpn" => "My internet through WireGuard",
        _ => "My internet",
    };

    public static string AccessTitle(string value, string fallback) => value switch
    {
        "paid" => "Paid",
        "free_probe" => "Free test",
        "grace" => "Grace",
        "suspended" => "Paused",
        _ => PlainStatus(value, fallback),
    };

    public static string PlainStatus(string value, string fallback)
    {
        var raw = string.IsNullOrWhiteSpace(value) ? fallback : value;
        return raw switch
        {
            "opening" => "Opening",
            "probing" => "Checking quality",
            "active" => "Active",
            "paused" => "Paused",
            "closed" => "Closed",
            "session" => "Session",
            _ => Humanize(raw),
        };
    }

    public static string PaymentActionTitle(string kind) => kind switch
    {
        "send" => "Payment sent",
        "receive" => "Payment received",
        "apply" => "Payment applied",
        "create" => "Payment ready",
        "open_channel" => "Exit funded",
        "sign" => "Payment ready",
        "close" => "Channel settled",
        "stream" => "Payments sent",
        "probe" => "Quality checked",
        "" => "",
        _ => Humanize(kind),
    };

    public static string WalletActionTitle(string kind) => kind switch
    {
        "topup" => "Invoice ready",
        "receive" => "Token imported",
        "send" => "Token ready",
        "withdraw" => "Invoice paid",
        "refresh" => "Wallet refreshed",
        "open_channel" => "Exit funded",
        "" => "",
        _ => Humanize(kind),
    };

    public static string CountryClaimText(string claimed, string observed, string status) => status switch
    {
        "match" => string.IsNullOrWhiteSpace(observed) && string.IsNullOrWhiteSpace(claimed)
            ? ""
            : $"{(string.IsNullOrWhiteSpace(observed) ? claimed : observed)} verified",
        "mismatch" => string.IsNullOrWhiteSpace(claimed)
            ? "country mismatch"
            : $"claimed {claimed}",
        _ => !string.IsNullOrWhiteSpace(observed) ? observed : claimed,
    };

    private static string Humanize(string value)
    {
        var text = value.Replace('_', ' ');
        return string.IsNullOrWhiteSpace(text)
            ? ""
            : char.ToUpperInvariant(text[0]) + text[1..];
    }

    public static string FormatDurationMs(ulong ms)
    {
        if (ms < 1_000)
        {
            return $"{ms} ms";
        }
        var seconds = ms / 1_000;
        if (seconds < 60)
        {
            return $"{seconds}s";
        }
        var minutes = seconds / 60;
        if (minutes < 60)
        {
            return $"{minutes}m";
        }
        return $"{minutes / 60}h";
    }
}

public sealed class NativeOutboundJoinRequestState
{
    public string RecipientNpub { get; set; } = "";
    public string RecipientPubkeyHex { get; set; } = "";
    public string RequestedAtText { get; set; } = "";
}

public sealed class NativeInboundJoinRequestState
{
    public string RequesterNpub { get; set; } = "";
    public string RequesterPubkeyHex { get; set; } = "";
    public string RequesterNodeName { get; set; } = "";
    public string RequestedAtText { get; set; } = "";
}

public sealed class NativeHealthIssue
{
    public string Code { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Detail { get; set; } = "";
}

public sealed class NativeNetworkSummary
{
    public string DefaultInterface { get; set; } = "";
    public string PrimaryIpv4 { get; set; } = "";
    public string PrimaryIpv6 { get; set; } = "";
    public string GatewayIpv4 { get; set; } = "";
    public string GatewayIpv6 { get; set; } = "";
    public ulong ChangedAt { get; set; }
    public string CaptivePortal { get; set; } = "";
}

public sealed class NativeProbeStatus
{
    public string State { get; set; } = "";
    public string Detail { get; set; } = "";
}

public sealed class NativePortMappingStatus
{
    public NativeProbeStatus Upnp { get; set; } = new();
    public NativeProbeStatus NatPmp { get; set; } = new();
    public NativeProbeStatus Pcp { get; set; } = new();
    public string ActiveProtocol { get; set; } = "";
    public string ExternalEndpoint { get; set; } = "";
    public string Gateway { get; set; } = "";
    public ulong GoodUntil { get; set; }
}

public sealed class QrMatrix
{
    public int Width { get; set; }
    public List<bool> Cells { get; set; } = [];
    public string Error { get; set; } = "";
}

public sealed class QrDecodeResult
{
    public string Value { get; set; } = "";
    public string Error { get; set; } = "";
}
