import Foundation

struct AppState: Decodable {
    var rev: UInt64 = 0
    var error = ""
    var appVersion = ""
    var platform = ""
    var mobile = true
    var vpnControlSupported = false
    var runtimeStatusDetail = ""
    var vpnEnabled = false
    var vpnActive = false
    var vpnStatus = "Disconnected"
    var daemonRunning = false
    var ownNpub = ""
    var nodeName = ""
    var selfMagicDnsName = ""
    var tunnelIp = ""
    var endpoint = ""
    var listenPort: Int = 0
    var relays: [RelayState] = []
    var nostrPubsubMode = "relay"
    var nostrPubsubFanout: UInt32 = 4
    var nostrPubsubMaxHops: UInt8 = 2
    var nostrPubsubMaxEventBytes: UInt32 = 65_536
    var joinRequestQrCodeOrLink = ""
    var connectedPeerCount: UInt64 = 0
    var expectedPeerCount: UInt64 = 0
    var fipsConnectedPeerCount: UInt64 = 0
    var fipsRosterPeerCount: UInt64 = 0
    var nonFipsRosterPeerCount: UInt64 = 0
    var meshReady = false
    var internetSource = "direct"
    var exitNode = ""
    var exitNodeLeakProtection = true
    var exitNodeActive = false
    var exitNodeBlocked = false
    var exitNodeStatusText = ""
    var exitDnsMode = "automatic"
    var exitDnsDohProvider = "cloudflare"
    var exitDnsCustomDohUrl = ""
    var exitDnsCustomDohBootstrapIps = ""
    var exitDnsThroughExitServers = ""
    var advertiseExitNode = false
    var advertisedRoutes: [String] = []
    var wireguardExitEnabled = false
    var wireguardExitConfigured = false
    var wireguardExitInterface = ""
    var wireguardExitAddress = ""
    var wireguardExitPrivateKey = ""
    var wireguardExitPeerPublicKey = ""
    var wireguardExitPeerPresharedKey = ""
    var wireguardExitEndpoint = ""
    var wireguardExitAllowedIps = ""
    var wireguardExitDns = ""
    var wireguardExitMtu: Int = 0
    var wireguardExitPersistentKeepaliveSecs: Int = 0
    var wireguardExitConfig = ""
    var walletFiatEnabled = true
    var walletFiatCurrency = "USD"
    var paidExitSeller = PaidExitSellerState()
    var paidRouteMarket = PaidRouteMarketState()
    var connectToNonRosterFipsPeers = true
    var fipsNostrDiscoveryEnabled = true
    var fipsWebrtcEnabled = false
    var fipsBootstrapEnabled = true
    var magicDnsSuffix = ""
    var magicDnsStatus = ""
    var autoconnect = false
    var configPath = ""
    var networks: [NetworkState] = []
    var health: [HealthIssue] = []

    var activeNetwork: NetworkState? {
        networks.first(where: { $0.enabled })
    }

    enum CodingKeys: String, CodingKey {
        case rev, error, appVersion, platform, mobile, vpnControlSupported
        case runtimeStatusDetail, vpnEnabled, vpnActive, vpnStatus, daemonRunning
        case ownNpub, nodeName, selfMagicDnsName, tunnelIp, endpoint, listenPort, relays
        case nostrPubsubMode, nostrPubsubFanout, nostrPubsubMaxHops, nostrPubsubMaxEventBytes
        case joinRequestQrCodeOrLink
        case connectedPeerCount, expectedPeerCount
        case fipsConnectedPeerCount, fipsRosterPeerCount, nonFipsRosterPeerCount
        case meshReady, internetSource, exitNode, exitNodeLeakProtection
        case exitNodeActive, exitNodeBlocked, exitNodeStatusText
        case exitDnsMode, exitDnsDohProvider, exitDnsCustomDohUrl
        case exitDnsCustomDohBootstrapIps, exitDnsThroughExitServers, advertiseExitNode
        case advertisedRoutes
        case wireguardExitEnabled, wireguardExitConfigured, wireguardExitInterface, wireguardExitAddress
        case wireguardExitPrivateKey, wireguardExitPeerPublicKey, wireguardExitPeerPresharedKey
        case wireguardExitEndpoint, wireguardExitAllowedIps, wireguardExitDns
        case wireguardExitMtu, wireguardExitPersistentKeepaliveSecs, wireguardExitConfig
        case walletFiatEnabled, walletFiatCurrency
        case paidExitSeller, paidRouteMarket
        case connectToNonRosterFipsPeers
        case fipsNostrDiscoveryEnabled, fipsWebrtcEnabled, fipsBootstrapEnabled
        case magicDnsSuffix, magicDnsStatus, autoconnect
        case configPath
        case networks, health
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        rev = container.uint64(.rev)
        error = container.string(.error)
        appVersion = container.string(.appVersion)
        platform = container.string(.platform)
        mobile = container.bool(.mobile, default: true)
        vpnControlSupported = container.bool(.vpnControlSupported)
        runtimeStatusDetail = container.string(.runtimeStatusDetail)
        vpnEnabled = container.bool(.vpnEnabled)
        vpnActive = container.bool(.vpnActive)
        vpnStatus = container.string(.vpnStatus, default: "Disconnected")
        daemonRunning = container.bool(.daemonRunning)
        ownNpub = container.string(.ownNpub)
        nodeName = container.string(.nodeName)
        selfMagicDnsName = container.string(.selfMagicDnsName)
        tunnelIp = container.string(.tunnelIp)
        endpoint = container.string(.endpoint)
        listenPort = container.int(.listenPort)
        relays = container.array(.relays)
        nostrPubsubMode = container.string(.nostrPubsubMode, default: "relay")
        nostrPubsubFanout = UInt32(container.int(.nostrPubsubFanout, default: 4))
        nostrPubsubMaxHops = UInt8(container.int(.nostrPubsubMaxHops, default: 2))
        nostrPubsubMaxEventBytes = UInt32(container.int(.nostrPubsubMaxEventBytes, default: 65_536))
        joinRequestQrCodeOrLink = container.string(.joinRequestQrCodeOrLink)
        connectedPeerCount = container.uint64(.connectedPeerCount)
        expectedPeerCount = container.uint64(.expectedPeerCount)
        fipsConnectedPeerCount = container.uint64(.fipsConnectedPeerCount)
        fipsRosterPeerCount = container.uint64(.fipsRosterPeerCount)
        nonFipsRosterPeerCount = container.uint64(.nonFipsRosterPeerCount)
        meshReady = container.bool(.meshReady)
        internetSource = container.string(.internetSource, default: "direct")
        exitNode = container.string(.exitNode)
        exitNodeLeakProtection = container.bool(.exitNodeLeakProtection, default: true)
        exitNodeActive = container.bool(.exitNodeActive)
        exitNodeBlocked = container.bool(.exitNodeBlocked)
        exitNodeStatusText = container.string(.exitNodeStatusText)
        exitDnsMode = container.string(.exitDnsMode, default: "automatic")
        exitDnsDohProvider = container.string(.exitDnsDohProvider, default: "cloudflare")
        exitDnsCustomDohUrl = container.string(.exitDnsCustomDohUrl)
        exitDnsCustomDohBootstrapIps = container.string(.exitDnsCustomDohBootstrapIps)
        exitDnsThroughExitServers = container.string(.exitDnsThroughExitServers)
        advertiseExitNode = container.bool(.advertiseExitNode)
        advertisedRoutes = container.array(.advertisedRoutes)
        wireguardExitEnabled = container.bool(.wireguardExitEnabled)
        wireguardExitConfigured = container.bool(.wireguardExitConfigured)
        wireguardExitInterface = container.string(.wireguardExitInterface)
        wireguardExitAddress = container.string(.wireguardExitAddress)
        wireguardExitPrivateKey = container.string(.wireguardExitPrivateKey)
        wireguardExitPeerPublicKey = container.string(.wireguardExitPeerPublicKey)
        wireguardExitPeerPresharedKey = container.string(.wireguardExitPeerPresharedKey)
        wireguardExitEndpoint = container.string(.wireguardExitEndpoint)
        wireguardExitAllowedIps = container.string(.wireguardExitAllowedIps)
        wireguardExitDns = container.string(.wireguardExitDns)
        wireguardExitMtu = container.int(.wireguardExitMtu)
        wireguardExitPersistentKeepaliveSecs = container.int(.wireguardExitPersistentKeepaliveSecs)
        wireguardExitConfig = container.string(.wireguardExitConfig)
        walletFiatEnabled = container.bool(.walletFiatEnabled, default: true)
        walletFiatCurrency = container.string(.walletFiatCurrency, default: "USD")
        paidExitSeller = (try? container.decodeIfPresent(PaidExitSellerState.self, forKey: .paidExitSeller)) ?? PaidExitSellerState()
        paidRouteMarket = (try? container.decodeIfPresent(PaidRouteMarketState.self, forKey: .paidRouteMarket)) ?? PaidRouteMarketState()
        connectToNonRosterFipsPeers = container.bool(.connectToNonRosterFipsPeers, default: true)
        fipsNostrDiscoveryEnabled = container.bool(.fipsNostrDiscoveryEnabled, default: true)
        fipsWebrtcEnabled = container.bool(.fipsWebrtcEnabled)
        fipsBootstrapEnabled = container.bool(.fipsBootstrapEnabled, default: true)
        magicDnsSuffix = container.string(.magicDnsSuffix)
        magicDnsStatus = container.string(.magicDnsStatus)
        autoconnect = container.bool(.autoconnect)
        configPath = container.string(.configPath)
        networks = container.array(.networks)
        health = container.array(.health)
    }
}

struct RelayState: Decodable, Identifiable {
    var url = ""
    var status = "unknown"
    var enabled = true
    var id: String { url }
    var connected: Bool { enabled && status == "connected" }
}

struct NetworkState: Decodable, Identifiable {
    var id = ""
    var name = ""
    var enabled = false
    var networkId = ""
    var localIsAdmin = false
    var joinRequestsEnabled = false
    var joinRequestAdminNpub = ""
    var outboundJoinRequest: OutboundJoinRequest?
    var joinRequestQrCodeOrLink = ""
    var inboundJoinRequests: [InboundJoinRequest] = []
    var onlineCount: UInt64 = 0
    var expectedCount: UInt64 = 0
    var participants: [ParticipantState] = []

    var displayName: String {
        name.isEmpty ? "Private network" : name
    }

    enum CodingKeys: String, CodingKey {
        case id, name, enabled, networkId, localIsAdmin, joinRequestsEnabled
        case joinRequestAdminNpub, outboundJoinRequest, joinRequestQrCodeOrLink, inboundJoinRequests
        case onlineCount, expectedCount, participants
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = container.string(.id)
        name = container.string(.name)
        enabled = container.bool(.enabled)
        networkId = container.string(.networkId)
        localIsAdmin = container.bool(.localIsAdmin)
        joinRequestsEnabled = container.bool(.joinRequestsEnabled)
        joinRequestAdminNpub = container.string(.joinRequestAdminNpub)
        outboundJoinRequest = try? container.decodeIfPresent(OutboundJoinRequest.self, forKey: .outboundJoinRequest)
        joinRequestQrCodeOrLink = container.string(.joinRequestQrCodeOrLink)
        inboundJoinRequests = container.array(.inboundJoinRequests)
        onlineCount = container.uint64(.onlineCount)
        expectedCount = container.uint64(.expectedCount)
        participants = container.array(.participants)
    }
}

struct ParticipantState: Decodable, Identifiable {
    var id: String { pubkeyHex.isEmpty ? npub : pubkeyHex }
    var npub = ""
    var pubkeyHex = ""
    var alias = ""
    var magicDnsAlias = ""
    var magicDnsName = ""
    var tunnelIp = ""
    var isAdmin = false
    var rosterAccepted = false
    var reachable = false
    var offersExitNode = false
    var fipsEndpointNpub = ""
    var fipsEndpointHints: [String] = []
    var fipsTransportAddr = ""
    var fipsTransportType = ""
    var fipsSrttMs: UInt64 = 0
    var fipsSrttAgeMs: UInt64 = 0
    var fipsPacketsSent: UInt64 = 0
    var fipsPacketsRecv: UInt64 = 0
    var fipsBytesSent: UInt64 = 0
    var fipsBytesRecv: UInt64 = 0
    var fipsDirectProbePending = false
    var fipsDirectProbeAfterMs: UInt64 = 0
    var fipsDirectProbeRetryCount: UInt32 = 0
    var fipsDirectProbeAutoReconnect = false
    var fipsDirectProbeExpiresAtMs: UInt64 = 0
    var state = ""
    var meshState = ""
    var statusText = ""
    var lastFipsControlSeenText = ""
    var lastFipsDataSeenText = ""
    var lastSeenText = ""

    var displayName: String {
        if !magicDnsName.isEmpty { return magicDnsName }
        if !alias.isEmpty { return alias }
        return "Device"
    }

    enum CodingKeys: String, CodingKey {
        case npub, pubkeyHex, alias, magicDnsAlias, magicDnsName, tunnelIp
        case isAdmin, rosterAccepted, reachable, offersExitNode
        case fipsEndpointNpub, fipsEndpointHints, fipsTransportAddr, fipsTransportType, fipsSrttMs
        case fipsSrttAgeMs
        case fipsPacketsSent, fipsPacketsRecv, fipsBytesSent, fipsBytesRecv
        case fipsDirectProbePending, fipsDirectProbeAfterMs, fipsDirectProbeRetryCount
        case fipsDirectProbeAutoReconnect, fipsDirectProbeExpiresAtMs
        case state, meshState, statusText
        case lastFipsControlSeenText, lastFipsDataSeenText, lastSeenText, lastSignalText
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        npub = container.string(.npub)
        pubkeyHex = container.string(.pubkeyHex)
        alias = container.string(.alias)
        magicDnsAlias = container.string(.magicDnsAlias)
        magicDnsName = container.string(.magicDnsName)
        tunnelIp = container.string(.tunnelIp)
        isAdmin = container.bool(.isAdmin)
        rosterAccepted = container.bool(.rosterAccepted)
        reachable = container.bool(.reachable)
        offersExitNode = container.bool(.offersExitNode)
        fipsEndpointNpub = container.string(.fipsEndpointNpub)
        fipsEndpointHints = container.array(.fipsEndpointHints)
        fipsTransportAddr = container.string(.fipsTransportAddr)
        fipsTransportType = container.string(.fipsTransportType)
        fipsSrttMs = container.uint64(.fipsSrttMs)
        fipsSrttAgeMs = container.uint64(.fipsSrttAgeMs)
        fipsPacketsSent = container.uint64(.fipsPacketsSent)
        fipsPacketsRecv = container.uint64(.fipsPacketsRecv)
        fipsBytesSent = container.uint64(.fipsBytesSent)
        fipsBytesRecv = container.uint64(.fipsBytesRecv)
        fipsDirectProbePending = container.bool(.fipsDirectProbePending)
        fipsDirectProbeAfterMs = container.uint64(.fipsDirectProbeAfterMs)
        fipsDirectProbeRetryCount = UInt32(container.uint64(.fipsDirectProbeRetryCount))
        fipsDirectProbeAutoReconnect = container.bool(.fipsDirectProbeAutoReconnect)
        fipsDirectProbeExpiresAtMs = container.uint64(.fipsDirectProbeExpiresAtMs)
        state = container.string(.state)
        meshState = container.string(.meshState)
        statusText = container.string(.statusText)
        lastFipsControlSeenText = container.string(.lastFipsControlSeenText)
        lastFipsDataSeenText = container.string(.lastFipsDataSeenText)
        lastSeenText = container.string(.lastSeenText, default: container.string(.lastSignalText))
    }
}

struct OutboundJoinRequest: Decodable {
    var recipientNpub = ""
    var requestedAtText = ""
}

struct InboundJoinRequest: Decodable, Identifiable {
    var id: String { requesterNpub }
    var requesterNpub = ""
    var requesterNodeName = ""
    var requestedAtText = ""
}

struct HealthIssue: Decodable, Identifiable {
    var id: String { code + summary }
    var code = ""
    var severity = ""
    var summary = ""
    var detail = ""
}

struct PaidExitSellerState: Decodable, Equatable {
    var supported = false
    var enabled = false
    var statusText = ""
    var providerLink = ""
    var upstream = ""
    var privateVpnAccess = ""
    var internetText = ""
    var publicIpText = ""
    var priceText = ""
    var priceMsatPerGb: UInt64 = 0
    var acceptedMints: [String] = []
    var maxChannelCapacitySat: UInt64 = 0
    var channelExpirySecs: UInt64 = 0
    var channelExpiryText = ""
    var settlementText = ""
    var freeProbeUnits: UInt64 = 0
    var freeProbeText = ""
    var graceUnits: UInt64 = 0
    var graceText = ""
    var countryCode = ""
    var networkClass = "unknown"
    var asn: UInt32 = 0
    var ipv4 = false
    var ipv6 = false
    var channelCreditMsat: UInt64 = 0
    var channelCreditText = ""
    var channelCreditTitleText = ""
    var channelCreditHelpText = ""
    var currentConnectionCount: UInt64 = 0
    var pastConnectionCount: UInt64 = 0
    var totalBillableBytes: UInt64 = 0
    var totalTrafficText = ""
    var totalPaidMsat: UInt64 = 0
    var totalPaidText = ""
    var totalDueMsat: UInt64 = 0
    var totalDueText = ""
    var totalUnpaidMsat: UInt64 = 0
    var totalUnpaidText = ""
    var channels: [PaidRouteChannelState] = []
    var sessions: [PaidRouteSessionState] = []

    init() {}
}

struct PaidRouteWalletMintState: Decodable, Identifiable, Equatable {
    var id: String { url }
    var url = ""
    var label = ""
    var isDefault = false
    var balanceKnown = false
    var balanceMsat: UInt64 = 0
    var balanceText = ""
    var lastCheckedUnix: UInt64 = 0

    init() {}
}

struct PaidRouteWalletState: Decodable, Equatable {
    var defaultMint = ""
    var balanceKnown = false
    var totalBalanceMsat: UInt64 = 0
    var totalBalanceText = ""
    var navigationBalanceText = ""
    var fiatCurrency = ""
    var fiatBalanceText = ""
    var exchangeRateText = ""
    var exchangeRateStatus = ""
    var exchangeRateSources = ""
    var exchangeRateStale = false
    var exchangeRateUpdatedAtUnix: UInt64 = 0
    var mints: [PaidRouteWalletMintState] = []
    var lastAction = PaidRouteWalletActionState()

    init() {}
}

struct PaidRouteWalletActionState: Decodable, Equatable {
    var kind = ""
    var statusText = ""
    var mintUrl = ""
    var amountSat: UInt64 = 0
    var amountText = ""
    var feeSat: UInt64 = 0
    var feeText = ""
    var quoteId = ""
    var paymentRequest = ""
    var token = ""
    var operationId = ""
    var expiresAtUnix: UInt64 = 0
    var preimage = ""
    var tokenState = ""
    var tokenRedeemable = false
    var tokenMemo = ""

    init() {}
}

struct PaidRoutePaymentActionState: Decodable, Equatable {
    var kind = ""
    var statusText = ""
    var payloadType = ""
    var sessionId = ""
    var leaseId = ""
    var channelId = ""
    var buyerNpub = ""
    var sellerNpub = ""
    var envelopeJson = ""
    var paidMsat: UInt64 = 0
    var paidText = ""
    var deliveredUnits: UInt64 = 0
    var deliveredUsageText = ""
    var amountDueMsat: UInt64 = 0
    var amountDueText = ""
    var unpaidMsat: UInt64 = 0
    var unpaidText = ""
    var allowRouting = false

    init() {}
}

struct PaidRouteOfferState: Decodable, Identifiable, Equatable {
    var personalRating: Int64 = 0
    var canRate = false
    var hasRating = false
    var ratingScore: Int64 = 0
    var id: String { key.isEmpty ? "\(sellerNpub):\(offerId)" : key }
    var key = ""
    var offerId = ""
    var sellerNpub = ""
    var statusText = ""
    var priceText = ""
    var priceMsatPerGb: UInt64 = 0
    var acceptedMints: [String] = []
    var maxChannelCapacitySat: UInt64 = 0
    var channelExpirySecs: UInt64 = 0
    var freeProbeUnits: UInt64 = 0
    var freeProbeText = ""
    var graceUnits: UInt64 = 0
    var graceText = ""
    var countryCode = ""
    var networkClass = "unknown"
    var asn: UInt32 = 0
    var ipv4 = false
    var ipv6 = false
    var hasQuality = false
    var qualityText = ""
    var bandwidthText = ""
    var latencyMs: UInt32 = 0
    var jitterMs: UInt32 = 0
    var packetLossPpm: UInt32 = 0
    var downBps: UInt64 = 0
    var upBps: UInt64 = 0
    var uptimeSecs: UInt64 = 0
    var firstSeenUnix: UInt64 = 0
    var lastSeenUnix: UInt64 = 0
    var relayUrls: [String] = []

    init() {}
}

struct PaidRouteChannelState: Decodable, Identifiable, Equatable {
    var id: String { channelId }
    var channelId = ""
    var offerId = ""
    var role = ""
    var status = ""
    var mintUrl = ""
    var counterpartyNpub = ""
    var capacitySat: UInt64 = 0
    var capacityText = ""
    var paidMsat: UInt64 = 0
    var paidText = ""
    var updatedAtUnix: UInt64 = 0
    var expiresAtUnix: UInt64 = 0
    var error = ""

    init() {}
}

struct PaidRouteSessionState: Decodable, Identifiable, Equatable {
    var sellerNpub = ""
    var personalRating: Int64 = 0
    var canRate = false
    var id: String { sessionId }
    var sessionId = ""
    var leaseId = ""
    var channelId = ""
    var statusText = ""
    var lifecycleStatus = ""
    var accessState = ""
    var titleText = ""
    var detailText = ""
    var settlementText = ""
    var collectActionText = ""
    var collectActionHelpText = ""
    var paymentChannelReady = false
    var allowRouting = false
    var deliveredUnits: UInt64 = 0
    var usageText = ""
    var amountDueMsat: UInt64 = 0
    var amountDueText = ""
    var paidMsat: UInt64 = 0
    var paidText = ""
    var unpaidMsat: UInt64 = 0
    var unpaidText = ""
    var activeMillis: UInt64 = 0
    var bytes: UInt64 = 0
    var packets: UInt64 = 0
    var realizedExitIp = ""
    var claimedCountryCode = ""
    var observedCountryCode = ""
    var countryClaimStatus = ""
    var locationText = ""
    var observedAsn: UInt32 = 0
    var hasQuality = false
    var qualityText = ""
    var bandwidthText = ""
    var latencyMs: UInt32 = 0
    var jitterMs: UInt32 = 0
    var packetLossPpm: UInt32 = 0
    var downBps: UInt64 = 0
    var upBps: UInt64 = 0
    var updatedAtUnix: UInt64 = 0
    var expiresAtUnix: UInt64 = 0

    init() {}
}

struct PaidRouteMarketFilterState: Decodable, Equatable {
    var query = ""
    var countryCode = ""
    var mintUrl = ""
    var requireIpv4 = false
    var requireIpv6 = false
    var sort = "quality"

    init() {}
}

struct PaidRouteMarketState: Decodable, Equatable {
    var supported = false
    var statusText = ""
    var manualProviderLink = ""
    var manualProviderStatusText = ""
    var storePath = ""
    var wallet = PaidRouteWalletState()
    var lastPaymentAction = PaidRoutePaymentActionState()
    var filter = PaidRouteMarketFilterState()
    var offers: [PaidRouteOfferState] = []
    var visibleOffers: [PaidRouteOfferState] = []
    var hiddenOfferCount: UInt64 = 0
    var countryOptions: [String] = []
    var channels: [PaidRouteChannelState] = []
    var sessions: [PaidRouteSessionState] = []

    init() {}
}

struct QrMatrix: Decodable {
    var width = 0
    var cells: [Bool] = []
    var error = ""
}

struct QrDecodeResult: Decodable {
    var value = ""
    var error = ""
}

private extension KeyedDecodingContainer {
    func string(_ key: Key, default defaultValue: String = "") -> String {
        (try? decodeIfPresent(String.self, forKey: key)) ?? defaultValue
    }

    func bool(_ key: Key, default defaultValue: Bool = false) -> Bool {
        (try? decodeIfPresent(Bool.self, forKey: key)) ?? defaultValue
    }

    func int(_ key: Key, default defaultValue: Int = 0) -> Int {
        (try? decodeIfPresent(Int.self, forKey: key)) ?? defaultValue
    }

    func uint64(_ key: Key, default defaultValue: UInt64 = 0) -> UInt64 {
        (try? decodeIfPresent(UInt64.self, forKey: key)) ?? defaultValue
    }

    func array<T: Decodable>(_ key: Key) -> [T] {
        (try? decodeIfPresent([T].self, forKey: key)) ?? []
    }

}
