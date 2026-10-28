import AppKit
import Darwin
import Foundation
import SwiftUI

extension AppManager {
    func clearActionStatus(after seconds: UInt64) {
        let statusToClear = actionStatus
        actionStatusClearTask?.cancel()
        actionStatusClearTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            await MainActor.run {
                guard self?.actionStatus == statusToClear else {
                    return
                }
                self?.actionStatus = ""
            }
        }
    }

    func maybePromptServiceUpdate(_ nextState: NativeAppState) {
        guard Self.serviceUpdateRecommended(in: nextState), !actionInFlight else {
            return
        }
        if actionStatus.isEmpty {
            actionStatus = "Background service needs update"
        }
    }

    static func serviceUpdateRecommended(in state: NativeAppState) -> Bool {
        state.serviceInstalled
            && !state.expectedServiceBinaryVersion.isEmpty
            && state.serviceBinaryVersion != state.expectedServiceBinaryVersion
    }

    static func daemonStarting(in state: NativeAppState) -> Bool {
        state.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && state.serviceRunning
            && state.vpnStatus.trimmingCharacters(in: .whitespacesAndNewlines) == "Background service starting"
    }

    static func fixtureModeRequested() -> Bool {
        let arguments = Set(CommandLine.arguments)
        if arguments.contains("--nvpn-fixture-mode") || arguments.contains("--nvpn-screenshot-fixture") {
            return true
        }
        let raw = ProcessInfo.processInfo.environment["NVPN_MACOS_FIXTURE_MODE"] ?? ""
        return ["1", "true", "yes", "on"].contains(raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }

    static func screenshotFixtureState() -> NativeAppState {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "4.0.31"
        let selfNpub = "npub12mh8r6uetvj9fptwua9gtng0ycz8uvzn0vmxsaddk7vfegeu29ts3qngt3"
        let macbookNpub = "npub1q0n4g9trrsyqezfgrsg6txtedmhgv0h5apur2a4yxgq4z0kgejmsjeclxl"
        let iphoneNpub = "npub1tmhvkh3ktx7dw06fxntuzmvc9r20wxnrapzd056240s42jtpyzps645uyh"
        let androidNpub = "npub1h988xqzvhu98t0n22ys7etjcg7ca33s78kda4mu5pfathz9xklmqxx6rg0"
        let ubuntuNpub = "npub1dxlnwd78xjhec3hlzc8qwjuc98w47hv89khggu8yk0ynpkw4czxsuccs3u"
        let joinNpub = "npub1xnvumr6snuvl7tcwll3kz9wny4fzjh9uwhmu4d6hc2hwuxrk6vqq8kukg4"
        let selfHex = "56ee71eb995b2454856ee74a85cd0f26047e30537b366875adb7989ca33c5157"
        let macbookHex = "03e75415631c080c89281c11a599796eee863ef4e8783576a43201513ec8ccb7"
        let iphoneHex = "5eeecb5e3659bcd73f4934d7c16d9828d4f71a63e844d7d34aabe15549612083"
        let androidHex = "b94e73004cbf0a75be6a5121ecae5847b1d8c61e3d9bdaef940a7abb88a6b7f6"
        let ubuntuHex = "69bf3737c734af9c46ff160e074b9829dd5f5d872dae8470e4b3c930d9d5c08d"
        let joinHex = "34d9cd8f509f19ff2f0effe36115d32552295cbc75f7cab757c2aeee1876d300"
        let fixtureNow = UInt64(Date().timeIntervalSince1970)
        let automaticExit = CommandLine.arguments.contains("--nvpn-screenshot-paid-automatic")
        let networkId = "demo-mesh"

        let local = NativeParticipantState(
            npub: selfNpub,
            pubkeyHex: selfHex,
            alias: "mini",
            magicDnsAlias: "mini",
            magicDnsName: "mini.nvpn",
            tunnelIp: "10.44.195.20",
            isAdmin: true,
            rosterAccepted: true,
            reachable: true,
            txBytes: 842_112,
            rxBytes: 1_302_804,
            advertisedRoutes: [],
            offersExitNode: false,
            fipsEndpointNpub: selfNpub,
            fipsEndpointHints: [],
            fipsTransportAddr: "192.0.2.57:51820",
            fipsTransportType: "udp",
            fipsSrttMs: 0,
            fipsSrttAgeMs: 0,
            fipsPacketsSent: 0,
            fipsPacketsRecv: 0,
            fipsBytesSent: 0,
            fipsBytesRecv: 0,
            fipsDirectProbePending: false,
            fipsDirectProbeAfterMs: 0,
            fipsDirectProbeRetryCount: 0,
            fipsDirectProbeAutoReconnect: false,
            fipsDirectProbeExpiresAtMs: 0,
            state: "local",
            meshState: "local",
            statusText: "local",
            lastFipsControlSeenText: "this device",
            lastFipsDataSeenText: "this device",
            lastSeenText: "self"
        )
        let macbook = NativeParticipantState(
            npub: macbookNpub,
            pubkeyHex: macbookHex,
            alias: "macbook",
            magicDnsAlias: "macbook",
            magicDnsName: "macbook.nvpn",
            tunnelIp: "10.44.178.166",
            isAdmin: false,
            rosterAccepted: true,
            reachable: true,
            txBytes: 290_144,
            rxBytes: 211_776,
            advertisedRoutes: [],
            offersExitNode: false,
            fipsEndpointNpub: macbookNpub,
            fipsEndpointHints: [],
            fipsTransportAddr: "",
            fipsTransportType: "mesh",
            fipsSrttMs: 38,
            fipsSrttAgeMs: 1_200,
            fipsPacketsSent: 4_284,
            fipsPacketsRecv: 4_103,
            fipsBytesSent: 628_104,
            fipsBytesRecv: 602_920,
            fipsDirectProbePending: false,
            fipsDirectProbeAfterMs: 0,
            fipsDirectProbeRetryCount: 0,
            fipsDirectProbeAutoReconnect: false,
            fipsDirectProbeExpiresAtMs: 0,
            state: "online",
            meshState: "via mesh",
            statusText: "via mesh, 38 ms",
            lastFipsControlSeenText: "seen now",
            lastFipsDataSeenText: "seen now",
            lastSeenText: "now"
        )
        let iphone = NativeParticipantState(
            npub: iphoneNpub,
            pubkeyHex: iphoneHex,
            alias: "iphone",
            magicDnsAlias: "iphone",
            magicDnsName: "iphone.nvpn",
            tunnelIp: "10.44.181.12",
            isAdmin: false,
            rosterAccepted: true,
            reachable: true,
            txBytes: 118_272,
            rxBytes: 91_440,
            advertisedRoutes: [],
            offersExitNode: false,
            fipsEndpointNpub: iphoneNpub,
            fipsEndpointHints: [],
            fipsTransportAddr: "192.0.2.74:52283",
            fipsTransportType: "udp",
            fipsSrttMs: 9,
            fipsSrttAgeMs: 900,
            fipsPacketsSent: 2_016,
            fipsPacketsRecv: 1_988,
            fipsBytesSent: 244_992,
            fipsBytesRecv: 239_872,
            fipsDirectProbePending: false,
            fipsDirectProbeAfterMs: 0,
            fipsDirectProbeRetryCount: 0,
            fipsDirectProbeAutoReconnect: false,
            fipsDirectProbeExpiresAtMs: 0,
            state: "online",
            meshState: "direct",
            statusText: "direct, 9 ms",
            lastFipsControlSeenText: "seen 1s ago",
            lastFipsDataSeenText: "seen 1s ago",
            lastSeenText: "1s ago"
        )
        let android = NativeParticipantState(
            npub: androidNpub,
            pubkeyHex: androidHex,
            alias: "android",
            magicDnsAlias: "android",
            magicDnsName: "android.nvpn",
            tunnelIp: "10.44.191.30",
            isAdmin: false,
            rosterAccepted: true,
            reachable: true,
            txBytes: 76_112,
            rxBytes: 64_928,
            advertisedRoutes: [],
            offersExitNode: false,
            fipsEndpointNpub: androidNpub,
            fipsEndpointHints: [],
            fipsTransportAddr: "192.0.2.92:47120",
            fipsTransportType: "udp",
            fipsSrttMs: 18,
            fipsSrttAgeMs: 1_100,
            fipsPacketsSent: 1_104,
            fipsPacketsRecv: 1_079,
            fipsBytesSent: 130_288,
            fipsBytesRecv: 127_416,
            fipsDirectProbePending: false,
            fipsDirectProbeAfterMs: 0,
            fipsDirectProbeRetryCount: 0,
            fipsDirectProbeAutoReconnect: false,
            fipsDirectProbeExpiresAtMs: 0,
            state: "online",
            meshState: "direct",
            statusText: "direct, 18 ms",
            lastFipsControlSeenText: "seen 2s ago",
            lastFipsDataSeenText: "seen 2s ago",
            lastSeenText: "2s ago"
        )
        let ubuntu = NativeParticipantState(
            npub: ubuntuNpub,
            pubkeyHex: ubuntuHex,
            alias: "ubuntu",
            magicDnsAlias: "ubuntu",
            magicDnsName: "ubuntu.nvpn",
            tunnelIp: "10.44.202.44",
            isAdmin: false,
            rosterAccepted: true,
            reachable: true,
            txBytes: 5_820_192,
            rxBytes: 4_911_240,
            advertisedRoutes: ["10.88.0.0/16"],
            offersExitNode: true,
            fipsEndpointNpub: ubuntuNpub,
            fipsEndpointHints: [],
            fipsTransportAddr: "203.0.113.44:51820",
            fipsTransportType: "udp",
            fipsSrttMs: 22,
            fipsSrttAgeMs: 1_400,
            fipsPacketsSent: 18_244,
            fipsPacketsRecv: 18_031,
            fipsBytesSent: 8_100_904,
            fipsBytesRecv: 7_900_512,
            fipsDirectProbePending: false,
            fipsDirectProbeAfterMs: 0,
            fipsDirectProbeRetryCount: 0,
            fipsDirectProbeAutoReconnect: false,
            fipsDirectProbeExpiresAtMs: 0,
            state: "online",
            meshState: "direct",
            statusText: "direct, 22 ms",
            lastFipsControlSeenText: "seen 3s ago",
            lastFipsDataSeenText: "seen 3s ago",
            lastSeenText: "3s ago"
        )
        let joinRequest = NativeInboundJoinRequestState(
            requesterNpub: joinNpub,
            requesterPubkeyHex: joinHex,
            requesterNodeName: "ipad",
            requestedAtText: "2m ago"
        )
        let network = NativeNetworkState(
            id: "demo",
            name: "Home Mesh",
            enabled: true,
            networkId: networkId,
            localIsAdmin: true,
            joinRequestsEnabled: true,
            joinRequestAdminNpub: "",
            adminNpubs: [selfNpub],
            outboundJoinRequest: nil,
            joinRequestQrCodeOrLink: "",
            inboundJoinRequests: [joinRequest],
            onlineCount: 5,
            expectedCount: 5,
            admins: [selfNpub],
            participants: [local, macbook, iphone, android, ubuntu]
        )
        let sellerScreenshot = CommandLine.arguments.contains("--nvpn-screenshot-paid-seller")

        return NativeAppState(
            rev: 1,
            platform: "macos",
            mobile: false,
            vpnControlSupported: true,
            cliInstallSupported: true,
            startupSettingsSupported: true,
            trayBehaviorSupported: true,
            runtimeStatusDetail: "Screenshot fixture",
            appVersion: version,
            configPath: "/Users/demo/Library/Application Support/nvpn/config.toml",
            error: "",
            cliInstalled: true,
            serviceSupported: true,
            serviceEnablementSupported: true,
            serviceInstalled: true,
            serviceDisabled: false,
            serviceRunning: true,
            serviceStatusDetail: "Background service running (nvpn), pid 4242",
            daemonRunning: true,
            vpnEnabled: true,
            vpnActive: true,
            vpnStatus: "Connected",
            daemonBinaryVersion: version,
            serviceBinaryVersion: version,
            expectedServiceBinaryVersion: version,
            ownNpub: selfNpub,
            ownPubkeyHex: selfHex,
            nodeId: "mini",
            nodeName: "mini",
            selfMagicDnsName: "mini.nvpn",
            endpoint: "203.0.113.8:51820",
            tunnelIp: "10.44.195.20",
            listenPort: 51820,
            relays: [
                NativeRelayState(url: "wss://relay.damus.io", status: "connected", enabled: true),
                NativeRelayState(url: "wss://relay.nostr.band", status: "unknown", enabled: true)
            ],
            nostrPubsubMode: "relay",
            nostrPubsubFanout: 4,
            nostrPubsubMaxHops: 2,
            nostrPubsubMaxEventBytes: 65_536,
            networkId: networkId,
            joinRequestQrCodeOrLink: "nvpn://join-request/demo",
            internetSource: automaticExit ? "paid_automatic" : sellerScreenshot ? "direct" : "paid_manual",
            exitNode: sellerScreenshot ? "" : "npub1paidexitfinlanddemo",
            exitNodeLeakProtection: true,
            exitNodeActive: !sellerScreenshot,
            exitNodeBlocked: false,
            exitNodeNeedsAttention: false,
            exitNodeStatusText: automaticExit
                ? "Automatic paid exit · FI · ≈ $0.02/GB · 198.51.100.42 · Active"
                : sellerScreenshot ? "" : "Using paid internet: FI",
            exitDnsMode: "automatic",
            exitDnsDohProvider: "cloudflare",
            exitDnsCustomDohUrl: "",
            exitDnsCustomDohBootstrapIps: "",
            exitDnsThroughExitServers: "",
            advertiseExitNode: false,
            advertisedRoutes: [],
            effectiveAdvertisedRoutes: [],
            wireguardExitEnabled: false,
            wireguardExitConfigured: true,
            wireguardExitInterface: "utun-demo",
            wireguardExitAddress: "10.8.0.2/32",
            wireguardExitPrivateKey: "demo-private-key",
            wireguardExitPeerPublicKey: "demo-peer-key",
            wireguardExitPeerPresharedKey: "",
            wireguardExitEndpoint: "203.0.113.20:51820",
            wireguardExitAllowedIps: "0.0.0.0/0",
            wireguardExitDns: "1.1.1.1",
            wireguardExitMtu: 1280,
            wireguardExitPersistentKeepaliveSecs: 25,
            wireguardExitConfig: "",
            walletFiatEnabled: true,
            walletFiatCurrency: "USD",
            paidExitSeller: NativePaidExitSellerState(
                supported: true,
                enabled: sellerScreenshot,
                ready: sellerScreenshot,
                statusText: sellerScreenshot ? "Selling internet is ready" : "Selling internet is off",
                providerLink: "nvpn://paid-exit/npub1paidexitfinlanddemo?maxMsatPerGb=25000&mint=https%3A%2F%2Fmint.minibits.cash%2FBitcoin",
                upstream: "host_default",
                privateVpnAccess: "denied",
                internetText: "My internet",
                publicIpText: "203.0.113.8",
                priceText: "≈ $0.02/GB",
                priceMsatPerGb: 25_000,
                acceptedMints: ["https://mint.minibits.cash/Bitcoin"],
                maxChannelCapacitySat: 250,
                channelExpirySecs: 86_400,
                channelExpiryText: "1 day",
                settlementText: "Channels end after 1 day or when you manually collect",
                freeProbeUnits: 1_048_576,
                freeProbeText: "1 MB",
                graceUnits: 262_144,
                graceText: "256 KB",
                countryCode: "FI",
                networkClass: "residential",
                asn: 12345,
                ipv4: true,
                ipv6: false,
                channelCreditMsat: 35_000,
                channelCreditText: "≈ $0.03",
                channelCreditTitleText: "Pending buyer credit",
                channelCreditHelpText: "Collect to move it into wallet",
                currentConnectionCount: 1,
                pastConnectionCount: 3,
                totalBillableBytes: 48_000_000,
                totalTrafficText: "45.8 MB used",
                totalPaidMsat: 92_000,
                totalPaidText: "≈ $0.07 paid",
                totalDueMsat: 88_000,
                totalDueText: "≈ $0.07 due",
                totalUnpaidMsat: 0,
                totalUnpaidText: "",
                channels: [
                    NativePaidRouteChannelState(
                        channelId: "seller-channel-demo",
                        offerId: "internet-exit",
                        role: "seller",
                        status: "active",
                        mintUrl: "https://mint.minibits.cash/Bitcoin",
                        counterpartyNpub: "npub1buyerstreamdemo",
                        capacitySat: 250,
                        capacityText: "≈ $0.20",
                        paidMsat: 35_000,
                        paidText: "≈ $0.03 paid",
                        updatedAtUnix: fixtureNow - 110,
                        expiresAtUnix: fixtureNow + 900,
                        error: ""
                    )
                ],
                sessions: [
                    NativePaidRouteSessionState(
                        sellerNpub: "",
                        personalRating: 0,
                        canRate: false,
                        sessionId: "seller-session-demo",
                        leaseId: "seller-lease-demo",
                        channelId: "seller-channel-demo",
                        statusText: "Routing paid traffic",
                        lifecycleStatus: "active",
                        accessState: "paid",
                        titleText: "Buyer online",
                        detailText: "Paid, 11.4 MB used, ≈ $0.02 due",
                        settlementText: "Ends in 15 min or when you manually collect",
                        collectActionText: "End & Collect",
                        collectActionHelpText: "Stop routing and move paid channel funds to wallet",
                        paymentChannelReady: true,
                        allowRouting: true,
                        deliveredUnits: 12_000_000,
                        usageText: "11.4 MB used",
                        amountDueMsat: 30_000,
                        amountDueText: "≈ $0.02 due",
                        paidMsat: 35_000,
                        paidText: "≈ $0.03 paid",
                        channelBalanceMsat: 0,
                        channelBalanceText: "",
                        unpaidMsat: 0,
                        unpaidText: "",
                        activeMillis: 0,
                        bytes: 12_000_000,
                        packets: 8_120,
                        realizedExitIp: "203.0.113.8",
                        claimedCountryCode: "FI",
                        observedCountryCode: "FI",
                        countryClaimStatus: "match",
                        locationText: "FI",
                        observedAsn: 12345,
                        hasQuality: true,
                        qualityText: "42 ms · 7 ms jitter · 0.05% loss",
                        bandwidthText: "25 Mbps down · 5 Mbps up",
                        latencyMs: 42,
                        jitterMs: 7,
                        packetLossPpm: 500,
                        downBps: 25_000_000,
                        upBps: 5_000_000,
                        updatedAtUnix: fixtureNow - 110,
                        expiresAtUnix: fixtureNow + 900
                    )
                ]
            ),
            paidRouteMarket: NativePaidRouteMarketState(
                supported: true,
                statusText: "2 internet sellers found",
                manualProviderLink: "",
                manualProviderStatusText: "",
                storePath: "/Users/demo/Library/Application Support/nvpn/paid-routes.json",
                wallet: NativePaidRouteWalletState(
                    defaultMint: "https://mint.coinos.io",
                    balanceKnown: true,
                    totalBalanceMsat: 123_000,
                    totalBalanceText: "≈ $0.10",
                    channelBalanceMsat: 225_000,
                    channelBalanceText: "≈ $0.18 in channels",
                    navigationBalanceText: "≈ $0.10",
                    fiatCurrency: "USD",
                    fiatBalanceText: "≈ $0.10",
                    exchangeRateText: "1 BTC = 80000.00 USD",
                    exchangeRateStatus: "Coinbase · Kraken",
                    exchangeRateSources: "coinbase,kraken",
                    exchangeRateStale: false,
                    exchangeRateUpdatedAtUnix: fixtureNow - 120,
                    mints: [
                        NativePaidRouteWalletMintState(
                            url: "https://mint.coinos.io",
                            label: "Coinos",
                            isDefault: true,
                            balanceKnown: true,
                            balanceMsat: 3_000,
                            balanceText: "≈ $0.0024",
                            lastCheckedUnix: fixtureNow - 120
                        ),
                        NativePaidRouteWalletMintState(
                            url: "https://mint.minibits.cash/Bitcoin",
                            label: "Minibits",
                            isDefault: false,
                            balanceKnown: true,
                            balanceMsat: 120_000,
                            balanceText: "≈ $0.10",
                            lastCheckedUnix: fixtureNow - 120
                        )
                    ],
                    history: NativePaidRouteWalletHistoryState(
                        loaded: true,
                        error: "",
                        entries: [
                            NativePaidRouteWalletActivityState(
                                id: "history-pending", kind: "top_up", status: "pending",
                                mintUrl: "https://mint.coinos.io", amountSat: 1000, feeSat: 0,
                                createdAtUnix: fixtureNow - 60
                            ),
                            NativePaidRouteWalletActivityState(
                                id: "history-payment", kind: "lightning_payment", status: "complete",
                                mintUrl: "https://mint.minibits.cash/Bitcoin", amountSat: 10, feeSat: 1,
                                createdAtUnix: fixtureNow - 3600
                            ),
                            NativePaidRouteWalletActivityState(
                                id: "history-expired", kind: "top_up", status: "expired",
                                mintUrl: "https://mint.minibits.cash/Bitcoin", amountSat: 100, feeSat: 0,
                                createdAtUnix: fixtureNow - 86400
                            )
                        ]
                    ),
                    lastAction: NativePaidRouteWalletActionState(
                        kind: "topup",
                        statusText: "Invoice ready",
                        mintUrl: "https://mint.minibits.cash/Bitcoin",
                        amountSat: 1_000,
                        amountText: "≈ $0.80",
                        feeSat: 0,
                        feeText: "",
                        quoteId: "quote-demo",
                        paymentRequest: "lnbc1000n1pdemoexamplepaidroutewalletinvoice",
                        token: "",
                        operationId: "",
                        expiresAtUnix: UInt64(Date().timeIntervalSince1970) + 3_600,
                        preimage: "",
                        tokenState: "",
                        tokenRedeemable: false,
                        tokenMemo: ""
                    )
                ),
                lastPaymentAction: NativePaidRoutePaymentActionState(
                    kind: "",
                    statusText: "",
                    payloadType: "",
                    sessionId: "",
                    leaseId: "",
                    channelId: "",
                    buyerNpub: "",
                    sellerNpub: "",
                    envelopeJson: "",
                    paidMsat: 0,
                    paidText: "≈ $0.00 paid",
                    deliveredUnits: 0,
                    deliveredUsageText: "0 units",
                    amountDueMsat: 0,
                    amountDueText: "≈ $0.00 due",
                    unpaidMsat: 0,
                    unpaidText: "",
                    allowRouting: false
                ),
                filter: NativePaidRouteMarketFilterState(
                    query: "",
                    countryCode: "",
                    mintUrl: "",
                    requireIpv4: false,
                    requireIpv6: false,
                    sort: "quality"
                ),
                offers: [
                    NativePaidRouteOfferState(
                        displayName: "Curious Otter",
                        key: "seller-fi:internet-exit",
                        offerId: "internet-exit",
                        sellerNpub: "npub1paidexitfinlanddemo",
                        statusText: "Selected · FI · Residential · 42 ms · seen 2m ago",
                        priceText: "≈ $0.02/GB",
                        priceMsatPerGb: 25_000,
                        acceptedMints: ["https://mint.minibits.cash/Bitcoin"],
                        maxChannelCapacitySat: 250,
                        channelExpirySecs: 900,
                        freeProbeUnits: 1_048_576,
                        freeProbeText: "1 MB",
                        graceUnits: 262_144,
                        graceText: "256 KB",
                        countryCode: "FI",
                        networkClass: "residential",
                        asn: 14593,
                        ipv4: true,
                        ipv6: false,
                        personalRating: 0,
                        canRate: true,
                        hasRating: true,
                        ratingScore: 72,
                        ratingUpdatedAtUnix: 1_780_649_900,
                        hasQuality: true,
                        qualityText: "42 ms · 7 ms jitter · 0.05% loss",
                        bandwidthText: "25 Mbps down · 5 Mbps up",
                        latencyMs: 42,
                        jitterMs: 7,
                        packetLossPpm: 500,
                        downBps: 25_000_000,
                        upBps: 5_000_000,
                        uptimeSecs: 3_600,
                        firstSeenUnix: 1_780_649_000,
                        lastSeenUnix: fixtureNow - 120,
                        relayUrls: ["wss://relay.damus.io"]
                    ),
                    NativePaidRouteOfferState(
                        displayName: "Sunny Falcon",
                        key: "seller-de:internet-exit",
                        offerId: "internet-exit",
                        sellerNpub: "npub1paidexitgermanydemo",
                        statusText: "DE · Datacenter · 18 ms · seen 5m ago",
                        priceText: "≈ $0.0064/GB",
                        priceMsatPerGb: 8_000,
                        acceptedMints: ["https://mint.minibits.cash/Bitcoin"],
                        maxChannelCapacitySat: 500,
                        channelExpirySecs: 900,
                        freeProbeUnits: 1_048_576,
                        freeProbeText: "1 MB",
                        graceUnits: 262_144,
                        graceText: "256 KB",
                        countryCode: "DE",
                        networkClass: "datacenter",
                        asn: 12_345,
                        ipv4: true,
                        ipv6: true,
                        personalRating: 0,
                        canRate: false,
                        hasRating: false,
                        ratingScore: 0,
                        ratingUpdatedAtUnix: 0,
                        hasQuality: true,
                        qualityText: "18 ms · 3 ms jitter · 0.01% loss",
                        bandwidthText: "90 Mbps down · 20 Mbps up",
                        latencyMs: 18,
                        jitterMs: 3,
                        packetLossPpm: 100,
                        downBps: 90_000_000,
                        upBps: 20_000_000,
                        uptimeSecs: 86_400,
                        firstSeenUnix: 1_780_648_000,
                        lastSeenUnix: 1_780_649_800,
                        relayUrls: ["wss://relay.nostr.band"]
                    )
                ],
                visibleOffers: [],
                hiddenOfferCount: 0,
                countryOptions: ["DE", "FI"],
                channels: [
                    NativePaidRouteChannelState(
                        channelId: "channel-fi-1",
                        offerId: "internet-exit",
                        role: "buyer",
                        status: "active",
                        mintUrl: "https://mint.minibits.cash/Bitcoin",
                        counterpartyNpub: "npub1paidexitfinlanddemo",
                        capacitySat: 250,
                        capacityText: "≈ $0.20",
                        paidMsat: 25_000,
                        paidText: "≈ $0.02 paid",
                        updatedAtUnix: fixtureNow - 120,
                        expiresAtUnix: fixtureNow + 900,
                        error: ""
                    )
                ],
                sessions: [
                    NativePaidRouteSessionState(
                        sellerNpub: "npub1paidexitfinlanddemo",
                        personalRating: 0,
                        canRate: true,
                        sessionId: "session-fi-1",
                        leaseId: "lease-fi-1",
                        channelId: "channel-fi-1",
                        statusText: "Connected",
                        lifecycleStatus: "active",
                        accessState: "paid",
                        titleText: "Connected",
                        detailText: "Paid, 1 GB used",
                        settlementText: "Channel ends in 15 min",
                        collectActionText: "",
                        collectActionHelpText: "",
                        paymentChannelReady: true,
                        allowRouting: true,
                        deliveredUnits: 1_000_000_000,
                        usageText: "1 GB used",
                        amountDueMsat: 25_000,
                        amountDueText: "≈ $0.02 due",
                        paidMsat: 25_000,
                        paidText: "≈ $0.02 paid",
                        channelBalanceMsat: 225_000,
                        channelBalanceText: "≈ $0.18 in channel",
                        unpaidMsat: 0,
                        unpaidText: "",
                        activeMillis: 31_000,
                        bytes: 1_000_000_000,
                        packets: 1_920,
                        realizedExitIp: "198.51.100.42",
                        claimedCountryCode: "FI",
                        observedCountryCode: "FI",
                        countryClaimStatus: "match",
                        locationText: "198.51.100.42 - FI matches claim",
                        observedAsn: 14593,
                        hasQuality: true,
                        qualityText: "42 ms · 7 ms jitter · 0.05% loss",
                        bandwidthText: "25 Mbps down · 5 Mbps up",
                        latencyMs: 42,
                        jitterMs: 7,
                        packetLossPpm: 500,
                        downBps: 25_000_000,
                        upBps: 5_000_000,
                        updatedAtUnix: fixtureNow - 120,
                        expiresAtUnix: fixtureNow + 900
                    )
                ]
            ),
            fipsHostTunnelEnabled: false,
            connectToNonRosterFipsPeers: true,
            fipsNostrDiscoveryEnabled: true,
            fipsWebrtcEnabled: false,
            fipsBootstrapEnabled: false,
            fipsBootstrapPeers: [:],
            fipsBootstrapPeerDefaults: [:],
            fipsHostInboundTcpPorts: "",
            magicDnsSuffix: "nvpn",
            magicDnsStatus: "Serving .nvpn names",
            autoconnect: true,
            launchOnStartup: true,
            closeToTrayOnClose: true,
            connectedPeerCount: 4,
            expectedPeerCount: 4,
            fipsConnectedPeerCount: 4,
            fipsRosterPeerCount: 4,
            nonFipsRosterPeerCount: 0,
            meshReady: true,
            health: [],
            network: NativeNetworkSummary(
                defaultInterface: "en0",
                primaryIpv4: "192.0.2.57",
                primaryIpv6: "",
                gatewayIpv4: "192.0.2.1",
                gatewayIpv6: "",
                changedAt: 0,
                captivePortal: "false"
            ),
            portMapping: NativePortMappingStatus(
                upnp: NativeProbeStatus(state: "ok", detail: "mapped"),
                natPmp: NativeProbeStatus(state: "unknown", detail: ""),
                pcp: NativeProbeStatus(state: "unknown", detail: ""),
                activeProtocol: "upnp",
                externalEndpoint: "203.0.113.8:51820",
                gateway: "192.0.2.1",
                goodUntil: 0
            ),
            networks: [network]
        )
    }
}

// The generated bindings only expose memberwise inits, so the empty
// placeholder state that renders while the core constructs off-thread is
// spelled out here. Any binding field change fails compilation on these inits.
private extension NativeProbeStatus {
    init() {
        self.init(state: "", detail: "")
    }
}

private extension NativeNetworkSummary {
    init() {
        self.init(
            defaultInterface: "",
            primaryIpv4: "",
            primaryIpv6: "",
            gatewayIpv4: "",
            gatewayIpv6: "",
            changedAt: 0,
            captivePortal: ""
        )
    }
}

private extension NativePortMappingStatus {
    init() {
        self.init(
            upnp: NativeProbeStatus(),
            natPmp: NativeProbeStatus(),
            pcp: NativeProbeStatus(),
            activeProtocol: "",
            externalEndpoint: "",
            gateway: "",
            goodUntil: 0
        )
    }
}

private extension NativePaidExitSellerState {
    init() {
        self.init(
            supported: false,
            enabled: false,
            ready: false,
            statusText: "",
            providerLink: "",
            upstream: "",
            privateVpnAccess: "",
            internetText: "",
            publicIpText: "",
            priceText: "",
            priceMsatPerGb: 0,
            acceptedMints: [],
            maxChannelCapacitySat: 0,
            channelExpirySecs: 0,
            channelExpiryText: "",
            settlementText: "",
            freeProbeUnits: 0,
            freeProbeText: "",
            graceUnits: 0,
            graceText: "",
            countryCode: "",
            networkClass: "",
            asn: 0,
            ipv4: false,
            ipv6: false,
            channelCreditMsat: 0,
            channelCreditText: "",
            channelCreditTitleText: "",
            channelCreditHelpText: "",
            currentConnectionCount: 0,
            pastConnectionCount: 0,
            totalBillableBytes: 0,
            totalTrafficText: "",
            totalPaidMsat: 0,
            totalPaidText: "",
            totalDueMsat: 0,
            totalDueText: "",
            totalUnpaidMsat: 0,
            totalUnpaidText: "",
            channels: [],
            sessions: []
        )
    }
}

private extension NativePaidRouteMarketFilterState {
    init() {
        self.init(query: "", countryCode: "", mintUrl: "", requireIpv4: false, requireIpv6: false, sort: "")
    }
}

private extension NativePaidRouteWalletActionState {
    init() {
        self.init(
            kind: "",
            statusText: "",
            mintUrl: "",
            amountSat: 0,
            amountText: "",
            feeSat: 0,
            feeText: "",
            quoteId: "",
            paymentRequest: "",
            token: "",
            operationId: "",
            expiresAtUnix: 0,
            preimage: "",
            tokenState: "",
            tokenRedeemable: false,
            tokenMemo: ""
        )
    }
}

private extension NativePaidRouteWalletHistoryState {
    init() {
        self.init(loaded: false, error: "", entries: [])
    }
}

private extension NativePaidRouteWalletState {
    init() {
        self.init(
            defaultMint: "",
            balanceKnown: false,
            totalBalanceMsat: 0,
            totalBalanceText: "",
            channelBalanceMsat: 0,
            channelBalanceText: "",
            navigationBalanceText: "",
            fiatCurrency: "",
            fiatBalanceText: "",
            exchangeRateText: "",
            exchangeRateStatus: "",
            exchangeRateSources: "",
            exchangeRateStale: false,
            exchangeRateUpdatedAtUnix: 0,
            mints: [],
            history: NativePaidRouteWalletHistoryState(),
            lastAction: NativePaidRouteWalletActionState()
        )
    }
}

private extension NativePaidRoutePaymentActionState {
    init() {
        self.init(
            kind: "",
            statusText: "",
            payloadType: "",
            sessionId: "",
            leaseId: "",
            channelId: "",
            buyerNpub: "",
            sellerNpub: "",
            envelopeJson: "",
            paidMsat: 0,
            paidText: "",
            deliveredUnits: 0,
            deliveredUsageText: "",
            amountDueMsat: 0,
            amountDueText: "",
            unpaidMsat: 0,
            unpaidText: "",
            allowRouting: false
        )
    }
}

private extension NativePaidRouteMarketState {
    init() {
        self.init(
            supported: false,
            statusText: "",
            manualProviderLink: "",
            manualProviderStatusText: "",
            storePath: "",
            wallet: NativePaidRouteWalletState(),
            lastPaymentAction: NativePaidRoutePaymentActionState(),
            filter: NativePaidRouteMarketFilterState(),
            offers: [],
            visibleOffers: [],
            hiddenOfferCount: 0,
            countryOptions: [],
            channels: [],
            sessions: []
        )
    }
}

private extension NativeAppState {
    init() {
        self.init(
            rev: 0,
            platform: "",
            mobile: false,
            vpnControlSupported: false,
            cliInstallSupported: false,
            startupSettingsSupported: false,
            trayBehaviorSupported: false,
            runtimeStatusDetail: "",
            appVersion: "",
            configPath: "",
            error: "",
            cliInstalled: false,
            serviceSupported: false,
            serviceEnablementSupported: false,
            serviceInstalled: false,
            serviceDisabled: false,
            serviceRunning: false,
            serviceStatusDetail: "",
            daemonRunning: false,
            vpnEnabled: false,
            vpnActive: false,
            vpnStatus: "",
            daemonBinaryVersion: "",
            serviceBinaryVersion: "",
            expectedServiceBinaryVersion: "",
            ownNpub: "",
            ownPubkeyHex: "",
            nodeId: "",
            nodeName: "",
            selfMagicDnsName: "",
            endpoint: "",
            tunnelIp: "",
            listenPort: 0,
            relays: [],
            nostrPubsubMode: "",
            nostrPubsubFanout: 0,
            nostrPubsubMaxHops: 0,
            nostrPubsubMaxEventBytes: 0,
            networkId: "",
            joinRequestQrCodeOrLink: "",
            internetSource: "",
            exitNode: "",
            exitNodeLeakProtection: false,
            exitNodeActive: false,
            exitNodeBlocked: false,
            exitNodeNeedsAttention: false,
            exitNodeStatusText: "",
            exitDnsMode: "",
            exitDnsDohProvider: "",
            exitDnsCustomDohUrl: "",
            exitDnsCustomDohBootstrapIps: "",
            exitDnsThroughExitServers: "",
            advertiseExitNode: false,
            advertisedRoutes: [],
            effectiveAdvertisedRoutes: [],
            wireguardExitEnabled: false,
            wireguardExitConfigured: false,
            wireguardExitInterface: "",
            wireguardExitAddress: "",
            wireguardExitPrivateKey: "",
            wireguardExitPeerPublicKey: "",
            wireguardExitPeerPresharedKey: "",
            wireguardExitEndpoint: "",
            wireguardExitAllowedIps: "",
            wireguardExitDns: "",
            wireguardExitMtu: 0,
            wireguardExitPersistentKeepaliveSecs: 0,
            wireguardExitConfig: "",
            walletFiatEnabled: false,
            walletFiatCurrency: "",
            paidExitSeller: NativePaidExitSellerState(),
            paidRouteMarket: NativePaidRouteMarketState(),
            fipsHostTunnelEnabled: false,
            connectToNonRosterFipsPeers: false,
            fipsNostrDiscoveryEnabled: false,
            fipsWebrtcEnabled: false,
            fipsBootstrapEnabled: false,
            fipsBootstrapPeers: [:],
            fipsBootstrapPeerDefaults: [:],
            fipsHostInboundTcpPorts: "",
            magicDnsSuffix: "",
            magicDnsStatus: "",
            autoconnect: false,
            launchOnStartup: false,
            closeToTrayOnClose: false,
            connectedPeerCount: 0,
            expectedPeerCount: 0,
            fipsConnectedPeerCount: 0,
            fipsRosterPeerCount: 0,
            nonFipsRosterPeerCount: 0,
            meshReady: false,
            health: [],
            network: NativeNetworkSummary(),
            portMapping: NativePortMappingStatus(),
            networks: []
        )
    }
}
