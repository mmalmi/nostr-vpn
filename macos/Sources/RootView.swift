import AppKit
import CoreImage
import SwiftUI

let searchVisibilityThreshold = 7

enum AddNetworkMode {
    case create
    case join
}
struct RootView: View {
    @ObservedObject var manager: AppManager

    @State var nodeName = ""
    @State var endpoint = ""
    @State var tunnelIp = ""
    @State var listenPort = ""
    @State var relayInput = ""
    @State var fipsHostInboundTcpPorts = ""
    @State var nostrPubsubMode = "relay"
    @State var nostrPubsubFanout = ""
    @State var nostrPubsubMaxHops = ""
    @State var nostrPubsubMaxEventBytes = ""
    @State var wireguardExitConfig = ""
    @State var exitDnsMode = "automatic"
    @State var exitDnsDohProvider = "cloudflare"
    @State var exitDnsCustomDohUrl = ""
    @State var exitDnsCustomDohBootstrapIps = ""
    @State var exitDnsThroughExitServers = ""
    @State var paidExitPriceMsatPerGb = ""
    @State var manualPaidExitProvider = ""
    @State var paidExitAcceptedMints = ""
    @State var paidExitMaxChannelCapacitySat = ""
    @State var paidExitChannelExpirySecs = ""
    @State var paidExitFreeProbeUnits = ""
    @State var paidExitGraceUnits = ""
    @State var paidExitCountryCode = ""
    @State var paidExitAsn = ""
    @State var paidRouteMintUrl = ""
    @State var paidRouteWalletFlow: PaidRouteWalletFlow?
    @State var paidRouteTopupAmount = "1000"
    @State var paidRouteReceiveToken = ""
    @State var showingWalletTokenScanner = false
    @State var pendingWalletToken = ""
    @State var showingWalletTokenReview = false
    @State var redeemingWalletToken = false
    @State var paidRouteSendAmount = "1000"
    @State var paidRouteWithdrawInvoice = ""
    @State var paidExitAdvancedTermsExpanded = RootView.initialPaidExitAdvancedTermsExpanded()
    @State var paidExitListingAdvancedExpanded = false
    @State var wireGuardUpstreamExpanded = RootView.initialWireGuardUpstreamExpanded()
    @State var paidRouteOfferCountryFilter = "all"
    @State var paidRouteOfferSort = "quality"
    @AppStorage("paidRouteHistoryClearedBeforeUnix") var paidRouteHistoryClearedBeforeUnix = 0.0
    @State var networkNameInput = ""
    @State var selectedDevicePubkeyHex: String?
    @State var networkNameDrafts: [String: String] = [:]
    @State var savedNetworksExpanded = false
    @State var pendingNetworkRemoval: NativeNetworkState?
    @State var pendingParticipantRemoval: PendingParticipantRemoval?
    @State var pendingJoinRequest: PendingJoinRequest?
    @State var diagnosticsExpanded = false
    @State var showingQrScanner = false
    @State var scanningJoinRequest = false
    @State var scannedQrCode: String?
    @State var selectedSidebarItem: SidebarItem? = RootView.initialSidebarItem()
    @State var shownNetworkId: String?
    @State var addNetworkPresented = false
    @State var addDevicePresented = false
    @State var addNetworkMode: AddNetworkMode?
    @State var joinRequestInput = ""
    @State var manualJoinExpanded = false
    @State var manualJoinAdminId = ""
    @State var manualJoinMeshId = ""
    @State var manualJoinDeviceId = ""
    @State var manualJoinDeviceName = ""
    @State var lastSyncedNodeName = ""
    @State var lastSyncedEndpoint = ""
    @State var lastSyncedTunnelIp = ""
    @State var lastSyncedListenPort: UInt32 = 0
    @State var lastSyncedFipsHostInboundTcpPorts = ""
    @State var lastSyncedNostrPubsubMode = ""
    @State var lastSyncedNostrPubsubFanout: UInt32 = 0
    @State var lastSyncedNostrPubsubMaxHops: UInt8 = 0
    @State var lastSyncedNostrPubsubMaxEventBytes: UInt32 = 0
    @State var lastSyncedWireguardExitConfig: String? = nil
    @State var lastSyncedExitDnsMode: String? = nil
    @State var lastSyncedExitDnsDohProvider: String? = nil
    @State var lastSyncedExitDnsCustomDohUrl: String? = nil
    @State var lastSyncedExitDnsCustomDohBootstrapIps: String? = nil
    @State var lastSyncedExitDnsThroughExitServers: String? = nil
    @State var lastSyncedManualPaidExitProvider: String? = nil
    @State var lastSyncedPaidExitSeller: NativePaidExitSellerState? = nil

    var state: NativeAppState {
        manager.state
    }

    var activeNetwork: NativeNetworkState? {
        manager.activeNetwork
    }

    static func initialSidebarItem() -> SidebarItem {
        let arguments = Set(CommandLine.arguments)
        if arguments.contains("--nvpn-screenshot-paid-seller") {
            return .sellExit
        }
        if arguments.contains("--nvpn-screenshot-paid-market") {
            return .publicExits
        }
        if arguments.contains("--nvpn-screenshot-paid-wallet") {
            return .wallet
        }
        if arguments.contains("--nvpn-screenshot-exit-nodes")
            || arguments.contains("--nvpn-screenshot-upstream") {
            return .internet
        }
        if arguments.contains("--nvpn-screenshot-settings") {
            return .settings
        }
        return .devices
    }

    static func initialWireGuardUpstreamExpanded() -> Bool {
        Set(CommandLine.arguments).contains("--nvpn-screenshot-upstream")
    }

    static func initialPaidExitAdvancedTermsExpanded() -> Bool {
        false
    }

    var shownNetwork: NativeNetworkState? {
        if let shownNetworkId,
           let network = state.networks.first(where: { $0.id == shownNetworkId }) {
            return network
        }
        return activeNetwork ?? state.networks.first
    }

    var paidRouteMarketAvailable: Bool {
        state.paidRouteMarket.supported
    }

    var paidExitSellerAvailable: Bool {
        state.paidExitSeller.supported
    }

    var visibleSidebarItem: SidebarItem {
        let item = selectedSidebarItem ?? .devices
        return sidebarItemVisible(item) ? item : .devices
    }

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            if manager.serviceUpdateRecommended {
                serviceUpdateStripe
            }
            if manager.updateAvailable {
                updateStripe
            }
            Divider()
            HStack(spacing: 0) {
                sidebar
                    .frame(width: 250)
                Divider()
                detailPane
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .ignoresSafeArea(.container, edges: .top)
        .onAppear {
            syncDrafts()
            normalizeSidebarSelection()
        }
        .onChange(of: state.rev) { _, _ in
            syncDrafts()
            normalizeSidebarSelection()
        }
        .onChange(of: shownNetwork?.enabled) { _, enabled in
            if addDevicePresented && enabled != true {
                addDevicePresented = false
            }
        }
        .onChange(of: addNetworkPresented) { _, presented in
            if !presented {
                addNetworkMode = nil
            }
        }
        .sheet(isPresented: $showingQrScanner, onDismiss: qrScannerDismissed) {
            QRCodeScannerSheet { code in
                scannedQrCode = code
                showingQrScanner = false
            }
        }
        .sheet(isPresented: $addNetworkPresented) {
            addNetworkSheetContent
        }
        .sheet(isPresented: $addDevicePresented) {
            if let network = shownNetwork, network.enabled {
                addDeviceSheetContent(network)
                    .alert("Add device?", isPresented: pendingJoinRequestPresented, presenting: pendingJoinRequest) { pending in
                        Button("Cancel", role: .cancel) {
                            pendingJoinRequest = nil
                        }
                        Button("Add") {
                            manager.importJoinRequest(pending.request)
                            joinRequestInput = ""
                            pendingJoinRequest = nil
                            addDevicePresented = false
                        }
                    } message: { pending in
                        Text("Add the device from this join request to \(pending.networkName)?")
                    }
            }
        }
        .alert("Action failed", isPresented: actionErrorPresented) {
            Button("OK") {
                manager.actionError = ""
            }
        } message: {
            Text(manager.actionError)
        }
    }

    var actionErrorPresented: Binding<Bool> {
        Binding(
            get: { !manager.actionError.isEmpty },
            set: { presented in
                if !presented {
                    manager.actionError = ""
                }
            }
        )
    }

    var pendingJoinRequestPresented: Binding<Bool> {
        Binding(
            get: { pendingJoinRequest != nil },
            set: { presented in
                if !presented {
                    pendingJoinRequest = nil
                }
            }
        )
    }

    func qrScannerDismissed() {
        let code = scannedQrCode
        let network = shownNetwork
        let shouldImport = scanningJoinRequest
        scannedQrCode = nil
        scanningJoinRequest = false

        guard shouldImport, let code, let network else {
            return
        }
        DispatchQueue.main.async {
            stageJoinRequest(code, network: network)
        }
    }

    var addNetworkSheetContent: some View {
        VStack(alignment: .leading, spacing: 0) {
            sheetTitleBar("Add Network", systemImage: "plus.circle") {
                addNetworkPresented = false
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    switch addNetworkMode {
                    case nil:
                        addNetworkChoiceSection
                    case .create:
                        addNetworkBackButton
                        createNetworkSection
                    case .join:
                        addNetworkBackButton
                        joinNetworkSection(activeNetwork)
                    }
                }
                .padding(18)
            }
        }
        .frame(width: 560, height: 620)
    }

    func addDeviceSheetContent(_ network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            sheetTitleBar("Link Device", systemImage: "person.badge.plus") {
                addDevicePresented = false
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    joinRequestInputSection(network)
                    manualAdminSection(network)
                }
                .padding(18)
            }
        }
        .frame(width: 560, height: 620)
    }

    func sheetTitleBar(_ title: String, systemImage: String, close: @escaping () -> Void) -> some View {
        HStack(spacing: 10) {
            Label(title, systemImage: systemImage)
                .font(.title3.weight(.semibold))
            Spacer()
            Button("Done", action: close)
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
    }

    var headerBar: some View {
        HStack(spacing: 18) {
            headerIdentity
            Spacer(minLength: 0)
            headerVpnControl
        }
        .padding(.leading, 104)
        .padding(.trailing, 18)
        .frame(height: 44)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    var serviceUpdateStripe: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.orange)
            Text(serviceUpdateStripeText)
                .font(.callout)
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: 12)
            Button {
                manager.installService()
            } label: {
                Text(manager.serviceSettling ? "Updating…" : "Update")
            }
            .controlSize(.small)
            .disabled(!state.serviceSupported || manager.actionInFlight || manager.serviceSettling)
        }
        .padding(.leading, 104)
        .padding(.trailing, 18)
        .padding(.vertical, 6)
        .background(Color(nsColor: .underPageBackgroundColor))
        .overlay(alignment: .bottom) {
            Divider()
        }
    }

    var serviceUpdateStripeText: String {
        let installed = state.serviceBinaryVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        let expected = state.expectedServiceBinaryVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        if installed.isEmpty || expected.isEmpty {
            return "Background service needs update to match the app"
        }
        return "Background service is on v\(installed); update to match app v\(expected)"
    }

    var updateStripe: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.secondary)
            Text(updateStripeText)
                .font(.callout)
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer(minLength: 12)
            Toggle("Install automatically", isOn: $manager.autoInstallUpdates)
                .toggleStyle(.checkbox)
                .font(.caption)
                .foregroundStyle(.secondary)
            Button {
                manager.installUpdate()
            } label: {
                Text(manager.updateInstalling ? "Installing…" : "Install")
            }
            .controlSize(.small)
            .disabled(!manager.updateInstallEnabled)
        }
        .padding(.leading, 104)
        .padding(.trailing, 18)
        .padding(.vertical, 6)
        .background(Color(nsColor: .underPageBackgroundColor))
        .overlay(alignment: .bottom) {
            Divider()
        }
    }

    var updateStripeText: String {
        let current = state.appVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        if current.isEmpty {
            return "Update available: \(manager.updateVersion)"
        }
        return "Update available: \(manager.updateVersion) (you're on \(current))"
    }

    var systemVersionLabel: String {
        let app = state.appVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        let daemon = state.daemonBinaryVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        switch (app.isEmpty, daemon.isEmpty) {
        case (true, true): return ""
        case (false, true): return "gui v\(app)"
        case (true, false): return "daemon v\(daemon)"
        case (false, false) where app == daemon: return "v\(app)"
        case (false, false): return "gui v\(app) · daemon v\(daemon)"
        }
    }

    var headerIdentity: some View {
        HStack(spacing: 6) {
            if let shownNetwork, state.networks.count > 1 {
                networkStatusDot(shownNetwork)
            }
            Picker("", selection: headerNetworkSelection) {
                ForEach(state.networks, id: \.id) { network in
                    Text(displayName(network))
                        .tag(network.id)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .disabled(state.networks.isEmpty)
            .frame(maxWidth: 160, alignment: .leading)

            Button {
                addNetworkPresented = true
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 11, weight: .semibold))
            }
            .buttonStyle(.borderless)
            .help("Add network")
            .accessibilityIdentifier("add-network-open")
        }
        .frame(width: 220, alignment: .leading)
    }

    var headerNetworkSelection: Binding<String> {
        Binding(
            get: { shownNetwork?.id ?? state.networks.first?.id ?? "" },
            set: { networkId in
                guard let network = state.networks.first(where: { $0.id == networkId }) else {
                    return
                }
                shownNetworkId = network.id
                selectedSidebarItem = .devices
                if !network.enabled {
                    activateNetwork(network)
                }
            }
        )
    }

    func networkStatusDot(_ network: NativeNetworkState) -> some View {
        Circle()
            .fill(network.enabled ? Color.green : Color.secondary.opacity(0.55))
            .frame(width: 7, height: 7)
    }

    var headerVpnControl: some View {
        HStack(spacing: 8) {
            Text(headerVpnStatusText)
                .font(.caption2)
                .foregroundStyle(headerStatusTextColor)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: 150, alignment: .trailing)
                .layoutPriority(1)
            if headerStatusDotVisible {
                Circle()
                    .fill(headerStatusColor)
                    .frame(width: 7, height: 7)
            }
            headerVpnSwitch
        }
        .help(manager.vpnSwitchEnabled ? "Turn VPN off" : "Turn VPN on")
    }

    var headerVpnSwitch: some View {
        let disabled = manager.actionInFlight || !state.vpnControlSupported || activeNetwork == nil
        return Button {
            manager.toggleVpn()
        } label: {
            ZStack(alignment: manager.vpnSwitchEnabled ? .trailing : .leading) {
                Capsule()
                    .fill(manager.vpnSwitchEnabled ? Color.accentColor : Color(nsColor: .tertiaryLabelColor).opacity(0.45))
                    .frame(width: 52, height: 26)
                Circle()
                    .fill(Color.white)
                    .frame(width: 22, height: 22)
                    .shadow(color: .black.opacity(0.22), radius: 1, y: 1)
                    .padding(2)
            }
            .frame(width: 52, height: 26)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .accessibilityIdentifier("vpn-service-toggle")
        .accessibilityLabel(manager.vpnSwitchEnabled ? "Turn VPN off" : "Turn VPN on")
        .accessibilityValue(manager.vpnSwitchEnabled ? "On" : "Off")
    }

    var sidebar: some View {
        VStack(alignment: .leading, spacing: 5) {
            sidebarButton(.devices, "Devices", "circle.grid.2x2.fill")
            sidebarButton(.internet, "Internet", "network")
            if paidRouteMarketAvailable {
                sidebarButton(.wallet, walletSidebarTitle, "creditcard.fill")
            }
            sidebarButton(.settings, "Settings", "gearshape")
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.top, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    var walletSidebarTitle: String {
        let balance = state.paidRouteMarket.wallet.navigationBalanceText
        return balance.isEmpty ? "Wallet" : "Wallet \(balance)"
    }

    func sidebarButton(_ item: SidebarItem, _ title: String, _ systemImage: String) -> some View {
        let selected = visibleSidebarItem == item
        return Button {
            selectedSidebarItem = item
        } label: {
            HStack(spacing: 8) {
                Label(title, systemImage: systemImage)
                    .labelStyle(.titleAndIcon)
                Spacer(minLength: 0)
            }
            .font(.subheadline.weight(.semibold))
            .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .frame(height: 32)
                .background(selected ? Color.accentColor : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                .foregroundStyle(selected ? Color.white : Color.primary)
                .contentShape(RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("sidebar-\(item)")
    }

    @ViewBuilder
    var detailPane: some View {
        switch visibleSidebarItem {
        case .devices:
            if let shownNetwork {
                devicesPane(shownNetwork)
            } else {
                setupPane
            }
        case .internet:
            pageScroll {
                pageTitle("Internet", "network")
                if let shownNetwork {
                    internetSection(shownNetwork)
                } else {
                    internetChoiceSettings
                    wireGuardExitSettings
                }
            }
        case .publicExits:
            pageScroll {
                pageTitle("Buy Internet", "cart.fill")
                Text("Experimental")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(state.exitNodeStatusText)
                    .font(.callout)
                    .foregroundStyle(state.exitNodeBlocked ? Color.red : Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("paid-exit-current-internet")
                paidRouteMarketSettings
            }
        case .sellExit:
            pageScroll {
                pageTitle("Sell Internet", "bitcoinsign.circle.fill")
                Text("Experimental")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                paidExitSellerSettings
            }
        case .wallet:
            pageScroll {
                pageTitle("Wallet", "creditcard.fill")
                paidRouteWalletSettings
            }
        case .settings:
            pageScroll {
                pageTitle("Settings", "gearshape")
                settingsSection
            }
        }
    }

    func sidebarItemVisible(_ item: SidebarItem) -> Bool {
        switch item {
        case .publicExits, .wallet:
            return paidRouteMarketAvailable
        case .sellExit:
            return paidExitSellerAvailable
        case .devices, .internet, .settings:
            return true
        }
    }

    func normalizeSidebarSelection() {
        if let selectedSidebarItem, !sidebarItemVisible(selectedSidebarItem) {
            self.selectedSidebarItem = .devices
        }
    }

    func pageScroll<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                content()
            }
            .padding(.horizontal, 28)
            .padding(.top, 28)
            .padding(.bottom, 32)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    func pageTitle(_ title: String, _ systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.system(size: 24, weight: .semibold))
    }
}
