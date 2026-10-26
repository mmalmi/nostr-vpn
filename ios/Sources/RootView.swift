import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct RootView: View {
    @ObservedObject var model: AppModel
    @AppStorage(AppModel.vpnDisclosureAcceptedKey) private var vpnDisclosureAccepted = false
    @State private var addNetworkPresented = false
    @State private var vpnDisclosurePresented = false
    @State private var startVpnAfterDisclosure = false
    @State private var shownNetworkId: String?
    @State private var selectedTab = Self.initialTab()

    private var shownNetwork: NetworkState? {
        if let shownNetworkId,
           let network = model.state.networks.first(where: { $0.id == shownNetworkId }) {
            return network
        }
        return model.activeNetwork ?? model.state.networks.first
    }

    var body: some View {
        Group {
            if model.state.networks.isEmpty {
                NavigationStack {
                    AddNetworkPage(
                        model: model,
                        showsWelcomeHeader: true,
                        onReviewVpnDisclosure: {
                            presentVpnDisclosure(startVpnAfterAccept: true)
                        }
                    )
                        .toolbar(.hidden, for: .navigationBar)
                }
            } else {
                TabView(selection: $selectedTab) {
                    NavigationStack {
                        DevicesPage(model: model, network: shownNetwork)
                            .toolbar { networkSwitcherToolbar }
                    }
                    .tabItem { Label("Devices", systemImage: "circle.grid.2x2.fill") }
                    .tag(AppTab.devices)

                    NavigationStack {
                        InternetPage(model: model, network: shownNetwork)
                            .navigationTitle("Internet")
                            .toolbar { networkSwitcherToolbar }
                    }
                    .tabItem { Label("Internet", systemImage: "network") }
                    .tag(AppTab.internet)

                    NavigationStack {
                        SettingsPage(model: model)
                            .navigationTitle("Settings")
                            .toolbar { networkSwitcherToolbar }
                    }
                    .tabItem { Label("Settings", systemImage: "gearshape") }
                    .tag(AppTab.settings)
                }
            }
        }
        .tint(.purple)
        .onChange(of: model.fileTransfersRequested, initial: true) { _, requested in
            if requested {
                selectedTab = .devices
                model.fileTransfersRequested = false
            }
        }
        .sheet(isPresented: $addNetworkPresented) {
            NavigationStack {
                AddNetworkPage(
                    model: model,
                    onCreated: { networkId in
                        shownNetworkId = networkId
                        addNetworkPresented = false
                        selectedTab = .devices
                    },
                    onReviewVpnDisclosure: {
                        presentVpnDisclosure(startVpnAfterAccept: true)
                    }
                )
                    .navigationTitle("Add Network")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { addNetworkPresented = false }
                        }
                }
            }
        }
        .sheet(isPresented: $vpnDisclosurePresented) {
            VpnDisclosureSheet {
                let shouldStartVpn = startVpnAfterDisclosure
                vpnDisclosureAccepted = true
                startVpnAfterDisclosure = false
                vpnDisclosurePresented = false
                model.markVpnDisclosureAccepted()
                if shouldStartVpn {
                    model.startVpnAfterDisclosure()
                }
            }
        }
        .onAppear {
            if model.vpnDisclosurePromptVisible && !vpnDisclosureAccepted {
                presentVpnDisclosure(startVpnAfterAccept: true)
            }
        }
        .onChange(of: model.vpnDisclosurePromptVisible) { _, visible in
            if visible && !vpnDisclosureAccepted {
                presentVpnDisclosure(startVpnAfterAccept: true)
            }
        }
        .onChange(of: model.state.rev) { _, _ in
            if let shownNetworkId,
               !model.state.networks.contains(where: { $0.id == shownNetworkId }) {
                self.shownNetworkId = nil
            }
        }
    }

    @ToolbarContentBuilder
    private var networkSwitcherToolbar: some ToolbarContent {
        ToolbarItem(placement: .principal) {
            NetworkSwitcher(
                model: model,
                shownNetwork: shownNetwork,
                shownNetworkId: $shownNetworkId,
                addNetworkPresented: $addNetworkPresented
            )
        }
        ToolbarItem(placement: .topBarTrailing) {
            ToolbarVpnSwitch(
                model: model,
                vpnDisclosureAccepted: vpnDisclosureAccepted,
                onReviewVpnDisclosure: {
                    presentVpnDisclosure(startVpnAfterAccept: true)
                }
            )
        }
    }

    private func presentVpnDisclosure(startVpnAfterAccept: Bool) {
        startVpnAfterDisclosure = startVpnAfterAccept
        vpnDisclosurePresented = true
    }

    private static func initialTab() -> AppTab {
        switch AppModel.screenshotTabArgument()?.lowercased() {
        case "internet", "exit", "exit-node", "exit-nodes", "routes", "routing":
            return .internet
        case "settings", "diagnostics":
            return .settings
        default:
            return .devices
        }
    }
}

private enum AppTab: Hashable {
    case devices
    case internet
    case settings
}

/// Header dropdown that shows the active network's name and lets the user
/// switch to any saved network or jump to the Add Network page. Single
/// "Add network" button when there's only one saved network and nothing
/// to switch to.
private struct NetworkSwitcher: View {
    @ObservedObject var model: AppModel
    let shownNetwork: NetworkState?
    @Binding var shownNetworkId: String?
    @Binding var addNetworkPresented: Bool

    var body: some View {
        Menu {
            Button {
                addNetworkPresented = true
            } label: {
                Label("Add network", systemImage: "plus")
            }
            .accessibilityIdentifier("add-network-open")
            if !model.state.networks.isEmpty {
                Divider()
            }
            ForEach(model.state.networks) { network in
                Button {
                    shownNetworkId = network.id
                } label: {
                    HStack {
                        if model.state.networks.count > 1 {
                            NetworkStatusDot(network: network)
                        }
                        Text(network.displayName)
                    }
                }
            }
        } label: {
            HStack(spacing: 4) {
                if let shownNetwork, model.state.networks.count > 1 {
                    NetworkStatusDot(network: shownNetwork)
                }
                Text(shownNetwork?.displayName ?? "Nostr VPN")
                    .font(.headline)
                    .lineLimit(1)
                Image(systemName: "chevron.down")
                    .font(.caption2)
            }
            .foregroundStyle(.primary)
        }
        .accessibilityIdentifier("network-switcher-open")
        .menuOrder(.fixed)
    }
}

private struct NetworkStatusDot: View {
    let network: NetworkState

    var body: some View {
        Circle()
            .fill(network.enabled ? Color.green : Color.secondary.opacity(0.55))
            .frame(width: 7, height: 7)
    }
}

private enum AddNetworkMode {
    case create
    case join
}

/// First screen on a fresh install AND the screen reachable from the
/// header switcher's "Add network" item. Same content in both contexts:
/// choose create or join first, then show only the selected path.
private struct AddNetworkPage: View {
    @ObservedObject var model: AppModel
    /// Called once the user lands on a network — used by the sheet
    /// presentation to dismiss itself so the underlying Devices tab is
    /// visible. The setup case (no active network) doesn't pass this:
    /// the root view's `if activeNetwork == nil` flips on its own.
    var onCreated: ((String) -> Void)? = nil
    var showsWelcomeHeader = false
    var onReviewVpnDisclosure: () -> Void = {}
    @State private var mode: AddNetworkMode?
    @State private var networkIdsBeforeQrJoin: Set<String>?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                if showsWelcomeHeader && mode == nil {
                    NostrVpnWelcomeHeader()
                }
                if !model.state.error.isEmpty || !model.statusMessage.isEmpty {
                    NoticeCard(
                        text: model.state.error.isEmpty ? model.statusMessage : model.state.error,
                        actionTitle: model.state.error.isEmpty && model.vpnDisclosurePromptVisible ? "Review" : nil,
                        action: onReviewVpnDisclosure
                    )
                }
                switch mode {
                case nil:
                    AddNetworkChoiceButtons(
                        mode: $mode,
                        onJoin: {
                            networkIdsBeforeQrJoin = Set(model.state.networks.map(\.id))
                            if !model.state.vpnEnabled {
                                model.setVpnEnabled(true)
                            }
                        }
                    )
                    if showsWelcomeHeader {
                        Link(destination: URL(string: "https://nostrvpn.org/privacy/")!) {
                            Label("Privacy Policy", systemImage: "hand.raised")
                        }
                        .font(.footnote)
                        .accessibilityIdentifier("onboarding-privacy-policy-link")
                    }
                case .create:
                    AddNetworkBackButton(mode: $mode)
                    CreateNetworkCard(model: model, onCreated: onCreated)
                case .join:
                    AddNetworkBackButton(mode: $mode)
                    JoinNetworkCard(model: model, onCreated: onCreated)
                }
            }
            .padding()
        }
        .safeAreaPadding(.bottom, 92)
        .background(AppColors.background)
        .onChange(of: model.state.networks.map(\.id)) { _, networkIds in
            guard mode == .join,
                  let networkIdsBeforeQrJoin,
                  let joinedNetworkId = networkIds.first(where: {
                      !networkIdsBeforeQrJoin.contains($0)
                  })
            else {
                return
            }
            self.networkIdsBeforeQrJoin = nil
            onCreated?(joinedNetworkId)
        }
    }
}

private struct AddNetworkChoiceButtons: View {
    @Binding var mode: AddNetworkMode?
    let onJoin: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Button {
                mode = .create
            } label: {
                Label("Create Network", systemImage: "plus.circle.fill")
                    .font(.headline)
                    .frame(maxWidth: .infinity, minHeight: 58)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.roundedRectangle(radius: 16))
            .controlSize(.large)
            .tint(AppColors.create)
            .accessibilityIdentifier("network-setup-create")

            Button {
                onJoin()
                mode = .join
            } label: {
                Label("Join Network", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .frame(maxWidth: .infinity, minHeight: 58)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.roundedRectangle(radius: 16))
            .controlSize(.large)
            .tint(AppColors.join)
            .accessibilityIdentifier("network-setup-join")
        }
    }
}

private struct NostrVpnWelcomeHeader: View {
    var body: some View {
        VStack(spacing: 12) {
            NostrVpnAppIcon()
            Text("Nostr VPN")
                .font(.largeTitle.weight(.bold))
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
        }
        .padding(.top, 26)
        .padding(.bottom, 10)
    }
}

private struct NostrVpnAppIcon: View {
    var body: some View {
        Group {
            if let icon = UIImage.appIcon {
                Image(uiImage: icon)
                    .resizable()
            } else {
                NostrVpnIconFallback()
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .frame(width: 82, height: 82)
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .shadow(color: .black.opacity(0.16), radius: 12, y: 6)
        .accessibilityHidden(true)
    }
}

private struct NostrVpnIconFallback: View {
    var body: some View {
        GeometryReader { geometry in
            let side = min(geometry.size.width, geometry.size.height)
            let scale = side / 108
            ZStack {
                RoundedRectangle(cornerRadius: 22 * scale, style: .continuous)
                    .fill(Color(red: 0.07, green: 0.03, blue: 0.23))
                Path { path in
                    path.move(to: CGPoint(x: 32 * scale, y: 75 * scale))
                    path.addLine(to: CGPoint(x: 32 * scale, y: 30 * scale))
                    path.addLine(to: CGPoint(x: 76 * scale, y: 75 * scale))
                    path.addLine(to: CGPoint(x: 76 * scale, y: 30 * scale))
                }
                .stroke(
                    Color(red: 0.95, green: 0.36, blue: 0.85),
                    style: StrokeStyle(lineWidth: 6.8 * scale, lineCap: .round, lineJoin: .round)
                )
                ForEach(Array(iconNodePoints(scale: scale).enumerated()), id: \.offset) { _, point in
                    Circle()
                        .fill(Color(red: 0.43, green: 0.91, blue: 1.0))
                        .frame(width: 10 * scale, height: 10 * scale)
                        .position(point)
                }
            }
            .frame(width: side, height: side)
        }
    }

    private func iconNodePoints(scale: CGFloat) -> [CGPoint] {
        [
            CGPoint(x: 32 * scale, y: 30 * scale),
            CGPoint(x: 32 * scale, y: 75 * scale),
            CGPoint(x: 76 * scale, y: 30 * scale),
            CGPoint(x: 76 * scale, y: 75 * scale),
        ]
    }
}

private extension UIImage {
    static var appIcon: UIImage? {
        guard
            let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any],
            let primaryIcon = icons["CFBundlePrimaryIcon"] as? [String: Any],
            let iconFiles = primaryIcon["CFBundleIconFiles"] as? [String],
            let iconName = iconFiles.last
        else {
            return nil
        }
        return UIImage(named: iconName)
    }
}

private struct AddNetworkBackButton: View {
    @Binding var mode: AddNetworkMode?

    var body: some View {
        HStack {
            Button {
                mode = nil
            } label: {
                Label("Back", systemImage: "chevron.left")
            }
            .buttonStyle(.bordered)
            Spacer()
        }
    }
}
