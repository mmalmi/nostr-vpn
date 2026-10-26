import AppKit
import CoreImage
import SwiftUI

extension RootView {
    var settingsPane: some View {
        ScrollViewReader { proxy in
            pageScroll {
                pageTitle("Settings", "gearshape")
                settingsSection
            }
            .onAppear {
                if settingsScrollToWireGuard {
                    proxy.scrollTo("settings-wireguard", anchor: .top)
                    settingsScrollToWireGuard = false
                }
            }
        }
    }

    var settingsSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            generalSettings
            connectionSettings
            exitDnsSettings
            wireGuardUpstreamSettings
                .id("settings-wireguard")
            deviceSettings
            if state.paidRouteMarket.supported {
                walletDisplaySettings
            }
            fipsSettings
            publicFipsSettings
            pubsubSettings
            relaySettings
            networkSettings
            systemSettings
            diagnosticsSection
        }
    }

    var connectionSettings: some View {
        surface {
            sectionHeader("Connection", systemImage: "network")
            Toggle("Block internet if selected source disconnects", isOn: Binding(
                get: { state.exitNodeLeakProtection },
                set: { manager.setExitNodeLeakProtection($0) }
            ))
            .frame(maxWidth: .infinity, alignment: .leading)
            .disabled(manager.actionInFlight)
        }
    }

    var exitDnsSettings: some View {
        surface {
            sectionHeader("Exit DNS", systemImage: "lock.shield")
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("MagicDNS stays local. Public DNS follows this policy while an internet exit is active.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Picker("Mode", selection: $exitDnsMode) {
                Text("Automatic (recommended)").tag("automatic")
                Text("Encrypted DNS").tag("encrypted")
                Text("DNS through exit").tag("through_exit")
            }
            .accessibilityIdentifier("exit-dns-mode")

            if exitDnsMode == "encrypted" {
                Picker("Provider", selection: $exitDnsDohProvider) {
                    Text("Cloudflare").tag("cloudflare")
                    Text("Quad9").tag("quad9")
                    Text("Custom DoH").tag("custom")
                }
                .accessibilityIdentifier("exit-dns-provider")
                if exitDnsDohProvider == "custom" {
                    TextField("HTTPS DoH URL", text: $exitDnsCustomDohUrl)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("exit-dns-custom-url")
                    TextField("Bootstrap IPs, comma separated", text: $exitDnsCustomDohBootstrapIps)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("exit-dns-bootstrap-ips")
                }
            } else if exitDnsMode == "through_exit" {
                TextField("DNS server IPs, comma separated", text: $exitDnsThroughExitServers)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("exit-dns-through-servers")
                Text("These DNS packets are sent only through the selected exit.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Uses WireGuard profile DNS when supplied; otherwise Cloudflare encrypted DNS.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button {
                manager.saveExitDnsSettings(
                    mode: exitDnsMode,
                    provider: exitDnsDohProvider,
                    customUrl: exitDnsCustomDohUrl,
                    bootstrapIps: exitDnsCustomDohBootstrapIps,
                    throughExitServers: exitDnsThroughExitServers
                )
            } label: {
                Label("Save Exit DNS", systemImage: "checkmark")
            }
            .disabled(manager.actionInFlight)
            .accessibilityIdentifier("exit-dns-save")
        }
    }

    var walletDisplaySettings: some View {
        surface {
            sectionHeader("Wallet", systemImage: "creditcard.fill")
            settingsToggleRow("Show fiat value", isOn: Binding(
                get: { state.walletFiatEnabled },
                set: { manager.setWalletFiatEnabled($0) }
            ))
            if state.walletFiatEnabled {
                Picker("Currency", selection: Binding(
                    get: { state.walletFiatCurrency },
                    set: { manager.setWalletFiatCurrency($0) }
                )) {
                    ForEach(["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF"], id: \.self) {
                        Text($0).tag($0)
                    }
                }
                .frame(maxWidth: 220, alignment: .leading)
                Text("Rates from Coinbase and Kraken")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    var relaySettings: some View {
        surface {
            sectionHeader("Relays", systemImage: "dot.radiowaves.left.and.right")
            HStack(spacing: 8) {
                TextField("wss://relay.example.com", text: $relayInput)
                    .textFieldStyle(.roundedBorder)
                    .disableAutocorrection(true)
                    .onSubmit { addRelayFromInput() }
                Button {
                    addRelayFromInput()
                } label: {
                    Label("Add", systemImage: "plus")
                }
                .disabled(relayInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || manager.actionInFlight)
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(state.relays, id: \.url) { relay in
                    relayRow(relay)
                }
            }
        }
    }

    func relayRow(_ relay: NativeRelayState) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(relay.status == "connected" ? Color.green : Color.secondary.opacity(0.65))
                .frame(width: 9, height: 9)
            Text(relay.url)
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(relay.enabled ? .primary : .secondary)
            Spacer(minLength: 8)
            Toggle("", isOn: Binding(
                get: { relay.enabled },
                set: { manager.setRelay(relay.url, enabled: $0) }
            ))
            .labelsHidden()
            .disabled(manager.actionInFlight)
            Button(role: .destructive) {
                manager.deleteRelay(relay.url)
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .disabled(manager.actionInFlight)
        }
        .padding(.vertical, 3)
    }

    func addRelayFromInput() {
        if manager.addRelay(relayInput) {
            relayInput = ""
        }
    }

    var deviceSettings: some View {
        surface {
            sectionHeader("This Device", systemImage: "macbook")
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    label("Name")
                    TextField("Name", text: $nodeName)
                }
                GridRow {
                    label("Tunnel IP")
                    TextField("Tunnel IP", text: $tunnelIp)
                }
            }
            Button {
                manager.saveDeviceSettings(
                    nodeName: nodeName,
                    endpoint: endpoint,
                    tunnelIp: tunnelIp,
                    listenPort: listenPort
                )
            } label: {
                Label("Save", systemImage: "checkmark")
            }
            .disabled(manager.actionInFlight)
        }
    }

    var generalSettings: some View {
        surface {
            sectionHeader("General", systemImage: "gearshape.fill")
            VStack(alignment: .leading, spacing: 8) {
                settingsToggleRow("Start VPN automatically", isOn: Binding(
                    get: { state.autoconnect },
                    set: { manager.setAutoconnect($0) }
                ))
                settingsToggleRow("Launch on startup", isOn: Binding(
                    get: { state.launchOnStartup },
                    set: { manager.setLaunchOnStartup($0) }
                ), disabled: !state.startupSettingsSupported)
                settingsToggleRow("Menu bar on close", isOn: Binding(
                    get: { state.closeToTrayOnClose },
                    set: { manager.setCloseToTray($0) }
                ), disabled: !state.trayBehaviorSupported)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    var publicFipsSettings: some View {
        surface {
            sectionHeader("Public .fips Addresses", systemImage: "network")
            VStack(alignment: .leading, spacing: 8) {
                Text("Public .fips addresses let hosts reach each other with end-to-end encryption, without static IPs, TLS certificates, or NAT port forwarding.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let url = URL(string: "https://learn.fips.network/") {
                    Link("Learn FIPS", destination: url)
                        .font(.caption)
                }
                settingsToggleRow("Let this Mac serve its public .fips address", isOn: Binding(
                    get: { state.fipsHostTunnelEnabled },
                    set: { manager.setFipsHostTunnel($0) }
                ))
                VStack(alignment: .leading, spacing: 8) {
                    detailValueRow("Your public FIPS address", publicFipsAddress)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Public .fips inbound TCP ports")
                            .foregroundStyle(.secondary)
                        TextField("", text: $fipsHostInboundTcpPorts)
                    }
                    Button {
                        manager.saveFipsHostInboundTcpPorts(fipsHostInboundTcpPorts)
                    } label: {
                        Label("Save", systemImage: "checkmark")
                    }
                    .disabled(manager.actionInFlight)
                }
                .disabled(!state.fipsHostTunnelEnabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    var publicFipsAddress: String {
        state.ownNpub.isEmpty ? "" : "\(state.ownNpub).fips"
    }

    var fipsSettings: some View {
        surface {
            sectionHeader("FIPS", systemImage: "shield.fill")
            VStack(alignment: .leading, spacing: 8) {
                settingsToggleRow("Connect to non-roster FIPS peers", isOn: Binding(
                    get: { state.connectToNonRosterFipsPeers },
                    set: { manager.setConnectToNonRosterFipsPeers($0) }
                ))
                settingsToggleRow("Find peers over Nostr relays", isOn: Binding(
                    get: { state.fipsNostrDiscoveryEnabled },
                    set: { manager.setFipsNostrDiscoveryEnabled($0) }
                ))
                settingsToggleRow("Enable WebRTC transport", isOn: Binding(
                    get: { state.fipsWebrtcEnabled },
                    set: { manager.setFipsWebrtcEnabled($0) }
                ))
                settingsToggleRow("Use bootstrap servers", isOn: Binding(
                    get: { state.fipsBootstrapEnabled },
                    set: { manager.setFipsBootstrapEnabled($0) }
                ))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    var pubsubSettings: some View {
        surface {
            sectionHeader("Nostr Pubsub", systemImage: "point.3.connected.trianglepath.dotted")
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    label("Mode")
                    Picker("", selection: $nostrPubsubMode) {
                        Text("Off").tag("off")
                        Text("Client").tag("client")
                        Text("Relay").tag("relay")
                    }
                    .pickerStyle(.segmented)
                }
                GridRow {
                    label("Fanout")
                    TextField("8", text: $nostrPubsubFanout)
                }
                GridRow {
                    label("Hops")
                    TextField("4", text: $nostrPubsubMaxHops)
                }
                GridRow {
                    label("Max event bytes")
                    TextField("65536", text: $nostrPubsubMaxEventBytes)
                }
            }
            Button {
                manager.saveNostrPubsubSettings(
                    mode: nostrPubsubMode,
                    fanout: nostrPubsubFanout,
                    maxHops: nostrPubsubMaxHops,
                    maxEventBytes: nostrPubsubMaxEventBytes
                )
            } label: {
                Label("Save", systemImage: "checkmark")
            }
            .disabled(manager.actionInFlight)
        }
    }

    func settingsToggleRow(_ title: String, isOn: Binding<Bool>, disabled: Bool = false) -> some View {
        HStack(spacing: 12) {
            Text(title)
            Spacer(minLength: 16)
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .disabled(disabled)
    }

    var wireGuardUpstreamSettings: some View {
        surface {
            disclosureSection(
                title: "WireGuard VPN",
                systemImage: "network",
                isExpanded: $wireGuardUpstreamExpanded,
                font: .headline
            ) {
                wireGuardUpstreamEditor
                    .padding(.top, 8)
            }
        }
    }

    var wireGuardUpstreamEditor: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Optional: paste a WireGuard config if you use a separate VPN provider.")
                .font(.caption)
                .foregroundStyle(.secondary)

            TextEditor(text: $wireguardExitConfig)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 160)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color(nsColor: .separatorColor))
                )

            HStack {
                Button {
                    manager.chooseWireGuardConfigFile()
                } label: {
                    Label("Import File", systemImage: "doc.badge.plus")
                }
                .disabled(manager.actionInFlight)

                Button {
                    manager.saveWireGuardExitConfig(wireguardExitConfig)
                } label: {
                    Label("Save", systemImage: "checkmark")
                }
                .disabled(manager.actionInFlight)
            }
        }
    }

    var networkSettings: some View {
        surface {
            HStack {
                sectionHeader("Networks", systemImage: "rectangle.stack")
                Spacer()
                TextField("New network", text: $networkNameInput)
                    .frame(width: 180)
                    .onSubmit { addNetwork() }
                Button {
                    addNetwork()
                } label: {
                    Image(systemName: "plus")
                }
                .disabled(networkNameInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || manager.actionInFlight)
            }

            if let network = shownNetwork {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                    GridRow {
                        label(network.enabled ? "Active" : "Shown")
                        TextField("Name", text: networkNameBinding(network))
                        Button {
                            manager.renameNetwork(networkId: network.id, name: networkNameDrafts[network.id] ?? network.name)
                        } label: {
                            Image(systemName: "checkmark")
                        }
                        .disabled(!network.localIsAdmin || manager.actionInFlight)
                    }
                    GridRow {
                        label("Network ID")
                        Text(displayNetworkId(network.networkId))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        copyButton(value: network.networkId, copied: .meshId, systemImage: "doc.on.doc")
                    }
                    GridRow {
                        label("")
                        Button(role: .destructive) {
                            pendingNetworkRemoval = network
                        } label: {
                            Label("Delete this network", systemImage: "trash")
                        }
                        .buttonStyle(.borderless)
                        .disabled(manager.actionInFlight)
                        .confirmationDialog(
                            "Remove \(displayName(network))?",
                            isPresented: Binding(
                                get: { pendingNetworkRemoval?.id == network.id },
                                set: { if !$0 { pendingNetworkRemoval = nil } }
                            ),
                            titleVisibility: .visible,
                            presenting: pendingNetworkRemoval
                        ) { target in
                            Button("Remove", role: .destructive) {
                                manager.removeNetwork(target.id)
                                pendingNetworkRemoval = nil
                            }
                            Button("Cancel", role: .cancel) { pendingNetworkRemoval = nil }
                        } message: { _ in
                            Text("This deletes the network from this device.")
                        }
                    }
                }
            }

            disclosureSection(
                title: "Saved Networks",
                systemImage: "rectangle.stack",
                isExpanded: $savedNetworksExpanded,
                font: .subheadline.weight(.medium)
            ) {
                VStack(alignment: .leading, spacing: 10) {
                    if manager.inactiveNetworks.isEmpty {
                        emptyRow("No saved networks", systemImage: "rectangle.stack")
                    } else {
                        ForEach(manager.inactiveNetworks, id: \.id) { network in
                            savedNetworkRow(network)
                        }
                    }
                }
                .padding(.top, 8)
            }
        }
    }

    func savedNetworkRow(_ network: NativeNetworkState) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                TextField("Name", text: networkNameBinding(network))
                    .textFieldStyle(.plain)
                Text("\(network.onlineCount) of \(network.expectedCount) connected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Activate") {
                activateNetwork(network)
            }
            .disabled(manager.actionInFlight)
            Button(role: .destructive) {
                pendingNetworkRemoval = network
            } label: {
                Image(systemName: "trash")
            }
            .disabled(manager.actionInFlight)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .confirmationDialog(
            "Remove \(pendingNetworkRemoval.map(displayName) ?? "network")?",
            isPresented: Binding(
                get: { pendingNetworkRemoval?.id == network.id },
                set: { if !$0 { pendingNetworkRemoval = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingNetworkRemoval
        ) { target in
            Button("Remove", role: .destructive) {
                manager.removeNetwork(target.id)
                pendingNetworkRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingNetworkRemoval = nil }
        } message: { _ in
            Text("This deletes the network from this device.")
        }
    }

    var systemSettings: some View {
        surface {
            HStack(spacing: 8) {
                sectionHeader("System", systemImage: "gearshape.2")
                if !systemVersionLabel.isEmpty {
                    Text(systemVersionLabel)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                if manager.serviceSettling || manager.updateChecking || manager.updateInstalling {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            HStack(spacing: 8) {
                badge(state.serviceInstalled ? "Service installed" : "Service missing", style: state.serviceInstalled ? .ok : .warn)
                badge(state.serviceRunning ? "Running" : "Stopped", style: state.serviceRunning ? .ok : .muted)
                if manager.serviceUpdateRecommended {
                    badge("Update available", style: .warn)
                }
                badge(state.cliInstalled ? "CLI installed" : "CLI missing", style: state.cliInstalled ? .ok : .muted)
                badge(manager.updateAvailable ? "Update \(manager.updateVersion)" : "Up to date", style: manager.updateAvailable ? .warn : .ok)
            }

            if manager.serviceUpdateRecommended || !state.serviceStatusDetail.isEmpty || !manager.updateStatus.isEmpty {
                Text(firstNonEmpty(manager.updateStatus, state.serviceStatusDetail, fallback: ""))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            HStack {
                Button {
                    manager.installService()
                } label: {
                    Label(serviceInstallButtonTitle, systemImage: manager.serviceUpdateRecommended ? "arrow.up.circle" : "arrow.down.to.line")
                }
                .disabled(!state.serviceSupported || manager.actionInFlight || manager.serviceSettling)

                Button {
                    manager.checkForUpdates()
                } label: {
                    Label("Check Updates", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(manager.updateChecking || manager.updateInstalling)

                Button {
                    manager.installCli()
                } label: {
                    Label(state.cliInstalled ? "Reinstall CLI" : "Install CLI", systemImage: "terminal")
                }
                .disabled(!state.cliInstallSupported || manager.actionInFlight)
            }
        }
    }

    var diagnosticsSection: some View {
        surface {
            disclosureSection(
                title: "Diagnostics",
                systemImage: "waveform.path.ecg",
                isExpanded: $diagnosticsExpanded
            ) {
                VStack(alignment: .leading, spacing: 12) {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), alignment: .leading)], alignment: .leading, spacing: 10) {
                        metric("Peers", "\(state.connectedPeerCount)/\(state.expectedPeerCount)")
                        metric("Roster FIPS", "\(state.fipsConnectedPeerCount)/\(state.fipsRosterPeerCount) direct")
                        metric("Other FIPS", "\(state.nonFipsRosterPeerCount)")
                        metric("Interface", state.network.defaultInterface.isEmpty ? "unknown" : state.network.defaultInterface)
                        metric("IPv4", state.network.primaryIpv4.isEmpty ? "-" : state.network.primaryIpv4)
                        metric("IPv6", state.network.primaryIpv6.isEmpty ? "-" : state.network.primaryIpv6)
                        metric("Gateway", firstNonEmpty(state.network.gatewayIpv4, state.network.gatewayIpv6, fallback: "unknown"))
                        metric("Mapping", state.portMapping.activeProtocol.isEmpty ? "none" : state.portMapping.activeProtocol)
                        metric("External", state.portMapping.externalEndpoint.isEmpty ? "stun/direct" : state.portMapping.externalEndpoint)
                    }
                    if state.health.isEmpty {
                        emptyRow("No health warnings", systemImage: "checkmark.circle")
                    } else {
                        ForEach(state.health, id: \.code) { issue in
                            HStack(alignment: .top, spacing: 8) {
                                badge(issue.severity, style: healthStyle(issue.severity))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(issue.summary)
                                    Text(issue.detail)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                .padding(.top, 8)
            }
        }
    }

    func disclosureSection<Content: View>(
        title: String,
        systemImage: String,
        isExpanded: Binding<Bool>,
        font: Font = .headline,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.14)) {
                    isExpanded.wrappedValue.toggle()
                }
            } label: {
                HStack(spacing: 7) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 10)
                        .rotationEffect(.degrees(isExpanded.wrappedValue ? 90 : 0))
                    Label(title, systemImage: systemImage)
                        .font(font)
                    Spacer(minLength: 0)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(title)
            .accessibilityValue(isExpanded.wrappedValue ? "Expanded" : "Collapsed")

            if isExpanded.wrappedValue {
                content()
            }
        }
    }
}
