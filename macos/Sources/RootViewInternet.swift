import AppKit
import CoreImage
import SwiftUI

extension RootView {
    func internetSection(_ network: NativeNetworkState) -> some View {
        LocalSearchScope { search in
            internetSection(network, search: search)
        }
    }

    func internetSection(_ network: NativeNetworkState, search: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            internetChoiceSettings
            trustedDeviceInternetSettings(network, search: search)
            shareInternetSettings
            wireGuardUpstreamSettings
            exitDnsSettings
        }
    }

    var internetChoiceSettings: some View {
        return surface {
            sectionHeader("Use Internet", systemImage: "network")
            Text(state.exitNodeStatusText)
                .font(.callout)
                .foregroundStyle(state.exitNodeBlocked ? Color.red : Color.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("internet-source-status")
            VStack(spacing: 8) {
                routeChoice(
                    title: "This device",
                    subtitle: "Use my normal connection",
                    selected: state.internetSource == "direct",
                    enabled: true
                ) {
                    manager.selectDirectExit()
                }

                if paidRouteMarketAvailable {
                    routeChoice(
                        title: "Paid Internet · Automatic",
                        subtitle: state.internetSource == "paid_automatic"
                            ? "Experimental · \(state.exitNodeStatusText)"
                            : "Experimental · Choose a reasonably priced provider that passes verification",
                        selected: state.internetSource == "paid_automatic",
                        enabled: true
                    ) {
                        manager.selectPaidAutomaticExit()
                    }

                    routeChoice(
                        title: "Paid Internet · Manual",
                        subtitle: state.internetSource == "paid_manual"
                            ? "Experimental · \(state.exitNodeStatusText)"
                            : "Experimental · Browse and choose a provider",
                        selected: state.internetSource == "paid_manual",
                        enabled: true
                    ) {
                        manager.selectPaidManualExit()
                        selectedSidebarItem = .publicExits
                    }
                }

                routeChoice(
                    title: "Upstream VPN",
                    subtitle: wireguardUpstreamSubtitle,
                    selected: state.internetSource == "wireguard",
                    enabled: state.wireguardExitConfigured
                ) {
                    manager.selectWireGuardUpstreamExit()
                }

                Divider()
                Toggle("Block internet if selected source disconnects", isOn: Binding(
                    get: { state.exitNodeLeakProtection },
                    set: { manager.setExitNodeLeakProtection($0) }
                ))
                .disabled(manager.actionInFlight)
            }
        }
    }

    func trustedDeviceInternetSettings(_ network: NativeNetworkState, search: Binding<String>) -> some View {
        let allPeerExitCandidates = exitNodeCandidates(network, search: "")
        let showSearch = allPeerExitCandidates.count > searchVisibilityThreshold
        let activeSearch = showSearch ? search.wrappedValue : ""
        let peerExitCandidates = exitNodeCandidates(network, search: activeSearch)

        return surface {
            sectionHeader("Private VPN Device", systemImage: "lock.shield.fill")
            if showSearch {
                TextField("Search devices", text: search)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(spacing: 8) {
                if peerExitCandidates.isEmpty {
                    emptyRow(
                        activeSearch.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            ? "No trusted devices sharing internet"
                            : "No trusted devices found",
                        systemImage: "tray"
                    )
                } else {
                    ForEach(peerExitCandidates, id: \.pubkeyHex) { participant in
                        routeChoice(
                            title: deviceName(participant),
                            subtitle: participant.statusText.isEmpty ? "Trusted device" : participant.statusText,
                            selected: state.internetSource == "private_vpn" && state.exitNode == participant.npub,
                            enabled: true
                        ) {
                            manager.selectPeerExit(participant.npub)
                        }
                    }
                }
            }
        }
    }

    var shareInternetSettings: some View {
        surface {
            HStack(spacing: 12) {
                sectionHeader("Share with Trusted Devices", systemImage: "lock.shield.fill")
                Spacer(minLength: 16)
                Toggle("", isOn: Binding(
                    get: { state.advertiseExitNode },
                    set: { manager.setAdvertiseExitNode($0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .disabled(manager.actionInFlight)
            }
            Text("Only devices in \(shownNetworkLabel) can use it.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if paidExitSellerAvailable {
                Divider()
                Button {
                    selectedSidebarItem = .sellExit
                } label: {
                    Label("Sell Internet · Experimental", systemImage: "bitcoinsign.circle.fill")
                }
                .accessibilityIdentifier("paid-exit-seller-open")
                .buttonStyle(.bordered)
            }
        }
    }

    var exitDnsSettings: some View {
        surface {
            sectionHeader("Exit DNS", systemImage: "lock.shield")
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
                Text("Uses WireGuard profile DNS when supplied; otherwise built-in encrypted DNS.")
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

    var shownNetworkLabel: String {
        shownNetwork.map(displayName) ?? "this network"
    }

    var paidExitSellerSummaryText: String {
        if !state.paidExitSeller.enabled {
            return "People can pay to use this Mac's internet connection."
        }
        return "Sharing is on. Save changes to refresh the listing automatically."
    }

    var wireguardUpstreamSubtitle: String {
        if !state.wireguardExitConfigured {
            return "Set up a WireGuard provider"
        }
        let endpoint = state.wireguardExitEndpoint
        if endpoint.isEmpty {
            return "Configured"
        }
        return "via \(endpoint)"
    }

    var paidExitCurrentUpstream: String {
        state.internetSource == "wireguard" ? "wireguard_exit" : "host_default"
    }

    var paidExitCurrentInternetTitle: String {
        state.internetSource == "wireguard" ? "My internet through WireGuard" : "My internet"
    }

    var paidExitCurrentInternetDetail: String {
        if state.internetSource == "wireguard" {
            return wireguardUpstreamSubtitle
        }
        if state.internetSource == "private_vpn" {
            return "Through the selected trusted device"
        }
        return "The same connection this Mac already uses"
    }

    func routeChoice(
        title: String,
        subtitle: String,
        selected: Bool,
        enabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? .green : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .disabled(!enabled || manager.actionInFlight)
        .opacity(enabled ? 1 : 0.55)
    }
}
