import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct SettingsPage: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                DeviceSettingsCard(model: model)
                GeneralSettingsCard(model: model)
                FipsSettingsCard(model: model)
                PubsubSettingsCard(model: model)
                RelaySettingsCard(model: model)
                DiagnosticsCard(state: model.state)
                PrivacySettingsCard()
            }
            .padding()
        }
        .scrollIndicators(.hidden)
        .background(AppColors.background)
    }
}

struct PrivacySettingsCard: View {
    var body: some View {
        AppCard {
            Text("Privacy")
                .font(.headline)
            Link(destination: URL(string: "https://nostrvpn.org/privacy/")!) {
                Label("Privacy Policy", systemImage: "hand.raised")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .accessibilityIdentifier("privacy-policy-link")
        }
    }
}

struct ParticipantRow: View {
    @ObservedObject var model: AppModel
    let network: NetworkState
    let participant: ParticipantState
    @State private var detailPresented = false

    var body: some View {
        Button {
            detailPresented = true
        } label: {
            AppCard {
                HStack(spacing: 12) {
                    Circle()
                        .fill(connectivityTint(participant, state: model.state))
                        .frame(width: 12, height: 12)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(deviceName(participant, state: model.state))
                                .font(.headline)
                                .lineLimit(nil)
                                .fixedSize(horizontal: false, vertical: true)
                            if participant.isAdmin {
                                Pill("Admin", tint: AppColors.accent)
                            }
                            if isSelf(participant, state: model.state) {
                                Pill("This device", tint: AppColors.ok)
                            }
                            if participant.offersExitNode {
                                Pill(
                                    exitNodeBadgeText(participant, state: model.state),
                                    tint: exitNodeBadgeTint(participant, state: model.state)
                                )
                            }
                            if isFipsRouted(participant, state: model.state) {
                                Pill("via mesh", tint: .secondary)
                            }
                        }
                        Text(deviceSubtitle(participant, state: model.state))
                            .foregroundStyle(.secondary)
                        Text(deviceStatus(participant, state: model.state))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(
            "roster-participant-\(participant.rosterAccepted ? "accepted" : "pending")-\(participant.npub)"
        )
        .sheet(isPresented: $detailPresented) {
            NavigationStack {
                DeviceDetailSheet(model: model, network: network, participant: participant)
                    .navigationTitle(deviceName(participant, state: model.state))
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Done") { detailPresented = false }
                        }
                    }
            }
        }
    }
}

struct DeviceDetailSheet: View {
    @ObservedObject var model: AppModel
    let network: NetworkState
    let participant: ParticipantState
    @State private var aliasDraft: String = ""
    @State private var endpointHintsDraft: String = ""
    @State private var pendingRemove = false

    private var isMe: Bool { isSelf(participant, state: model.state) }
    private var localIsAdmin: Bool { network.localIsAdmin }

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                AppCard {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(connectivityTint(participant, state: model.state))
                            .frame(width: 12, height: 12)
                        Text(deviceDetailStatus(participant, state: model.state))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Spacer()
                        if participant.isAdmin {
                            Pill("Admin", tint: AppColors.accent)
                        }
                        if isMe {
                            Pill("This device", tint: AppColors.ok)
                        }
                        if participant.offersExitNode {
                            Pill(
                                exitNodeBadgeText(participant, state: model.state),
                                tint: exitNodeBadgeTint(participant, state: model.state)
                            )
                        }
                    }
                }

                AppCard {
                    Text("Identity")
                        .font(.headline)
                    if !participant.magicDnsName.isEmpty {
                        labelValueRow("Magic DNS", participant.magicDnsName)
                    }
                    labelValueRow("Device ID", participant.npub, copyable: true)
                    if !participant.tunnelIp.isEmpty {
                        labelValueRow("Tunnel IP", participant.tunnelIp, copyable: true)
                    }
                    labelValueRow("FIPS path", fipsPath(participant, state: model.state))
                    if participant.fipsSrttAgeMs > 0 {
                        labelValueRow("Latency age", formatDurationMs(participant.fipsSrttAgeMs))
                    }
                    if !participant.lastFipsControlSeenText.isEmpty {
                        labelValueRow("Control seen", participant.lastFipsControlSeenText)
                    }
                    if !participant.lastFipsDataSeenText.isEmpty {
                        labelValueRow("Data seen", participant.lastFipsDataSeenText)
                    }
                    if !participant.fipsTransportAddr.isEmpty {
                        labelValueRow("Endpoint", participant.fipsTransportAddr)
                    }
                    if !participant.fipsEndpointHints.isEmpty {
                        labelValueRow("Address hints", participant.fipsEndpointHints.joined(separator: ", "))
                    }
                }

                if localIsAdmin {
                    AppCard {
                        Text("Manage")
                            .font(.headline)
                        TextField("Alias", text: $aliasDraft)
                            .textFieldStyle(.roundedBorder)
                            .onAppear { aliasDraft = participant.magicDnsAlias }
                        Button {
                            model.dispatch(
                                NativeActions.setParticipantAlias(npub: participant.npub, alias: aliasDraft),
                                status: "Saving alias"
                            )
                        } label: {
                            Label("Save alias", systemImage: "checkmark")
                        }
                        .buttonStyle(.bordered)

                        if !isMe {
                            TextField("host or host:port", text: $endpointHintsDraft)
                                .textFieldStyle(.roundedBorder)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .onAppear { endpointHintsDraft = participant.fipsEndpointHints.joined(separator: ", ") }
                            Button {
                                model.dispatch(
                                    NativeActions.setParticipantEndpointHints(
                                        npub: participant.npub,
                                        endpointHints: endpointHints(from: endpointHintsDraft)
                                    ),
                                    status: "Saving address hints"
                                )
                            } label: {
                                Label("Save hints", systemImage: "network")
                            }
                            .buttonStyle(.bordered)

                            Button {
                                if participant.isAdmin {
                                    model.dispatch(
                                        NativeActions.removeAdmin(networkId: network.id, npub: participant.npub),
                                        status: "Removing admin"
                                    )
                                } else {
                                    model.dispatch(
                                        NativeActions.addAdmin(networkId: network.id, npub: participant.npub),
                                        status: "Granting admin"
                                    )
                                }
                            } label: {
                                Label(participant.isAdmin ? "Remove admin" : "Make admin", systemImage: participant.isAdmin ? "person.fill.badge.minus" : "person.fill.badge.plus")
                            }
                            .buttonStyle(.bordered)

                            Button(role: .destructive) {
                                pendingRemove = true
                            } label: {
                                Label("Remove from network", systemImage: "trash")
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .confirmationDialog(
                        "Remove \(deviceName(participant, state: model.state))?",
                        isPresented: $pendingRemove,
                        titleVisibility: .visible
                    ) {
                        Button("Remove", role: .destructive) {
                            model.dispatch(
                                NativeActions.removeParticipant(networkId: network.id, npub: participant.npub),
                                status: "Removing device"
                            )
                            pendingRemove = false
                        }
                        Button("Cancel", role: .cancel) { pendingRemove = false }
                    } message: {
                        Text("This removes the device from the network's roster. They keep the network locally but won't be in this roster anymore.")
                    }
                }
            }
            .padding()
        }
        .background(AppColors.background)
    }

    private func endpointHints(from value: String) -> [String] {
        value
            .components(separatedBy: CharacterSet(charactersIn: ", \n\r\t"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func labelValueRow(_ label: String, _ value: String, copyable: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            if label == "Device ID" {
                WrappingIdentifierText(
                    value: value,
                    font: .preferredFont(forTextStyle: .callout),
                    color: .label
                )
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text(value)
                    .font(.callout)
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if copyable {
                Button {
                    model.copy(value)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
        }
    }
}

struct AddDeviceCard: View {
    let network: NetworkState
    let add: (String, String) -> Bool
    @State private var deviceId = ""
    @State private var alias = ""

    private var trimmedDeviceId: String {
        deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var deviceIdInvalid: Bool {
        !trimmedDeviceId.isEmpty && !isValidDeviceId(trimmedDeviceId)
    }

    var body: some View {
        AppCard {
            Text("Add by Device ID")
                .font(.headline)
            TextField("Device ID", text: $deviceId)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("manual-admin-joiner-id")
            if deviceIdInvalid {
                Text("Not a valid device ID")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            TextField("Name", text: $alias)
                .textFieldStyle(.roundedBorder)
            Button("Add") {
                if add(trimmedDeviceId, alias) {
                    deviceId = ""
                    alias = ""
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(trimmedDeviceId.isEmpty || deviceIdInvalid)
            .accessibilityIdentifier("manual-admin-submit")
        }
    }
}

struct DeviceSettingsCard: View {
    @ObservedObject var model: AppModel
    @State private var nodeName = ""
    @State private var tunnelIp = ""
    @State private var endpoint = ""
    @State private var port = ""

    var body: some View {
        AppCard {
            Text("This Device")
                .font(.headline)
            VStack(alignment: .leading, spacing: 4) {
                Text("Device ID")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                CopyLine(value: model.state.ownNpub, model: model)
            }
            TextField("Name", text: $nodeName)
                .textFieldStyle(.roundedBorder)
            TextField("Tunnel IP", text: $tunnelIp)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            TextField("Endpoint", text: $endpoint)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            TextField("Listen Port", text: $port)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
            Button("Save") {
                var patch: [String: Any] = [
                    "nodeName": nodeName,
                    "tunnelIp": tunnelIp,
                    "endpoint": endpoint,
                ]
                if let listenPort = Int(port) {
                    patch["listenPort"] = listenPort
                }
                model.dispatch(NativeActions.updateSettings(patch), status: "Saving")
            }
            .buttonStyle(.borderedProminent)
        }
        .onAppear {
            nodeName = model.state.nodeName
            tunnelIp = model.state.tunnelIp
            endpoint = model.state.endpoint
            port = String(model.state.listenPort)
        }
        .onChange(of: model.state.rev) { _, _ in
            nodeName = model.state.nodeName
            tunnelIp = model.state.tunnelIp
            endpoint = model.state.endpoint
            port = String(model.state.listenPort)
        }
    }
}

struct GeneralSettingsCard: View {
    @ObservedObject var model: AppModel

    var body: some View {
        AppCard {
            Text("General")
                .font(.headline)
            Toggle("Start VPN automatically", isOn: Binding(
                get: { model.state.autoconnect },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["autoconnect": value]), status: "Saving")
                }
            ))
            .disabled(model.actionInFlight)
            .accessibilityIdentifier("autoconnect-toggle")
            .accessibilityValue(model.state.autoconnect ? "On" : "Off")
        }
    }
}

struct FipsSettingsCard: View {
    @ObservedObject var model: AppModel

    var body: some View {
        AppCard {
            Text("FIPS")
                .font(.headline)
            Toggle("Connect to non-roster FIPS peers", isOn: Binding(
                get: { model.state.connectToNonRosterFipsPeers },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["connectToNonRosterFipsPeers": value]), status: "Saving")
                }
            ))
            .accessibilityIdentifier("fips-connect-non-roster")
            .accessibilityValue(model.state.connectToNonRosterFipsPeers ? "On" : "Off")
            Toggle("Find peers over Nostr relays", isOn: Binding(
                get: { model.state.fipsNostrDiscoveryEnabled },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["fipsNostrDiscoveryEnabled": value]), status: "Saving")
                }
            ))
            .accessibilityIdentifier("fips-nostr-discovery")
            .accessibilityValue(model.state.fipsNostrDiscoveryEnabled ? "On" : "Off")
            Toggle("Enable WebRTC transport", isOn: Binding(
                get: { model.state.fipsWebrtcEnabled },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["fipsWebrtcEnabled": value]), status: "Saving")
                }
            ))
            .accessibilityIdentifier("fips-webrtc")
            .accessibilityValue(model.state.fipsWebrtcEnabled ? "On" : "Off")
            Toggle("Use bootstrap servers", isOn: Binding(
                get: { model.state.fipsBootstrapEnabled },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["fipsBootstrapEnabled": value]), status: "Saving")
                }
            ))
            .accessibilityIdentifier("fips-bootstrap")
            .accessibilityValue(model.state.fipsBootstrapEnabled ? "On" : "Off")
        }
    }
}

struct PubsubSettingsCard: View {
    @ObservedObject var model: AppModel
    @State private var mode = "relay"
    @State private var fanout = ""
    @State private var maxHops = ""
    @State private var maxEventBytes = ""

    var body: some View {
        AppCard {
            Text("Nostr Pubsub")
                .font(.headline)
            Picker("Mode", selection: $mode) {
                Text("Off").tag("off")
                Text("Client").tag("client")
                Text("Relay").tag("relay")
            }
            .pickerStyle(.segmented)
            TextField("Fanout", text: $fanout)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
            TextField("Hops", text: $maxHops)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
            TextField("Max event bytes", text: $maxEventBytes)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
            Button("Save") {
                var patch: [String: Any] = ["nostrPubsubMode": mode]
                if let fanout = Int(fanout) {
                    patch["nostrPubsubFanout"] = fanout
                }
                if let maxHops = Int(maxHops) {
                    patch["nostrPubsubMaxHops"] = maxHops
                }
                if let maxEventBytes = Int(maxEventBytes) {
                    patch["nostrPubsubMaxEventBytes"] = maxEventBytes
                }
                model.dispatch(NativeActions.updateSettings(patch), status: "Saving")
            }
            .buttonStyle(.borderedProminent)
        }
        .onAppear { sync() }
        .onChange(of: model.state.rev) { _, _ in sync() }
    }

    private func sync() {
        mode = model.state.nostrPubsubMode
        fanout = String(model.state.nostrPubsubFanout)
        maxHops = String(model.state.nostrPubsubMaxHops)
        maxEventBytes = String(model.state.nostrPubsubMaxEventBytes)
    }
}

struct RelaySettingsCard: View {
    @ObservedObject var model: AppModel
    @State private var relayInput = ""

    var body: some View {
        AppCard {
            Text("Relays")
                .font(.headline)
            HStack(spacing: 8) {
                TextField("wss://relay.example.com", text: $relayInput)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                    .submitLabel(.done)
                    .onSubmit { addRelayFromInput() }
                Button {
                    addRelayFromInput()
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderedProminent)
                .disabled(relayInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            VStack(alignment: .leading, spacing: 8) {
                ForEach(model.state.relays) { relay in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(relay.connected ? AppColors.ok : Color.secondary.opacity(0.65))
                            .frame(width: 10, height: 10)
                        Text(relay.url)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .foregroundStyle(relay.enabled ? .primary : .secondary)
                        Spacer(minLength: 8)
                        Toggle("", isOn: Binding(
                            get: { relay.enabled },
                            set: { setRelay(relay.url, enabled: $0) }
                        ))
                        .labelsHidden()
                        Button(role: .destructive) {
                            deleteRelay(relay.url)
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    private func addRelayFromInput() {
        guard let url = normalizedRelayUrl(relayInput) else {
            return
        }
        var lists = relayLists()
        lists.disabled.removeAll { $0 == url }
        if !lists.enabled.contains(url) {
            lists.enabled.append(url)
        }
        saveRelayLists(lists)
        relayInput = ""
    }

    private func setRelay(_ url: String, enabled: Bool) {
        guard let url = normalizedRelayUrl(url) else {
            return
        }
        var lists = relayLists()
        lists.enabled.removeAll { $0 == url }
        lists.disabled.removeAll { $0 == url }
        if enabled {
            lists.enabled.append(url)
        } else {
            lists.disabled.append(url)
        }
        saveRelayLists(lists)
    }

    private func deleteRelay(_ url: String) {
        guard let url = normalizedRelayUrl(url) else {
            return
        }
        var lists = relayLists()
        lists.enabled.removeAll { $0 == url }
        lists.disabled.removeAll { $0 == url }
        saveRelayLists(lists)
    }

    private func relayLists() -> (enabled: [String], disabled: [String]) {
        let enabled = uniqueRelayList(model.state.relays.filter(\.enabled).compactMap { normalizedRelayUrl($0.url) })
        let disabled = uniqueRelayList(model.state.relays.filter { !$0.enabled }.compactMap { normalizedRelayUrl($0.url) })
            .filter { !enabled.contains($0) }
        return (enabled, disabled)
    }

    private func saveRelayLists(_ lists: (enabled: [String], disabled: [String])) {
        let enabled = uniqueRelayList(lists.enabled)
        let disabled = uniqueRelayList(lists.disabled).filter { !enabled.contains($0) }
        model.dispatch(
            NativeActions.updateSettings(["relays": enabled, "disabledRelays": disabled]),
            status: "Saving"
        )
    }

    private func normalizedRelayUrl(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if trimmed.hasPrefix("ws://") || trimmed.hasPrefix("wss://") {
            return trimmed
        }
        return "wss://\(trimmed)"
    }

    private func uniqueRelayList(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}

struct WireGuardSettingsCard: View {
    @ObservedObject var model: AppModel
    @State private var config = ""
    @State private var lastSyncedConfig: String?
    @State private var importingConfig = false
    @FocusState private var configFocused: Bool

    var body: some View {
        AppCard {
            Text("WireGuard Upstream")
                .font(.headline)
            Text("Paste a WireGuard config from an upstream VPN provider such as Mullvad or Proton VPN.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Toggle("Enabled", isOn: Binding(
                get: { model.state.wireguardExitEnabled },
                set: { value in
                    model.dispatch(NativeActions.updateSettings(["wireguardExitEnabled": value]), status: "Saving")
                }
            ))
            .accessibilityIdentifier("wireguard-enabled")
            .accessibilityLabel(
                model.state.wireguardExitEnabled
                    ? "WireGuard upstream on"
                    : "WireGuard upstream off"
            )
            .accessibilityValue(model.state.wireguardExitEnabled ? "On" : "Off")
            TextEditor(text: $config)
                .font(.system(.body, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($configFocused)
                .frame(minHeight: 180)
                .accessibilityIdentifier("wireguard-config")
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.25))
                )
                .toolbar {
                    ToolbarItemGroup(placement: .keyboard) {
                        Spacer()
                        Button("Done") {
                            configFocused = false
                        }
                        .accessibilityIdentifier("wireguard-keyboard-done")
                    }
                }
            HStack {
                Button("Import File") {
                    importingConfig = true
                }
                .buttonStyle(.bordered)
                .disabled(model.actionInFlight)
                .accessibilityIdentifier("wireguard-import")

                Button("Save") {
                    model.dispatch(NativeActions.updateSettings(["wireguardExitConfig": config]), status: "Saving")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.actionInFlight)
                .accessibilityIdentifier("wireguard-save")
            }
        }
        .fileImporter(
            isPresented: $importingConfig,
            allowedContentTypes: [.plainText, .data, .item],
            allowsMultipleSelection: false,
            onCompletion: importConfigFile
        )
        .onAppear {
            syncSavedConfigIfNeeded(force: true)
        }
        .onChange(of: model.state.rev) { _, _ in
            syncSavedConfigIfNeeded()
        }
    }

    private func syncSavedConfigIfNeeded(force: Bool = false) {
        let savedConfig = model.state.wireguardExitConfig
        guard force || savedConfig != lastSyncedConfig else {
            return
        }
        config = savedConfig
        lastSyncedConfig = savedConfig
    }

    private func importConfigFile(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else {
                return
            }
            let didStartAccess = url.startAccessingSecurityScopedResource()
            defer {
                if didStartAccess {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            let imported = try String(contentsOf: url, encoding: .utf8)
            guard !imported.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                model.statusMessage = "Selected WireGuard config is empty."
                return
            }
            config = imported
            model.dispatch(
                NativeActions.updateSettings(["wireguardExitConfig": imported]),
                status: "Importing"
            )
        } catch {
            model.statusMessage = error.localizedDescription
        }
    }
}
