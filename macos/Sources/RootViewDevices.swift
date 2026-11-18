import AppKit
import CoreImage
import SwiftUI

extension RootView {
    func devicesPane(_ network: NativeNetworkState) -> some View {
        HStack(spacing: 0) {
            deviceListColumn(network)
                .frame(minWidth: 290, idealWidth: 330, maxWidth: 360)
            Divider()
            deviceDetailColumn(network)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    var setupPane: some View {
        pageScroll {
            pageTitle("Add Network", "plus.circle")
            Button("Received files") { manager.showReceivedFiles() }
                .buttonStyle(.bordered)
            switch addNetworkMode {
            case nil:
                addNetworkChoiceSection
            case .create:
                addNetworkBackButton
                createNetworkSection
            case .join:
                addNetworkBackButton
                joinNetworkSection(nil)
            }
        }
    }

    var addNetworkChoiceSection: some View {
        surface {
            VStack(alignment: .leading, spacing: 10) {
                Button {
                    addNetworkMode = .create
                } label: {
                    Label("Create Network", systemImage: "plus.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("network-setup-create")

                Button {
                    addNetworkMode = .join
                } label: {
                    Label("Join Network", systemImage: "arrow.down.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .accessibilityIdentifier("manual-join-choose-join")
                .buttonStyle(.borderedProminent)
            }
        }
    }

    var addNetworkBackButton: some View {
        HStack {
            Button {
                addNetworkMode = nil
            } label: {
                Label("Back", systemImage: "chevron.left")
            }
            Spacer()
        }
    }

    func deviceListColumn(_ network: NativeNetworkState) -> some View {
        LocalSearchScope { search in
            deviceListColumn(network, search: search)
        }
    }

    func deviceListColumn(_ network: NativeNetworkState, search: Binding<String>) -> some View {
        let showSearch = sortedParticipants(network).count > searchVisibilityThreshold
        return VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Devices")
                            .font(.system(size: 24, weight: .semibold))
                        Text(deviceAvailabilityText(network))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    deviceHeaderActions(network)
                }
                if showSearch {
                    TextField("Search", text: search)
                        .textFieldStyle(.roundedBorder)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 24)
            .padding(.bottom, 4)

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    FileTransfersView(manager: manager)
                    let activeSearch = showSearch ? search.wrappedValue : ""
                    let participants = visibleParticipants(network, search: activeSearch)
                    let selectedPubkeyHex = selectedParticipant(in: network)?.pubkeyHex
                    if participants.isEmpty {
                        emptyRow(
                            activeSearch.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                ? "No devices"
                                : "No matching devices",
                            systemImage: "circle.dotted"
                        )
                    } else {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(displayName(network))
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .padding(.horizontal, 10)
                            ForEach(participants, id: \.pubkeyHex) { participant in
                                deviceListRow(
                                    participant,
                                    network: network,
                                    selected: selectedPubkeyHex == participant.pubkeyHex
                                )
                            }
                        }
                    }

                }
                .padding(.horizontal, 12)
                .padding(.bottom, 24)
            }
        }
    }

    func deviceHeaderActions(_ network: NativeNetworkState) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 8) {
                activateNetworkButton(network)
                addDeviceButton(network)
            }
            HStack(spacing: 8) {
                activateNetworkButton(network, compact: true)
                addDeviceButton(network, compact: true)
            }
        }
    }

    @ViewBuilder
    func activateNetworkButton(_ network: NativeNetworkState, compact: Bool = false) -> some View {
        if !network.enabled {
            Button {
                activateNetwork(network)
            } label: {
                if compact {
                    Image(systemName: "checkmark.circle.fill")
                } else {
                    Label("Activate", systemImage: "checkmark.circle.fill")
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(manager.actionInFlight)
            .help("Activate this network")
        }
    }

    @ViewBuilder
    func addDeviceButton(_ network: NativeNetworkState, compact: Bool = false) -> some View {
        if network.localIsAdmin {
            Button {
                addDevicePresented = true
            } label: {
                if compact {
                    Image(systemName: "person.badge.plus")
                } else {
                    Label("Link device", systemImage: "person.badge.plus")
                }
            }
            .controlSize(.small)
            .accessibilityIdentifier("manual-join-admin-open")
            .disabled(!network.enabled)
            .help(network.enabled ? "Link device to this network" : "Activate this network first")
        }
    }

    func deviceListRow(
        _ participant: NativeParticipantState,
        network: NativeNetworkState,
        selected: Bool
    ) -> some View {
        Button {
            selectedDevicePubkeyHex = participant.pubkeyHex
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    connectivityDot(participant, size: 8)
                    Text(deviceName(participant))
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    if isSelf(participant) {
                        badge("This device", style: selected ? .selected : .ok)
                    }
                    if !participant.rosterAccepted && !isSelf(participant) {
                        badge("Joining", style: selected ? .selected : .warn)
                    }
                    if participant.isAdmin {
                        badge("Admin", style: selected ? .selected : .muted)
                    }
                    if participant.offersExitNode {
                        badge(exitNodeBadgeText(participant), style: selected ? .selected : exitNodeBadgeStyle(participant))
                    }
                    if isFipsRouted(participant) {
                        badge("via mesh", style: selected ? .selected : .muted)
                    }
                }
                HStack(spacing: 6) {
                    if !deviceSubtitle(participant).isEmpty {
                        Text(deviceSubtitle(participant))
                    }
                    if !cleanIp(participant.tunnelIp).isEmpty {
                        Text(cleanIp(participant.tunnelIp))
                    }
                }
                .font(.caption)
                .foregroundStyle(selected ? Color.white.opacity(0.78) : Color.secondary)
                .lineLimit(1)
            }
            .foregroundStyle(selected ? Color.white : Color.primary)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                selected ? Color.accentColor : Color.clear,
                in: RoundedRectangle(cornerRadius: 7)
            )
            .contentShape(Rectangle())
        }
        .accessibilityIdentifier(
            "roster-participant-\(participant.rosterAccepted ? "accepted" : "pending")-\(participant.npub)"
        )
        .buttonStyle(.plain)
    }

    func deviceDetailColumn(_ network: NativeNetworkState) -> some View {
        ScrollView {
            if let participant = selectedParticipant(in: network) {
                VStack(alignment: .leading, spacing: 22) {
                    deviceDetailHeader(participant, network: network)
                    if !isSelf(participant) {
                        Button { manager.chooseFiles(to: participant.npub) } label: {
                            Label("Send files", systemImage: "paperplane.fill")
                        }
                        .disabled(!manager.state.vpnActive || !network.enabled || !participant.reachable || manager.actionInFlight)
                        .help(manager.state.vpnActive ? "Send files to this device" : "Connect VPN to send files")
                    }
                    if network.localIsAdmin {
                        deviceAdminSection(participant, network: network)
                    }
                    deviceAddressesSection(participant)
                    deviceConnectivitySection(participant)
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
                .padding(.bottom, 30)
                .frame(maxWidth: 640, alignment: .topLeading)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Devices")
                        .font(.system(size: 24, weight: .semibold))
                    emptyRow("No devices yet", systemImage: "circle.dotted")
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    func deviceDetailHeader(_ participant: NativeParticipantState, network: NativeNetworkState) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(deviceName(participant))
                        .font(.system(size: 24, weight: .semibold))
                        .lineLimit(2)
                    if isSelf(participant) || participant.isAdmin || participant.offersExitNode || participant.reachable {
                        HStack(spacing: 6) {
                            if isSelf(participant) {
                                badge("This device", style: .ok)
                            }
                            if participant.isAdmin {
                                badge("Admin", style: .muted)
                            }
                            if participant.offersExitNode {
                                badge(exitNodeBadgeText(participant), style: exitNodeBadgeStyle(participant))
                            }
                            if isDirectFipsPeer(participant) {
                                badge("direct connection", style: .ok)
                            } else if isFipsRouted(participant) {
                                badge("via mesh", style: .muted)
                            }
                        }
                    }
                }
                Spacer()
                HStack(spacing: 7) {
                    connectivityDot(participant, size: 8)
                    Text(deviceStatusText(participant))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    func deviceAdminSection(_ participant: NativeParticipantState, network: NativeNetworkState) -> some View {
        surface {
            sectionHeader("Manage Device", systemImage: "person.badge.key")

            SyncedTextFieldRow(
                title: "Name",
                placeholder: "Name",
                identity: participant.pubkeyHex,
                value: participant.magicDnsAlias,
                systemImage: "checkmark",
                disabled: manager.actionInFlight
            ) { draft in
                manager.setParticipantAlias(
                    npub: participant.npub,
                    alias: draft
                )
            }

            if !isSelf(participant) {
                SyncedTextFieldRow(
                    title: "Hints",
                    placeholder: "host or host:port",
                    identity: participant.pubkeyHex,
                    value: participant.fipsEndpointHints.joined(separator: ", "),
                    systemImage: "network",
                    disabled: manager.actionInFlight
                ) { draft in
                    manager.setParticipantEndpointHints(
                        npub: participant.npub,
                        endpointHints: endpointHints(from: draft)
                    )
                }
                deviceActionButtons(participant, network: network)
            }
        }
    }

    func deviceAddressesSection(_ participant: NativeParticipantState) -> some View {
        surface {
            Text("Addresses")
                .font(.headline)
            detailValueRow("MagicDNS", deviceMagicDnsName(participant))
            detailValueRow("VPN IP", cleanIp(participant.tunnelIp))
            detailValueRow("Device ID", participant.npub)
        }
    }

    func deviceConnectivitySection(_ participant: NativeParticipantState) -> some View {
        surface {
            Text("Connectivity")
                .font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 130), alignment: .leading)], alignment: .leading, spacing: 12) {
                metric("Role", deviceRoleText(participant))
                metric("State", deviceStatusText(participant))
                metric("FIPS path", fipsPathText(participant))
                metric("Latency age", participant.fipsSrttAgeMs == 0 ? "-" : formatDurationMs(participant.fipsSrttAgeMs))
                metric("Control seen", participant.lastFipsControlSeenText.isEmpty ? "-" : participant.lastFipsControlSeenText)
                metric("Data seen", participant.lastFipsDataSeenText.isEmpty ? "-" : participant.lastFipsDataSeenText)
                metric("Address hints", participant.fipsEndpointHints.isEmpty ? "-" : participant.fipsEndpointHints.joined(separator: ", "))
                metric("Last seen", participant.lastSeenText.isEmpty ? "-" : participant.lastSeenText)
                metric("Sent", formatBytes(participant.txBytes))
                metric("Received", formatBytes(participant.rxBytes))
            }
            if !participant.statusText.isEmpty {
                Text(participant.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    func deviceActionButtons(_ participant: NativeParticipantState, network: NativeNetworkState) -> some View {
        HStack(spacing: 6) {
            Button {
                manager.toggleAdmin(networkId: network.id, participant: participant)
            } label: {
                Label(
                    participant.isAdmin ? "Remove admin" : "Make admin",
                    systemImage: participant.isAdmin ? "star.slash" : "star"
                )
            }
            .disabled(manager.actionInFlight)
            .help(participant.isAdmin ? "Remove admin" : "Make admin")
            Button(role: .destructive) {
                pendingParticipantRemoval = PendingParticipantRemoval(
                    networkId: network.id,
                    npub: participant.npub,
                    deviceName: deviceName(participant)
                )
            } label: {
                Label("Remove", systemImage: "trash")
            }
            .disabled(isSelf(participant) || manager.actionInFlight)
            .help("Remove device")
        }
        .controlSize(.small)
        .confirmationDialog(
            "Remove \(pendingParticipantRemoval?.deviceName ?? "device")?",
            isPresented: Binding(
                get: { pendingParticipantRemoval != nil },
                set: { if !$0 { pendingParticipantRemoval = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingParticipantRemoval
        ) { target in
            Button("Remove", role: .destructive) {
                manager.removeParticipant(networkId: target.networkId, npub: target.npub)
                pendingParticipantRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingParticipantRemoval = nil }
        } message: { _ in
            Text("This removes the device from the network's roster. They keep the network locally but won't be in this roster anymore.")
        }
    }

    func detailValueRow(
        _ title: String,
        _ value: String,
        displayValue customDisplayValue: String? = nil,
        accessibilityIdentifier: String? = nil
    ) -> some View {
        let displayValue = value.isEmpty ? "-" : customDisplayValue ?? value
        return VStack(alignment: .leading, spacing: 4) {
            if value.hasPrefix("npub1") {
                WrappingIdentifierText(
                    value: displayValue,
                    font: .preferredFont(forTextStyle: .subheadline),
                    color: .labelColor
                )
            } else {
                Text(displayValue)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            HStack(spacing: 6) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if !value.isEmpty {
                    Button {
                        manager.copy(value)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy")
                }
            }
        }
        .padding(.vertical, 3)
        .accessibilityIdentifier(accessibilityIdentifier ?? "")
        .accessibilityLabel(value)
    }

    func joinRequestInputSection(_ network: NativeNetworkState) -> some View {
        return surface {
            sectionHeader("Add Join Request", systemImage: "camera.viewfinder")
            Text("Scan the joining device's request QR, or paste its join request. Valid links open confirmation automatically.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                Button {
                    scanningJoinRequest = true
                    showingQrScanner = true
                } label: {
                    Label("Scan QR", systemImage: "camera.viewfinder")
                }
                .disabled(manager.actionInFlight)
                TextField("nvpn://join-request/…", text: $joinRequestInput)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: joinRequestInput) { _, value in
                        stageJoinRequest(value, network: network)
                    }
            }
        }
    }

    func stageJoinRequest(_ value: String, network: NativeNetworkState) {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard looksLikeJoinRequestQrOrLink(trimmed) else { return }
        pendingJoinRequest = PendingJoinRequest(
            networkId: network.id,
            networkName: network.name.isEmpty ? "this network" : network.name,
            request: trimmed
        )
    }

    var createNetworkSection: some View {
        surface {
            sectionHeader("Create Network", systemImage: "plus.circle")
            HStack(spacing: 8) {
                TextField("Network name", text: $networkNameInput)
                    .accessibilityIdentifier("network-create-name")
                    .onSubmit {
                        addNetwork { added in
                            if added {
                                finishCreateNetwork()
                            }
                        }
                    }
                Button {
                    addNetwork(defaultName: "My Network") { added in
                        if added {
                            finishCreateNetwork()
                        }
                    }
                } label: {
                    Label("Create", systemImage: "plus")
                }
                .disabled(manager.actionInFlight)
                .accessibilityIdentifier("network-create-submit")
            }
        }
    }

    /// Land on the new network's Devices view right after Create. The
    /// sidebar may have been on Routing/Settings; from the Add Network
    /// sheet we also have to dismiss. Both are no-ops if already in the
    /// target state.
    func finishCreateNetwork() {
        shownNetworkId = manager.activeNetwork?.id
        addNetworkPresented = false
        selectedSidebarItem = .devices
    }

    func joinNetworkSection(_ network: NativeNetworkState?) -> some View {
        let requestNetwork = network ?? state.networks.first { candidate in
            !candidate.joinRequestQrCodeOrLink.isEmpty
        }
        let joinRequestQrCodeOrLink: String
        if state.joinRequestQrCodeOrLink.isEmpty {
            joinRequestQrCodeOrLink = requestNetwork?.joinRequestQrCodeOrLink ?? ""
        } else {
            joinRequestQrCodeOrLink = state.joinRequestQrCodeOrLink
        }
        return surface {
            sectionHeader("Join Network", systemImage: "arrow.down.circle")
            if !joinRequestQrCodeOrLink.isEmpty {
                QrCodeView(text: joinRequestQrCodeOrLink)
                    .frame(width: 220, height: 220)
                    .frame(maxWidth: .infinity, alignment: .center)
                HStack(spacing: 8) {
                    Button {
                        manager.copy(joinRequestQrCodeOrLink)
                    } label: {
                        Label("Copy Request", systemImage: "doc.on.doc")
                    }
                    Button {
                        manager.share(joinRequestQrCodeOrLink)
                    } label: {
                        Label("Share", systemImage: "square.and.arrow.up")
                    }
                }
                .disabled(manager.actionInFlight)
                detailValueRow(
                    "Your Device ID",
                    state.ownNpub,
                    accessibilityIdentifier: "joiner-device-id-value"
                )
            }

            DisclosureGroup(isExpanded: $manualJoinExpanded) {
                manualJoinFields
                    .padding(.top, 6)
            } label: {
                Text("Manual join")
                    .accessibilityIdentifier("manual-join-expander")
            }

        }
    }

    var manualJoinFields: some View {
        let admin = manualJoinAdminId.trimmingCharacters(in: .whitespacesAndNewlines)
        let mesh = normalizeNetworkIdInput(manualJoinMeshId)
        let invalid = !admin.isEmpty && !isValidDeviceId(admin)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Give the admin your Device ID. Enter their Device ID and Network ID here; they must add your Device ID too.")
                .font(.caption)
                .foregroundStyle(.secondary)
            detailValueRow(
                "Your Device ID",
                state.ownNpub,
                accessibilityIdentifier: "joiner-device-id-value"
            )
            TextField("Admin Device ID", text: $manualJoinAdminId)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("manual-join-admin-id")
            if invalid {
                Text("Not a valid device ID")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            TextField("Network ID", text: $manualJoinMeshId)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("manual-join-network-id")
            Button("Add manually") {
                manager.manualAddNetwork(adminNpub: admin, meshNetworkId: mesh) { added in
                    guard added else { return }
                    manualJoinAdminId = ""
                    manualJoinMeshId = ""
                    manualJoinExpanded = false
                    finishCreateNetwork()
                }
            }
            .accessibilityIdentifier("manual-join-submit")
            .disabled(admin.isEmpty || mesh.isEmpty || invalid || manager.actionInFlight)
        }
    }

    func manualAdminSection(_ network: NativeNetworkState) -> some View {
        let deviceId = manualJoinDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        let invalid = !deviceId.isEmpty && !isValidDeviceId(deviceId)
        return surface {
            sectionHeader("For Manual Join", systemImage: "person.2.badge.gearshape")
            Text("Share these values with the joining device, then add its Device ID below.")
                .font(.caption)
                .foregroundStyle(.secondary)
            detailValueRow(
                "Admin Device ID",
                state.ownNpub,
                accessibilityIdentifier: "admin-device-id-value"
            )
            detailValueRow(
                "Network ID",
                network.networkId,
                displayValue: displayNetworkId(network.networkId),
                accessibilityIdentifier: "admin-network-id-value"
            )
            TextField("Joining Device ID", text: $manualJoinDeviceId)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("manual-join-admin-device-id")
            if invalid {
                Text("Not a valid device ID")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            TextField("Name", text: $manualJoinDeviceName)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("manual-join-admin-device-name")
            Button("Add by Device ID") {
                manager.addParticipant(
                    networkId: network.id,
                    npub: deviceId,
                    alias: manualJoinDeviceName
                ) { added in
                    guard added else { return }
                    manualJoinDeviceId = ""
                    manualJoinDeviceName = ""
                    addDevicePresented = false
                    selectedSidebarItem = .devices
                }
            }
            .accessibilityIdentifier("manual-join-admin-submit")
            .disabled(deviceId.isEmpty || invalid || manager.actionInFlight)
        }
    }

}
