import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct DevicesPage: View {
    @ObservedObject var model: AppModel
    let network: NetworkState?
    @State private var addDevicePresented = false
    @State private var pendingNetworkRemoval: NetworkState?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                FileTransfersCard(model: model)
                if !model.state.error.isEmpty || shouldShowStatusNotice(model.statusMessage) {
                    NoticeCard(
                        text: model.state.error.isEmpty ? model.statusMessage : model.state.error,
                        actionTitle: nil,
                        action: {}
                    )
                }
                if let network {
                    if !network.enabled {
                        Button {
                            model.dispatch(
                                NativeActions.setNetworkEnabled(network.id, true),
                                status: "Activating network"
                            )
                        } label: {
                            Label("Activate Network", systemImage: "checkmark.circle.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.actionInFlight)
                    }
                    if network.localIsAdmin {
                        Button {
                            addDevicePresented = true
                        } label: {
                            Label("Link device", systemImage: "person.badge.plus")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!network.enabled)
                        .accessibilityIdentifier("link-device-open")
                    }
                    ForEach(sortedParticipants(network.participants, state: model.state)) { participant in
                        ParticipantRow(model: model, network: network, participant: participant)
                    }
                    Button(role: .destructive) {
                        pendingNetworkRemoval = network
                    } label: {
                        Label("Delete network", systemImage: "trash")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .padding(.top, 8)
                } else {
                    NoticeCard(text: "No network")
                }
            }
            .padding()
        }
        .scrollIndicators(.hidden)
        .safeAreaPadding(.bottom, 92)
        .background(AppColors.background)
        .sheet(isPresented: $addDevicePresented) {
            if let network {
                NavigationStack {
                    AddDeviceSheet(model: model, network: network)
                        .navigationTitle("Link Device")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Done") {
                                    addDevicePresented = false
                                }
                            }
                        }
                }
            }
        }
        .confirmationDialog(
            "Delete \(pendingNetworkRemoval?.displayName ?? "network")?",
            isPresented: Binding(
                get: { pendingNetworkRemoval != nil },
                set: { if !$0 { pendingNetworkRemoval = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingNetworkRemoval
        ) { network in
            Button("Delete", role: .destructive) {
                model.dispatch(NativeActions.removeNetwork(network.id), status: "Deleting network")
                pendingNetworkRemoval = nil
            }
            Button("Cancel", role: .cancel) { pendingNetworkRemoval = nil }
        } message: { _ in
            Text("Removes the network from this device. You can link it again later.")
        }
    }

    private func shouldShowStatusNotice(_ message: String) -> Bool {
        !message.isEmpty && message != AppModel.vpnDisclosurePromptMessage
    }

}
struct ToolbarVpnSwitch: View {
    @ObservedObject var model: AppModel
    let vpnDisclosureAccepted: Bool
    let onReviewVpnDisclosure: () -> Void

    private var enabled: Bool {
        !model.actionInFlight && model.state.vpnControlSupported && model.activeNetwork != nil
    }

    var body: some View {
        Button {
            if !model.state.vpnEnabled && !vpnDisclosureAccepted {
                model.requireVpnDisclosureReview()
                onReviewVpnDisclosure()
            } else {
                model.toggleVpn()
            }
        } label: {
            ZStack(alignment: model.state.vpnEnabled ? .trailing : .leading) {
                Capsule()
                    .fill(model.state.vpnEnabled ? AppColors.accent : Color.gray.opacity(0.24))
                    .frame(width: 48, height: 28)
                Circle()
                    .fill(Color.white)
                    .frame(width: 24, height: 24)
                    .shadow(color: .black.opacity(0.22), radius: 1, y: 1)
                    .padding(2)
            }
            .frame(width: 48, height: 28)
            .contentShape(Capsule())
            .opacity(enabled ? 1 : 0.55)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityIdentifier("vpn-toggle")
        .accessibilityLabel(model.state.vpnEnabled ? "Turn VPN off" : "Turn VPN on")
        .accessibilityValue(model.state.vpnEnabled ? "On" : "Off")
    }
}

struct VpnDisclosureSheet: View {
    let acknowledge: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Before Turning VPN On")
                        .font(.title2.weight(.semibold))
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("Nostr VPN is a private mesh VPN for your own devices, trusted peers, and WireGuard endpoints you configure. It is not a public VPN, anonymity, stealth, or consumer proxy service.")
                    Text("The app processes device identity, peer lists, routing settings, endpoints, join metadata, traffic counters, and connection health on this device only to operate the VPN you configure.")
                    Text("Sirius Business Oy does not collect or retain your browsing traffic, private mesh traffic, VPN connection data, or DNS queries, and does not sell, use, or disclose VPN data to third parties.")
                    Text("Packet traffic is encrypted. At your direction, the app sends only the data needed for the requested connection to peers, relays, bridge paths, and WireGuard endpoints you choose. Independent operators handle that data under their own policies.")
                    Text("Exit DNS can use DNS from your WireGuard profile, Cloudflare encrypted DNS as the Automatic fallback, Quad9, a custom encrypted DNS service, or DNS servers you configure through the exit. Those independently operated DNS services can receive your DNS queries and ordinary connection metadata, such as your IP address and request time, under their own policies.")
                }
                .font(.body)
                .foregroundStyle(.primary)
                .padding()
            }
            .navigationTitle("VPN Data Use")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", action: acknowledge)
                        .fontWeight(.semibold)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

struct CreateNetworkCard: View {
    @ObservedObject var model: AppModel
    var onCreated: ((String) -> Void)? = nil
    @State private var networkName = "My Network"

    var body: some View {
        SetupCard(title: "Create Network", systemImage: "plus.circle.fill", tint: AppColors.create) {
            VStack(alignment: .leading, spacing: 10) {
                TextField("Network name", text: $networkName)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("network-create-name")
                Button {
                    let name = networkName.trimmingCharacters(in: .whitespacesAndNewlines)
                    let created = model.dispatch(
                        NativeActions.addNetwork(name.isEmpty ? "My Network" : name),
                        status: "Creating network"
                    )
                    if created, let networkId = model.activeNetwork?.id {
                        networkName = "My Network"
                        onCreated?(networkId)
                    }
                } label: {
                    Label("Create", systemImage: "plus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.actionInFlight)
                .accessibilityIdentifier("network-create-submit")
            }
        }
    }
}

struct JoinNetworkCard: View {
    @ObservedObject var model: AppModel
    var onCreated: ((String) -> Void)? = nil
    @State private var manualExpanded = false
    @State private var manualAdminId = ""
    @State private var manualNetworkId = ""

    private var manualAdminInvalid: Bool {
        let value = manualAdminId.trimmingCharacters(in: .whitespacesAndNewlines)
        return !value.isEmpty && !isValidDeviceId(value)
    }

    private var requestNetwork: NetworkState? {
        model.activeNetwork ?? model.state.networks.first { network in
            !network.joinRequestQrCodeOrLink.isEmpty
        }
    }

    private var joinRequestQrCodeOrLink: String {
        if !model.state.joinRequestQrCodeOrLink.isEmpty {
            return model.state.joinRequestQrCodeOrLink
        }
        return requestNetwork?.joinRequestQrCodeOrLink ?? ""
    }

    var body: some View {
        SetupCard(title: "Join Network", systemImage: "arrow.down.circle.fill", tint: AppColors.join) {
            if !joinRequestQrCodeOrLink.isEmpty {
                Pill("Join request", tint: .orange)
                VStack(alignment: .leading, spacing: 8) {
                    GeometryReader { geometry in
                        QrCodeView(matrix: model.qrMatrix(for: joinRequestQrCodeOrLink))
                            .frame(width: geometry.size.width, height: geometry.size.width)
                            .accessibilityIdentifier("join-request-qr")
                    }
                    .aspectRatio(1, contentMode: .fit)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("join-request-qr-content")
                    HStack(spacing: 10) {
                        Button {
                            model.copy(joinRequestQrCodeOrLink)
                        } label: {
                            Label("Copy Request", systemImage: model.copiedValue == joinRequestQrCodeOrLink ? "checkmark" : "doc.on.doc")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        if let requestUrl = URL(string: joinRequestQrCodeOrLink) {
                            ShareLink(item: requestUrl) {
                                Label("Share", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                }
            }

            DisclosureGroup(isExpanded: $manualExpanded) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Give the admin your Device ID. Enter their Device ID and Network ID here; they must add your Device ID too.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    CopyLine(
                        value: model.state.ownNpub,
                        valueAccessibilityIdentifier: "joiner-device-id-value",
                        model: model
                    )
                    TextField("Admin Device ID", text: $manualAdminId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("manual-join-admin-id")
                    if manualAdminInvalid {
                        Text("Not a valid device ID")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                    TextField("Network ID", text: $manualNetworkId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("manual-join-network-id")
                    Button("Add manually") {
                        let added = model.dispatch(
                            NativeActions.manualAddNetwork(
                                adminNpub: manualAdminId.trimmingCharacters(in: .whitespacesAndNewlines),
                                meshNetworkId: normalizeNetworkIdInput(manualNetworkId)
                            ),
                            status: "Adding network"
                        )
                        if added {
                            manualAdminId = ""
                            manualNetworkId = ""
                            manualExpanded = false
                            if let networkId = model.activeNetwork?.id {
                                onCreated?(networkId)
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("manual-join-submit")
                    .disabled(
                        manualAdminId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || normalizeNetworkIdInput(manualNetworkId).isEmpty
                            || manualAdminInvalid
                    )
                }
                .padding(.top, 6)
            } label: {
                Text("Manual join")
                    .accessibilityIdentifier("manual-join-expand")
            }
            .font(.subheadline)

        }
    }
}

/// Admin-only sheet for approving a joining device's signed join request.
struct AddDeviceSheet: View {
    @ObservedObject var model: AppModel
    let network: NetworkState
    @Environment(\.dismiss) private var dismiss
    @State private var qrScannerPresented = false
    @State private var scannedQrCode: String?
    @State private var scanError = ""
    @State private var joinRequestInput = ""
    @State private var pendingJoinRequest: PendingJoinRequest?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 14) {
                if !model.state.error.isEmpty {
                    NoticeCard(text: model.state.error)
                }
                ScanJoinerDeviceCard(
                    requestInput: $joinRequestInput,
                    scanError: scanError,
                    scan: { qrScannerPresented = true },
                    paste: {
                        if let text = UIPasteboard.general.string {
                            importJoinerValue(text)
                        }
                    },
                    inputChanged: { value in
                        stageJoinRequest(value)
                    }
                )
                ManualPairingInfoCard(model: model, network: network)
                AddDeviceCard(network: network) { npub, alias in
                    let added = model.dispatch(
                        NativeActions.addParticipant(networkId: network.id, npub: npub, alias: alias),
                        status: "Adding device"
                    )
                    if added {
                        dismiss()
                    }
                    return added
                }
            }
            .padding()
        }
        .safeAreaPadding(.bottom, 92)
        .background(AppColors.background)
        .sheet(isPresented: $qrScannerPresented, onDismiss: qrScannerDismissed) {
            QRCodeScannerSheet { code in
                scannedQrCode = code
                qrScannerPresented = false
            }
        }
        .alert("Add device?", isPresented: pendingJoinRequestPresented, presenting: pendingJoinRequest) { pending in
            Button("Cancel", role: .cancel) {
                pendingJoinRequest = nil
            }
            Button("Add") {
                if model.dispatch(NativeActions.importJoinRequest(pending.request), status: "Adding device") {
                    joinRequestInput = ""
                    pendingJoinRequest = nil
                    dismiss()
                }
            }
            .accessibilityIdentifier("join-request-confirm-add")
        } message: { pending in
            Text("Add the device from this join request to \(pending.networkName)?")
        }
    }

    private var pendingJoinRequestPresented: Binding<Bool> {
        Binding(
            get: { pendingJoinRequest != nil },
            set: { presented in
                if !presented {
                    pendingJoinRequest = nil
                }
            }
        )
    }

    private func qrScannerDismissed() {
        guard let code = scannedQrCode else {
            return
        }
        scannedQrCode = nil
        DispatchQueue.main.async {
            handleScannedJoinerCode(code)
        }
    }

    private func importJoinerValue(_ value: String) {
        let request = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !request.isEmpty else { return }
        if looksLikeJoinRequestQrOrLink(request) {
            stageJoinRequest(request)
            return
        }
        scanError = "Not a Nostr VPN join request."
    }

    private func handleScannedJoinerCode(_ value: String) {
        if looksLikeJoinRequestQrOrLink(value) {
            stageJoinRequest(value)
            return
        }
        scanError = "Not a Nostr VPN join request."
    }

    private func stageJoinRequest(_ value: String) {
        let request = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard looksLikeJoinRequestQrOrLink(request) else { return }
        scanError = ""
        pendingJoinRequest = PendingJoinRequest(
            networkName: network.name.isEmpty ? "this network" : network.name,
            request: request
        )
    }
}

struct ManualPairingInfoCard: View {
    @ObservedObject var model: AppModel
    let network: NetworkState

    var body: some View {
        AppCard {
            Text("For manual join")
                .font(.headline)
            Text("Share these values with the joining device, then add its Device ID below.")
                .font(.caption)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text("Admin Device ID")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                CopyLine(
                    value: model.state.ownNpub,
                    valueAccessibilityIdentifier: "admin-device-id-value",
                    model: model
                )
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Network ID")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                CopyLine(
                    value: network.networkId,
                    displayValue: displayNetworkId(network.networkId),
                    valueAccessibilityIdentifier: "admin-network-id-value",
                    model: model
                )
            }
        }
    }
}

struct ScanJoinerDeviceCard: View {
    @Binding var requestInput: String
    let scanError: String
    let scan: () -> Void
    let paste: () -> Void
    let inputChanged: (String) -> Void

    var body: some View {
        AppCard {
            Text("Add join request")
                .font(.headline)
            Text("Scan or paste the joining device's join request. Valid links open confirmation automatically.")
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("Join request", text: $requestInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
                .onChange(of: requestInput) { _, value in
                    inputChanged(value)
                }
            Button(action: paste) {
                Label("Paste", systemImage: "doc.on.clipboard")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            Button(action: scan) {
                Label("Scan QR", systemImage: "camera.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("join-request-scan-open")
            if !scanError.isEmpty {
                Text(scanError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }
}
