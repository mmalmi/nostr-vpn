import AppKit
import CoreImage
import SwiftUI

extension RootView {
    func surface<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            content()
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    func sectionHeader(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.headline)
    }

    func emptyRow(_ text: String, systemImage: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
            Text(text)
        }
        .foregroundStyle(.secondary)
        .font(.subheadline)
        .padding(.vertical, 6)
    }

    func label(_ text: String) -> some View {
        Text(text)
            .foregroundStyle(.secondary)
            .frame(width: 86, alignment: .leading)
    }

    func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value.isEmpty ? "-" : value)
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    func badge(_ text: String, style: BadgeStyle) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .foregroundStyle(style.foreground)
            .background(style.background, in: RoundedRectangle(cornerRadius: 6))
    }

    func copyButton(
        value: String,
        copied: CopyValue,
        peerNpub: String? = nil,
        systemImage: String
    ) -> some View {
        Button {
            manager.copy(value, as: copied, peerNpub: peerNpub)
        } label: {
            Image(systemName: copyIndicator(copied, peerNpub: peerNpub) ? "checkmark" : systemImage)
        }
        .buttonStyle(.borderless)
    }

    func copyIndicator(_ copied: CopyValue, peerNpub: String?) -> Bool {
        manager.copiedValue == copied && (copied != .peerNpub || manager.copiedPeerNpub == peerNpub)
    }

    func networkNameBinding(_ network: NativeNetworkState) -> Binding<String> {
        Binding(
            get: { networkNameDrafts[network.id] ?? network.name },
            set: { networkNameDrafts[network.id] = $0 }
        )
    }

    func activateNetwork(_ network: NativeNetworkState) {
        guard !network.enabled else { return }
        shownNetworkId = network.id
        manager.setNetworkEnabled(networkId: network.id, enabled: true)
    }

    func endpointHints(from value: String) -> [String] {
        value
            .components(separatedBy: CharacterSet(charactersIn: ", \n\r\t"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    func addNetwork(defaultName: String = "", completion: ((Bool) -> Void)? = nil) {
        let name = networkNameInput.trimmingCharacters(in: .whitespacesAndNewlines)
        manager.addNetwork(name.isEmpty ? defaultName : name) { added in
            if added {
                networkNameInput = ""
                shownNetworkId = manager.activeNetwork?.id
            }
            completion?(added)
        }
    }

    func syncDrafts() {
        if let shownNetworkId,
           !state.networks.contains(where: { $0.id == shownNetworkId }) {
            self.shownNetworkId = nil
        }
        if state.nodeName != lastSyncedNodeName {
            nodeName = state.nodeName
            lastSyncedNodeName = state.nodeName
        }
        if state.endpoint != lastSyncedEndpoint {
            endpoint = state.endpoint
            lastSyncedEndpoint = state.endpoint
        }
        if state.tunnelIp != lastSyncedTunnelIp {
            tunnelIp = state.tunnelIp
            lastSyncedTunnelIp = state.tunnelIp
        }
        if state.listenPort != lastSyncedListenPort {
            listenPort = String(state.listenPort)
            lastSyncedListenPort = state.listenPort
        }
        if state.fipsHostInboundTcpPorts != lastSyncedFipsHostInboundTcpPorts {
            fipsHostInboundTcpPorts = state.fipsHostInboundTcpPorts
            lastSyncedFipsHostInboundTcpPorts = state.fipsHostInboundTcpPorts
        }
        if state.nostrPubsubMode != lastSyncedNostrPubsubMode {
            nostrPubsubMode = state.nostrPubsubMode
            lastSyncedNostrPubsubMode = state.nostrPubsubMode
        }
        if state.nostrPubsubFanout != lastSyncedNostrPubsubFanout {
            nostrPubsubFanout = String(state.nostrPubsubFanout)
            lastSyncedNostrPubsubFanout = state.nostrPubsubFanout
        }
        if state.nostrPubsubMaxHops != lastSyncedNostrPubsubMaxHops {
            nostrPubsubMaxHops = String(state.nostrPubsubMaxHops)
            lastSyncedNostrPubsubMaxHops = state.nostrPubsubMaxHops
        }
        if state.nostrPubsubMaxEventBytes != lastSyncedNostrPubsubMaxEventBytes {
            nostrPubsubMaxEventBytes = String(state.nostrPubsubMaxEventBytes)
            lastSyncedNostrPubsubMaxEventBytes = state.nostrPubsubMaxEventBytes
        }
        if lastSyncedWireguardExitConfig != state.wireguardExitConfig {
            wireguardExitConfig = state.wireguardExitConfig
            lastSyncedWireguardExitConfig = state.wireguardExitConfig
        }
        if lastSyncedExitDnsMode != state.exitDnsMode {
            exitDnsMode = state.exitDnsMode
            lastSyncedExitDnsMode = state.exitDnsMode
        }
        if lastSyncedExitDnsDohProvider != state.exitDnsDohProvider {
            exitDnsDohProvider = state.exitDnsDohProvider
            lastSyncedExitDnsDohProvider = state.exitDnsDohProvider
        }
        if lastSyncedExitDnsCustomDohUrl != state.exitDnsCustomDohUrl {
            exitDnsCustomDohUrl = state.exitDnsCustomDohUrl
            lastSyncedExitDnsCustomDohUrl = state.exitDnsCustomDohUrl
        }
        if lastSyncedExitDnsCustomDohBootstrapIps != state.exitDnsCustomDohBootstrapIps {
            exitDnsCustomDohBootstrapIps = state.exitDnsCustomDohBootstrapIps
            lastSyncedExitDnsCustomDohBootstrapIps = state.exitDnsCustomDohBootstrapIps
        }
        if lastSyncedExitDnsThroughExitServers != state.exitDnsThroughExitServers {
            exitDnsThroughExitServers = state.exitDnsThroughExitServers
            lastSyncedExitDnsThroughExitServers = state.exitDnsThroughExitServers
        }
        if lastSyncedManualPaidExitProvider != state.paidRouteMarket.manualProviderLink {
            manualPaidExitProvider = state.paidRouteMarket.manualProviderLink
            lastSyncedManualPaidExitProvider = state.paidRouteMarket.manualProviderLink
        }
        if paidExitSellerDraftConfigChanged(
            from: lastSyncedPaidExitSeller,
            to: state.paidExitSeller
        ) {
            let seller = state.paidExitSeller
            paidExitPriceMsatPerGb = String(seller.priceMsatPerGb)
            paidExitAcceptedMints = seller.acceptedMints.joined(separator: ", ")
            paidExitMaxChannelCapacitySat = String(seller.maxChannelCapacitySat)
            paidExitChannelExpirySecs = paidExitDurationDraft(seller.channelExpirySecs)
            paidExitFreeProbeUnits = fallbackText(seller.freeProbeText, paidExitTrafficUnitDraft(seller.freeProbeUnits))
            paidExitGraceUnits = fallbackText(seller.graceText, paidExitTrafficUnitDraft(seller.graceUnits))
            paidExitCountryCode = seller.countryCode
            paidExitNetworkClass = seller.networkClass
            paidExitAsn = seller.asn == 0 ? "" : String(seller.asn)
        }
        lastSyncedPaidExitSeller = state.paidExitSeller

        for network in state.networks {
            if networkNameDrafts[network.id] == nil {
                networkNameDrafts[network.id] = network.name
            }
        }

        if let network = shownNetwork {
            let participants = sortedParticipants(network)
            if let selectedDevicePubkeyHex,
               participants.contains(where: { $0.pubkeyHex == selectedDevicePubkeyHex }) {
                return
            }
            selectedDevicePubkeyHex = participants.first?.pubkeyHex
        } else {
            selectedDevicePubkeyHex = nil
        }
    }

    func paidExitSellerDraftConfigChanged(
        from previous: NativePaidExitSellerState?,
        to current: NativePaidExitSellerState
    ) -> Bool {
        guard let previous else { return true }
        return previous.priceMsatPerGb != current.priceMsatPerGb
            || previous.acceptedMints != current.acceptedMints
            || previous.maxChannelCapacitySat != current.maxChannelCapacitySat
            || previous.channelExpirySecs != current.channelExpirySecs
            || previous.freeProbeUnits != current.freeProbeUnits
            || previous.graceUnits != current.graceUnits
            || previous.countryCode != current.countryCode
            || previous.asn != current.asn
    }

    func displayName(_ network: NativeNetworkState) -> String {
        network.name.isEmpty ? "Network" : network.name
    }

    /// A valid device ID is a bech32-encoded npub: `npub1` + 58 bech32 chars.
    func isValidDeviceId(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 63, trimmed.hasPrefix("npub1") else { return false }
        let body = trimmed.dropFirst(5)
        let allowed: Set<Character> = Set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        return body.allSatisfy { allowed.contains($0) }
    }

    var headerVpnStatusText: String {
        manager.vpnStatusText
    }

    var headerStatusDotVisible: Bool {
        state.exitNodeBlocked || state.exitNodeActive || state.vpnActive || state.vpnEnabled
    }

    var headerStatusColor: Color {
        if state.exitNodeBlocked {
            return .red
        }
        if state.exitNodeActive || state.vpnActive {
            return .green
        }
        if state.vpnEnabled {
            return .orange
        }
        return .secondary
    }

    var headerStatusTextColor: Color {
        state.exitNodeBlocked ? .red : .secondary
    }

    func deviceAvailabilityText(_ network: NativeNetworkState) -> String {
        if network.expectedCount == 0 {
            return "No devices"
        }
        let deviceWord = network.expectedCount == 1 ? "device" : "devices"
        return "\(network.onlineCount) online · \(network.expectedCount) \(deviceWord)"
    }

    var serviceInstallButtonTitle: String {
        if manager.serviceUpdateRecommended {
            return "Update Service"
        }
        return state.serviceInstalled ? "Reinstall Service" : "Install Service"
    }

    func sortedParticipants(_ network: NativeNetworkState) -> [NativeParticipantState] {
        network.participants.sorted { lhs, rhs in
            if isSelf(lhs) != isSelf(rhs) {
                return isSelf(lhs)
            }
            if lhs.reachable != rhs.reachable {
                return lhs.reachable && !rhs.reachable
            }
            return deviceName(lhs).localizedCaseInsensitiveCompare(deviceName(rhs)) == .orderedAscending
        }
    }

    func visibleParticipants(_ network: NativeNetworkState, search: String) -> [NativeParticipantState] {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else {
            return sortedParticipants(network)
        }
        return sortedParticipants(network).filter { participant in
            [
                deviceName(participant),
                participant.alias,
                participant.magicDnsAlias,
                participant.magicDnsName,
                participant.npub,
                participant.tunnelIp,
                deviceStatusText(participant),
            ].contains { $0.lowercased().contains(needle) }
        }
    }

    func selectedParticipant(in network: NativeNetworkState) -> NativeParticipantState? {
        let participants = sortedParticipants(network)
        if let selectedDevicePubkeyHex,
           let selected = participants.first(where: { $0.pubkeyHex == selectedDevicePubkeyHex }) {
            return selected
        }
        return participants.first
    }

    func isSelf(_ participant: NativeParticipantState) -> Bool {
        participant.npub == state.ownNpub || participant.meshState == "local"
    }

    func deviceName(_ participant: NativeParticipantState) -> String {
        if !participant.magicDnsName.isEmpty {
            return participant.magicDnsName
        }
        if isSelf(participant), !state.selfMagicDnsName.isEmpty {
            return state.selfMagicDnsName
        }
        if !participant.alias.isEmpty {
            return participant.alias
        }
        if !participant.magicDnsAlias.isEmpty {
            return participant.magicDnsAlias
        }
        return "Device"
    }

    func deviceSubtitle(_ participant: NativeParticipantState) -> String {
        return ""
    }

    func deviceMagicDnsName(_ participant: NativeParticipantState) -> String {
        if !participant.magicDnsName.isEmpty {
            return participant.magicDnsName
        }
        if isSelf(participant), !state.selfMagicDnsName.isEmpty {
            return state.selfMagicDnsName
        }
        if !participant.magicDnsAlias.isEmpty, !state.magicDnsSuffix.isEmpty {
            return "\(participant.magicDnsAlias).\(state.magicDnsSuffix)"
        }
        return ""
    }

    func isActiveExitParticipant(_ participant: NativeParticipantState) -> Bool {
        state.exitNodeActive && !state.exitNode.isEmpty && participant.npub == state.exitNode
    }

    func exitNodeBadgeText(_ participant: NativeParticipantState) -> String {
        isActiveExitParticipant(participant) ? "Exit active" : "Exit offered"
    }

    func exitNodeBadgeStyle(_ participant: NativeParticipantState) -> BadgeStyle {
        isActiveExitParticipant(participant) ? .ok : .warn
    }

    func deviceRoleText(_ participant: NativeParticipantState) -> String {
        var roles: [String] = []
        if isSelf(participant) {
            roles.append("This device")
        }
        if participant.isAdmin {
            roles.append("Admin")
        }
        if participant.offersExitNode {
            roles.append(exitNodeBadgeText(participant))
        }
        return roles.isEmpty ? "Member" : roles.joined(separator: ", ")
    }

    func deviceStatusText(_ participant: NativeParticipantState) -> String {
        switch participant.state {
        case "local", "online", "present":
            return "Online"
        case "pending":
            return "Connecting"
        case "offline", "absent", "off":
            return "Offline"
        case _ where participant.reachable:
            return "Online"
        default:
            return "Unknown"
        }
    }

    func fipsPathText(_ participant: NativeParticipantState) -> String {
        if isSelf(participant) {
            return "This device"
        }
        if isDirectFipsPeer(participant) {
            let transport = participant.fipsTransportType.isEmpty ? "" : " (\(participant.fipsTransportType.uppercased()))"
            if participant.fipsSrttMs > 0 {
                return "Direct connection\(transport), \(participant.fipsSrttMs) ms"
            }
            return "Direct connection\(transport)"
        }
        if participant.reachable {
            if participant.fipsSrttMs > 0 {
                return "Via mesh, \(participant.fipsSrttMs) ms"
            }
            return "Via mesh"
        }
        if participant.state == "pending" {
            return "Connecting"
        }
        return "Offline"
    }

    func isDirectFipsPeer(_ participant: NativeParticipantState) -> Bool {
        !isSelf(participant)
            && participant.reachable
            && !participant.fipsTransportAddr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func isFipsRouted(_ participant: NativeParticipantState) -> Bool {
        !isSelf(participant)
            && participant.reachable
            && participant.fipsTransportAddr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func connectivityDot(_ participant: NativeParticipantState, size: CGFloat) -> some View {
        Circle()
            .fill(connectivityTint(participant))
            .frame(width: size, height: size)
    }

    func connectivityTint(_ participant: NativeParticipantState) -> Color {
        switch participant.state {
        case "local", "online", "present":
            return .green
        case "pending":
            return .orange
        default:
            return .secondary
        }
    }

    func exitNodeCandidates(_ network: NativeNetworkState, search: String) -> [NativeParticipantState] {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return network.participants.filter { participant in
            if isSelf(participant) || !participant.offersExitNode {
                return false
            }
            guard !needle.isEmpty else {
                return true
            }
            return [
                participant.alias,
                participant.magicDnsAlias,
                participant.magicDnsName,
                participant.npub,
                participant.tunnelIp,
            ].contains { $0.lowercased().contains(needle) }
        }
    }

    func badgeStyle(for state: String) -> BadgeStyle {
        switch state {
        case "local", "online", "present":
            return .ok
        case "pending":
            return .warn
        case "offline", "absent":
            return .bad
        default:
            return .muted
        }
    }

    func healthStyle(_ severity: String) -> BadgeStyle {
        switch severity {
        case "critical":
            return .bad
        case "warning":
            return .warn
        case "info":
            return .muted
        default:
            return .muted
        }
    }
}


struct PendingParticipantRemoval {
    let networkId: String
    let npub: String
    let deviceName: String
}

struct PendingJoinRequest: Identifiable {
    let id = UUID()
    let networkId: String
    let networkName: String
    let request: String
}

func looksLikeJoinRequestQrOrLink(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return trimmed.hasPrefix("nvpn://join-request/") && trimmed.count > "nvpn://join-request/".count
}

struct LocalSearchScope<Content: View>: View {
    @State var search = ""
    let content: (Binding<String>) -> Content

    init(@ViewBuilder content: @escaping (Binding<String>) -> Content) {
        self.content = content
    }

    var body: some View {
        content($search)
    }
}

struct SyncedTextFieldRow: View {
    let title: String
    let placeholder: String
    let identity: String
    let value: String
    let systemImage: String
    let disabled: Bool
    let onSave: (String) -> Void

    @State var draft = ""
    @State var syncedIdentity = ""
    @State var syncedValue = ""

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .foregroundStyle(.secondary)
                .frame(width: 86, alignment: .leading)
            TextField(placeholder, text: $draft)
            Button {
                onSave(draft)
            } label: {
                Label("Save", systemImage: systemImage)
            }
            .disabled(disabled)
        }
        .onAppear {
            syncDraft(force: true)
        }
        .onChange(of: identity) { _, _ in
            syncDraft(force: true)
        }
        .onChange(of: value) { _, _ in
            syncDraft(force: false)
        }
    }

    func syncDraft(force: Bool) {
        let identityChanged = syncedIdentity != identity
        if force || identityChanged || draft == syncedValue {
            draft = value
        }
        syncedIdentity = identity
        syncedValue = value
    }
}

struct WrappingIdentifierText: NSViewRepresentable {
    let value: String
    let font: NSFont
    let color: NSColor

    func makeNSView(context: Context) -> NSTextView {
        let textView = NSTextView()
        textView.drawsBackground = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.textContainerInset = .zero
        textView.textContainer?.lineFragmentPadding = 0
        textView.textContainer?.lineBreakMode = .byCharWrapping
        textView.textContainer?.widthTracksTextView = true
        textView.isHorizontallyResizable = false
        textView.isVerticallyResizable = true
        textView.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return textView
    }

    func updateNSView(_ textView: NSTextView, context: Context) {
        textView.textStorage?.setAttributedString(attributedText)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSTextView, context: Context) -> CGSize? {
        guard let width = proposal.width, let textContainer = nsView.textContainer else {
            return nil
        }
        nsView.frame.size.width = width
        textContainer.containerSize = CGSize(width: width, height: .greatestFiniteMagnitude)
        nsView.layoutManager?.ensureLayout(for: textContainer)
        let height = nsView.layoutManager?.usedRect(for: textContainer).height ?? font.pointSize
        return CGSize(width: width, height: ceil(height))
    }

    var attributedText: NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.hyphenationFactor = 0
        paragraph.lineBreakMode = .byCharWrapping
        return NSAttributedString(
            string: value.isEmpty ? "-" : value,
            attributes: [
                .font: font,
                .foregroundColor: color,
                .paragraphStyle: paragraph,
            ]
        )
    }
}

struct QrCodeView: View {
    let text: String

    var body: some View {
        if text.isEmpty {
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .textBackgroundColor))
                .overlay(Image(systemName: "qrcode").foregroundStyle(.secondary))
        } else if let image = qrImage(text) {
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .padding(8)
                .background(Color.white, in: RoundedRectangle(cornerRadius: 8))
        } else {
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .textBackgroundColor))
                .overlay(Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange))
        }
    }

    func qrImage(_ text: String) -> NSImage? {
        let data = Data(text.utf8)
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
            return nil
        }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else {
            return nil
        }
        let transformed = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let representation = NSCIImageRep(ciImage: transformed)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }
}

enum SidebarItem: Hashable {
    case devices
    case internet
    case publicExits
    case sellExit
    case wallet
    case settings
}

enum BadgeStyle {
    case ok
    case warn
    case bad
    case muted
    case selected

    var foreground: Color {
        switch self {
        case .ok:
            return .green
        case .warn:
            return .orange
        case .bad:
            return .red
        case .muted:
            return .secondary
        case .selected:
            return .white
        }
    }

    var background: Color {
        switch self {
        case .ok:
            return .green.opacity(0.14)
        case .warn:
            return .orange.opacity(0.14)
        case .bad:
            return .red.opacity(0.14)
        case .muted:
            return .secondary.opacity(0.12)
        case .selected:
            return .white.opacity(0.18)
        }
    }
}

func formatBytes(_ bytes: UInt64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var value = Double(bytes)
    var unitIndex = 0
    while value >= 1024, unitIndex < units.count - 1 {
        value /= 1024
        unitIndex += 1
    }
    if unitIndex == 0 {
        return "\(bytes) B"
    }
    if value.rounded() == value {
        return String(format: "%.0f %@", value, units[unitIndex])
    }
    return String(format: "%.1f %@", value, units[unitIndex])
}

func formatDurationMs(_ ms: UInt64) -> String {
    if ms == 0 { return "-" }
    if ms < 1_000 { return "\(ms) ms" }
    let seconds = ms / 1_000
    if seconds < 60 { return "\(seconds)s" }
    let minutes = seconds / 60
    if minutes < 60 { return "\(minutes)m" }
    return "\(minutes / 60)h"
}

func displayNetworkId(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count > 4, isHexString(trimmed) else {
        return trimmed
    }
    return stride(from: 0, to: trimmed.count, by: 4)
        .map { offset -> String in
            let start = trimmed.index(trimmed.startIndex, offsetBy: offset)
            let end = trimmed.index(start, offsetBy: min(4, trimmed.distance(from: start, to: trimmed.endIndex)))
            return String(trimmed[start..<end])
        }
        .joined(separator: "-")
}

func normalizeNetworkIdInput(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    let compactScalars = trimmed.unicodeScalars.filter {
        !$0.properties.isWhitespace && $0 != "-"
    }
    let compact = String(String.UnicodeScalarView(compactScalars))
    if compact.isEmpty && trimmed.unicodeScalars.allSatisfy({ $0.properties.isWhitespace || $0 == "-" }) {
        return ""
    }
    return !compact.isEmpty && isHexString(compact) ? compact.lowercased() : trimmed
}

func isHexString(_ value: String) -> Bool {
    !value.isEmpty && value.unicodeScalars.allSatisfy { scalar in
        (48...57).contains(Int(scalar.value))
            || (65...70).contains(Int(scalar.value))
            || (97...102).contains(Int(scalar.value))
    }
}

func cleanIp(_ value: String) -> String {
    value.split(separator: "/").first.map(String.init) ?? value
}

func firstNonEmpty(_ values: String..., fallback: String) -> String {
    values.first { !$0.isEmpty } ?? fallback
}
