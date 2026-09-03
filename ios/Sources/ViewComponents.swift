import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct AppCard<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct SetupCard<Content: View>: View {
    let title: String
    let systemImage: String
    let tint: Color
    let content: Content

    init(title: String, systemImage: String, tint: Color, @ViewBuilder content: () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.tint = tint
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: systemImage)
                .font(.headline)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(tint)
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 2, style: .continuous)
                .fill(tint)
                .frame(width: 4)
                .padding(.vertical, 14)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(tint.opacity(0.24), lineWidth: 1)
        }
        .tint(tint)
    }
}

struct NoticeCard: View {
    let text: String
    var actionTitle: String? = nil
    var action: () -> Void = {}

    var body: some View {
        AppCard {
            Text(text)
                .foregroundStyle(.brown)
            if let actionTitle {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)
            }
        }
    }
}

struct WrappingIdentifierText: UIViewRepresentable {
    let value: String
    let font: UIFont
    let color: UIColor

    func makeUIView(context: Context) -> UITextView {
        let textView = UITextView()
        textView.backgroundColor = .clear
        textView.isEditable = false
        textView.isSelectable = true
        textView.isScrollEnabled = false
        textView.textContainerInset = .zero
        textView.textContainer.lineFragmentPadding = 0
        textView.textContainer.lineBreakMode = .byCharWrapping
        textView.adjustsFontForContentSizeCategory = true
        textView.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return textView
    }

    func updateUIView(_ textView: UITextView, context: Context) {
        textView.attributedText = attributedText
    }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView: UITextView, context: Context) -> CGSize? {
        guard let width = proposal.width else {
            return nil
        }
        let fittingSize = uiView.sizeThatFits(
            CGSize(width: width, height: CGFloat.greatestFiniteMagnitude)
        )
        return CGSize(width: width, height: fittingSize.height)
    }

    private var attributedText: NSAttributedString {
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

struct CopyLine: View {
    let value: String
    var displayValue: String? = nil
    var valueAccessibilityIdentifier: String? = nil
    @ObservedObject var model: AppModel

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            copyValue
                .accessibilityIdentifier(valueAccessibilityIdentifier ?? "")
                .accessibilityLabel(value)
            Button {
                model.copy(value)
            } label: {
                Label("Copy", systemImage: model.copiedValue == value ? "checkmark" : "doc.on.doc")
            }
            .disabled(value.isEmpty)
        }
    }

    @ViewBuilder
    private var copyValue: some View {
        if value.hasPrefix("npub1") {
            WrappingIdentifierText(
                value: (displayValue ?? value).isEmpty ? "-" : (displayValue ?? value),
                font: .preferredFont(forTextStyle: .footnote),
                color: .secondaryLabel
            )
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Text((displayValue ?? value).isEmpty ? "-" : (displayValue ?? value))
                .font(.footnote)
                .textSelection(.enabled)
                .foregroundStyle(.secondary)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
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

struct ScannedDeviceLink {
    let deviceId: String
    let alias: String?
}

struct PendingJoinRequest: Identifiable {
    let id = UUID()
    let networkName: String
    let request: String
}

func looksLikeJoinRequestQrOrLink(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return trimmed.hasPrefix("nvpn://join-request/") && trimmed.count > "nvpn://join-request/".count
}

func parseScannedDeviceLinkQr(_ value: String) -> ScannedDeviceLink? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if let deviceId = normalizedDeviceIdCandidate(trimmed) {
        return ScannedDeviceLink(deviceId: deviceId, alias: nil)
    }
    if let parsed = parseScannedDeviceJson(trimmed) {
        return parsed
    }
    return parseScannedDeviceUrl(trimmed)
}

func parseScannedDeviceJson(_ value: String) -> ScannedDeviceLink? {
    guard value.hasPrefix("{"),
          let data = value.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data),
          let json = object as? [String: Any]
    else {
        return nil
    }
    guard let deviceId = firstValidDeviceId(
        jsonString(json["deviceId"]),
        jsonString(json["device"]),
        jsonString(json["npub"]),
        jsonString(json["requesterNpub"])
    ) else {
        return nil
    }
    return ScannedDeviceLink(
        deviceId: deviceId,
        alias: firstNonBlank(
            jsonString(json["name"]),
            jsonString(json["nodeName"]),
            jsonString(json["label"])
        )
    )
}

func parseScannedDeviceUrl(_ value: String) -> ScannedDeviceLink? {
    guard let components = URLComponents(string: value),
          components.scheme?.lowercased() == "nvpn"
    else {
        return nil
    }
    var query: [String: String] = [:]
    for item in components.queryItems ?? [] where query[item.name] == nil {
        query[item.name] = item.value ?? ""
    }
    let pathCandidate = components.path
        .split(separator: "/")
        .last
        .map(String.init)
    guard let deviceId = firstValidDeviceId(
        query["deviceId"],
        query["device"],
        query["npub"],
        query["requesterNpub"],
        components.host,
        pathCandidate
    ) else {
        return nil
    }
    return ScannedDeviceLink(
        deviceId: deviceId,
        alias: firstNonBlank(query["name"], query["nodeName"], query["label"])
    )
}

func jsonString(_ value: Any?) -> String? {
    value as? String
}

func firstValidDeviceId(_ values: String?...) -> String? {
    values.compactMap { normalizedDeviceIdCandidate($0 ?? "") }.first
}

func normalizedDeviceIdCandidate(_ value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        return nil
    }
    let withoutNostrPrefix: String
    if trimmed.lowercased().hasPrefix("nostr:") {
        withoutNostrPrefix = String(trimmed.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)
    } else {
        withoutNostrPrefix = trimmed
    }
    return isValidDeviceId(withoutNostrPrefix) ? withoutNostrPrefix : nil
}

func firstNonBlank(_ values: String?...) -> String? {
    values
        .map { ($0 ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
        .first { !$0.isEmpty }
}

struct Metric: View {
    let label: String
    let value: String

    init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 80, alignment: .leading)
            Text(value.isEmpty ? "-" : value)
                .lineLimit(2)
                .truncationMode(.middle)
        }
        .font(.footnote)
        .accessibilityElement(children: .combine)
    }
}

struct Pill: View {
    let text: String
    let tint: Color

    init(_ text: String, tint: Color) {
        self.text = text
        self.tint = tint
    }

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(tint.opacity(0.12))
            .clipShape(Capsule())
    }
}

struct QrCodeView: View {
    let matrix: QrMatrix

    var body: some View {
        Canvas { context, size in
            let side = min(size.width, size.height)
            let origin = CGPoint(
                x: (size.width - side) / 2,
                y: (size.height - side) / 2
            )
            context.fill(
                Path(CGRect(origin: origin, size: CGSize(width: side, height: side))),
                with: .color(.white)
            )
            guard matrix.width > 0, matrix.cells.count == matrix.width * matrix.width else {
                return
            }
            let quiet = 3
            let modules = matrix.width + quiet * 2
            let cell = side / CGFloat(modules)
            for y in 0..<matrix.width {
                for x in 0..<matrix.width where matrix.cells[y * matrix.width + x] {
                    let rect = CGRect(
                        x: origin.x + CGFloat(x + quiet) * cell,
                        y: origin.y + CGFloat(y + quiet) * cell,
                        width: cell,
                        height: cell
                    )
                    context.fill(Path(rect), with: .color(.black))
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

enum AppColors {
    static let background = Color(uiColor: .systemGroupedBackground)
    static let accent = Color.purple
    static let create = Color.green
    static let join = Color.blue
    static let ok = Color.green
}

func cleanIp(_ value: String) -> String {
    value.split(separator: "/").first.map(String.init) ?? value
}

func sortedParticipants(_ participants: [ParticipantState], state: AppState) -> [ParticipantState] {
    participants.sorted { lhs, rhs in
        let lhsSelf = isSelf(lhs, state: state)
        let rhsSelf = isSelf(rhs, state: state)
        if lhsSelf != rhsSelf {
            return lhsSelf
        }
        if lhs.reachable != rhs.reachable {
            return lhs.reachable && !rhs.reachable
        }
        return deviceName(lhs, state: state).localizedCaseInsensitiveCompare(deviceName(rhs, state: state)) == .orderedAscending
    }
}

func isSelf(_ participant: ParticipantState, state: AppState) -> Bool {
    (!state.ownNpub.isEmpty && participant.npub == state.ownNpub) || participant.meshState == "local"
}

func isActiveExitParticipant(_ participant: ParticipantState, state: AppState) -> Bool {
    state.exitNodeActive && !state.exitNode.isEmpty && participant.npub == state.exitNode
}

func exitNodeBadgeText(_ participant: ParticipantState, state: AppState) -> String {
    isActiveExitParticipant(participant, state: state) ? "Exit active" : "Exit offered"
}

func exitNodeBadgeTint(_ participant: ParticipantState, state: AppState) -> Color {
    isActiveExitParticipant(participant, state: state) ? AppColors.ok : .orange
}

func deviceName(_ participant: ParticipantState, state: AppState) -> String {
    if !participant.magicDnsName.isEmpty {
        return participant.magicDnsName
    }
    if isSelf(participant, state: state), !state.selfMagicDnsName.isEmpty {
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

func deviceSubtitle(_ participant: ParticipantState, state: AppState) -> String {
    let ip = cleanIp(participant.tunnelIp)
    if isSelf(participant, state: state) {
        return ip.isEmpty ? "This device" : "This device - \(ip)"
    }
    return ip
}

func deviceStatus(_ participant: ParticipantState, state: AppState) -> String {
    if isSelf(participant, state: state) {
        return state.vpnEnabled ? "This device" : "Off"
    }
    switch participant.state {
    case "local", "online", "present":
        return "Online"
    case "pending":
        return "Connecting"
    case "offline", "absent", "off":
        return "Offline"
    default:
        return participant.reachable ? "Online" : "Unknown"
    }
}

func deviceDetailStatus(_ participant: ParticipantState, state: AppState) -> String {
    if isSelf(participant, state: state) {
        return deviceStatus(participant, state: state)
    }
    if !participant.statusText.isEmpty {
        return participant.statusText
    }
    return deviceStatus(participant, state: state)
}

func fipsPath(_ participant: ParticipantState, state: AppState) -> String {
    if isSelf(participant, state: state) {
        return "This device"
    }
    if participant.reachable
        && !participant.fipsTransportAddr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    {
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

func formatDurationMs(_ ms: UInt64) -> String {
    if ms == 0 { return "-" }
    if ms < 1_000 { return "\(ms) ms" }
    let seconds = ms / 1_000
    if seconds < 60 { return "\(seconds)s" }
    let minutes = seconds / 60
    if minutes < 60 { return "\(minutes)m" }
    return "\(minutes / 60)h"
}

func connectivityTint(_ participant: ParticipantState, state: AppState) -> Color {
    if isSelf(participant, state: state) {
        return state.vpnActive ? AppColors.ok : Color.gray.opacity(0.35)
    }
    switch participant.state {
    case "local", "online", "present":
        return AppColors.ok
    case "pending":
        return .orange
    default:
        return Color.gray.opacity(0.35)
    }
}

func isFipsRouted(_ participant: ParticipantState, state: AppState) -> Bool {
    !isSelf(participant, state: state)
        && participant.reachable
        && participant.fipsTransportAddr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
}

let bech32BodyCharset: Set<Character> = Set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

/// A valid device ID is a bech32-encoded npub: `npub1` + 58 bech32 chars.
func isValidDeviceId(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count == 63, trimmed.hasPrefix("npub1") else { return false }
    return trimmed.dropFirst(5).allSatisfy { bech32BodyCharset.contains($0) }
}
