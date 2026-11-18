import Foundation

struct FileTransferPresentation: Decodable, Identifiable, Sendable {
    struct File: Decodable, Sendable {
        var name: String
        var sizeBytes: UInt64
        var localPath: String?
    }
    var id: String
    var peerNpub: String
    var peerName: String
    var isSender: Bool
    var files: [File]
    var status: String
    var transferredBytes: UInt64
    var totalBytes: UInt64
    var error: String?

    var person: String { peerName.isEmpty ? "Device …\(peerNpub.suffix(6))" : peerName }
    var title: String {
        guard let first = files.first else { return "Files" }
        return files.count == 1 ? first.name : "\(first.name) + \(files.count - 1)"
    }
    var progressText: String { "\(Self.bytes(transferredBytes)) of \(Self.bytes(totalBytes))" }
    var active: Bool { ["queued", "preparing", "connecting", "transferring", "paused", "offered"].contains(status) }
    var statusText: String {
        switch status {
        case "queued": return "Queued — waiting for a connection"
        case "cancelling": return "Cancelling…"
        case "declining": return "Declining…"
        case "offered": return isSender ? "Waiting for \(person) to accept" : "Wants to send \(files.count == 1 ? "a file" : "\(files.count) files")"
        case "preparing": return "Preparing files…"
        case "connecting": return "Connecting…"
        case "transferring": return isSender ? "Sending" : "Receiving"
        case "paused": return "Paused"
        case "completed": return isSender ? "Delivered" : "Received"
        case "declined": return "Declined"
        case "cancelled": return "Cancelled"
        case "failed": return "Could not transfer files"
        default: return "Files unavailable"
        }
    }
    func statusText(connected: Bool) -> String {
        if !connected && ["connecting", "transferring"].contains(status) { return "Paused — connect to continue" }
        return statusText
    }
    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
    }
}

func mergedFileTransfers(live: [FileTransferPresentation], app: [FileTransferPresentation]) -> [FileTransferPresentation] {
    guard !live.isEmpty else { return app }
    var rows = live
    for pending in app where ["queued", "cancelling", "declining"].contains(pending.status) {
        if let index = rows.firstIndex(where: { $0.id == pending.id }) {
            if pending.status != "queued", rows[index].active { rows[index] = pending }
        } else { rows.insert(pending, at: 0) }
    }
    return rows
}

func fileSelectionSummary(_ urls: [URL]) -> String {
    let name = urls.first?.lastPathComponent ?? "Files"
    let title = urls.count > 1 ? "\(name) + \(urls.count - 1)" : name
    let sizes = urls.compactMap { try? $0.resourceValues(forKeys: [.fileSizeKey]).fileSize }
    guard sizes.count == urls.count else { return title }
    let total = sizes.reduce(UInt64(0)) { $0 + UInt64(max(0, $1)) }
    return "\(title) · \(FileTransferPresentation.bytes(total))"
}
