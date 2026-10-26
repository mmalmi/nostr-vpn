import AppKit
import SwiftUI

extension AppManager {
    func showReceivedFiles() {
        guard !state.configPath.isEmpty else { actionError = "Received files are not available yet."; return }
        let folder = URL(fileURLWithPath: state.configPath).deletingLastPathComponent()
            .appendingPathComponent("file-transfers/inbox", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            actionError = "No received files yet."
            return
        }
        if !NSWorkspace.shared.open(folder) { actionError = "Could not open received files." }
    }

    func chooseFileRecipient(for urls: [URL]) {
        guard state.vpnActive else { actionError = "Connect VPN to send files."; return }
        var seen = Set<String>()
        let peers = state.networks.filter(\.enabled).flatMap(\.participants)
            .filter { $0.npub != state.ownNpub && $0.rosterAccepted && $0.reachable && seen.insert($0.npub).inserted }
        let alert = NSAlert()
        alert.messageText = "Send files"
        guard !peers.isEmpty else {
            alert.informativeText = "Connect to a network with an online device first."
            alert.addButton(withTitle: "OK")
            alert.runModal()
            return
        }
        alert.informativeText = "Choose a device for \(urls.count) file\(urls.count == 1 ? "" : "s")."
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 300, height: 28))
        picker.addItems(withTitles: peers.map { $0.alias.isEmpty ? ($0.magicDnsAlias.isEmpty ? $0.npub : $0.magicDnsAlias) : $0.alias })
        alert.accessoryView = picker
        alert.addButton(withTitle: "Send")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { sendFiles(urls, to: peers[picker.indexOfSelectedItem].npub) }
    }

    func chooseFiles(to npub: String) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Send"
        panel.begin { [weak self] response in
            guard response == .OK else { return }
            Task { @MainActor in self?.sendFiles(panel.urls, to: npub) }
        }
    }

    func sendFiles(_ urls: [URL], to npub: String, completion: ((Bool) -> Void)? = nil) {
        guard !urls.isEmpty, !state.configPath.isEmpty else { completion?(false); return }
        guard state.vpnActive else { actionError = "Connect VPN to send files."; completion?(false); return }
        guard urls.count <= 32 else { actionError = "Choose up to 32 files."; completion?(false); return }
        let parent = URL(fileURLWithPath: state.configPath).deletingLastPathComponent()
        actionStatus = "Preparing files…"
        Task {
            do {
                let paths = try await Task.detached(priority: .userInitiated) {
                    try FileTransferStorage.stage(urls, in: parent)
                }.value
                dispatch(.sendFiles(npub: npub, paths: paths), status: "Offering files", completion: completion)
            } catch { actionError = error.localizedDescription; actionStatus = ""; completion?(false) }
        }
    }
}

struct FileTransfersView: View {
    @ObservedObject var manager: AppManager
    var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Files").font(.headline)
                    Spacer()
                    Button("Received files") { manager.showReceivedFiles() }
                }
                if !manager.state.fileTransfers.isEmpty {
                if !manager.state.vpnActive { Text("Connect VPN to continue transfers.").font(.caption).foregroundStyle(.secondary) }
                ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                ForEach(manager.state.fileTransfers, id: \.id) { transfer in
                    VStack(alignment: .leading, spacing: 6) {
                        if transfer.status == "unavailable" {
                            Text("Files unavailable").fontWeight(.medium)
                        } else {
                        Text(transfer.files.map(\.name).joined(separator: ", ")).fontWeight(.medium)
                        Text("\(transfer.isSender ? "To" : "From") \(transfer.peerName.isEmpty ? transfer.peerNpub : transfer.peerName)")
                            .font(.caption).foregroundStyle(.secondary)
                        if ["connecting", "transferring"].contains(transfer.status) {
                            ProgressView(value: Double(transfer.transferredBytes), total: Double(max(1, transfer.totalBytes)))
                        }
                        Text(transfer.status == "offered" ? (transfer.isSender ? "Waiting for acceptance" : "Wants to send you files") : (transfer.status == "preparing" ? "Preparing…" : transfer.status.capitalized))
                            .font(.caption)
                        Text("\(ByteCountFormatter.string(fromByteCount: Int64(clamping: transfer.transferredBytes), countStyle: .file)) / \(ByteCountFormatter.string(fromByteCount: Int64(clamping: transfer.totalBytes), countStyle: .file))")
                            .font(.caption).foregroundStyle(.secondary)
                        }
                        if let error = transfer.error { Text(error).foregroundStyle(.red).font(.caption) }
                        HStack {
                            if transfer.status == "offered" && !transfer.isSender {
                                Button("Accept") { manager.dispatch(.acceptFileTransfer(id: transfer.id)) }
                                Button("Decline") { manager.dispatch(.declineFileTransfer(id: transfer.id)) }
                            } else if ["offered", "preparing", "connecting", "transferring", "paused"].contains(transfer.status) {
                                if transfer.status == "paused" { Button("Resume") { manager.dispatch(.resumeFileTransfer(id: transfer.id)) } }
                                Button("Cancel") { manager.dispatch(.cancelFileTransfer(id: transfer.id)) }
                            }
                            if transfer.status == "completed" && !transfer.isSender {
                                Button("Show in Finder") {
                                    NSWorkspace.shared.activateFileViewerSelecting(transfer.files.compactMap { $0.localPath.map { URL(fileURLWithPath: $0) } })
                                }
                            }
                        }.disabled(manager.actionInFlight || (!manager.state.vpnActive && transfer.status != "completed"))
                    }
                    Divider()
                }
                }
                }.frame(height: min(300, CGFloat(manager.state.fileTransfers.count) * 170))
                }
            }.padding(12)
    }
}
