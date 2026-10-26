import Foundation
import SwiftUI
import UniformTypeIdentifiers

extension AppModel {
    func sendFiles(_ urls: [URL], to npub: String) {
        guard !urls.isEmpty, let supportDir else { return }
        guard state.vpnActive else { statusMessage = "Connect VPN to send files."; return }
        guard urls.count <= 32 else { statusMessage = "Choose up to 32 files."; return }
        statusMessage = "Preparing files…"
        Task {
            do {
                let paths = try await Task.detached(priority: .userInitiated) {
                    try FileTransferStorage.stage(urls, in: supportDir)
                }.value
                dispatch(["type": "send_files", "npub": npub, "paths": paths], status: "Offering files")
            } catch { statusMessage = error.localizedDescription }
        }
    }

    func publishFileSharePeers() {
        guard let supportDir else { return }
        var seen = Set<String>()
        let peers = state.networks.filter { state.vpnActive && $0.enabled }.flatMap(\.participants)
            .filter { $0.npub != state.ownNpub && $0.rosterAccepted && $0.reachable && seen.insert($0.npub).inserted }
            .map { FileSharePeer(npub: $0.npub, name: $0.alias.isEmpty ? ($0.magicDnsAlias.isEmpty ? $0.npub : $0.magicDnsAlias) : $0.alias) }
        guard let data = try? JSONEncoder().encode(peers) else { return }
        let url = supportDir.appendingPathComponent("file-share-peers.json")
        try? data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func fileTransferAction(_ action: String, id: String) {
        dispatch(["type": "\(action)_file_transfer", "id": id])
    }
}

struct FileSendButton: View {
    @ObservedObject var model: AppModel
    let npub: String
    let enabled: Bool
    @State private var picking = false
    var body: some View {
        Button { picking = true } label: {
            Label("Send files", systemImage: "paperplane.fill").frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .disabled(!model.state.vpnActive || !enabled || model.actionInFlight)
        .fileImporter(isPresented: $picking, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            switch result {
            case .success(let urls): model.sendFiles(urls, to: npub)
            case .failure(let error): model.statusMessage = error.localizedDescription
            }
        }
    }
}

struct FileTransfersCard: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if !model.state.fileTransfers.isEmpty {
            AppCard {
                Text("Files").font(.headline)
                if !model.state.vpnActive { Text("Connect VPN to continue transfers.").font(.caption).foregroundStyle(.secondary) }
                ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                ForEach(model.state.fileTransfers) { transfer in
                    VStack(alignment: .leading, spacing: 7) {
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
                        if let error = transfer.error { Text(error).font(.caption).foregroundStyle(.red) }
                        HStack {
                            if transfer.status == "offered" && !transfer.isSender {
                                Button("Accept") { model.fileTransferAction("accept", id: transfer.id) }.buttonStyle(.borderedProminent)
                                Button("Decline") { model.fileTransferAction("decline", id: transfer.id) }.buttonStyle(.bordered)
                            } else if ["offered", "preparing", "connecting", "transferring", "paused"].contains(transfer.status) {
                                if transfer.status == "paused" { Button("Resume") { model.fileTransferAction("resume", id: transfer.id) } }
                                Button("Cancel") { model.fileTransferAction("cancel", id: transfer.id) }
                            }
                        }.disabled(model.actionInFlight || !model.state.vpnActive)
                        if transfer.status == "completed" && !transfer.isSender {
                            ForEach(Array(transfer.files.enumerated()), id: \.offset) { _, file in
                                if let path = file.localPath {
                                    ShareLink(item: URL(fileURLWithPath: path)) { Label("Save or share \(file.name)", systemImage: "square.and.arrow.up.fill") }
                                }
                            }
                        }
                    }.padding(.vertical, 6)
                    Divider()
                }
                }
                }.frame(height: min(300, CGFloat(model.state.fileTransfers.count) * 170))
            }
        }
    }
}
