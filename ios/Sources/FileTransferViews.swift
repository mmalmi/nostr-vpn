import Foundation
import SwiftUI
import UniformTypeIdentifiers
import UserNotifications
import QuickLook

extension AppModel {
    var fileTransfersForDisplay: [FileTransferPresentation] {
        mergedFileTransfers(live: observedFileTransfers, app: state.fileTransfers.map { row in
            FileTransferPresentation(id: row.id, peerNpub: row.peerNpub, peerName: row.peerName, isSender: row.isSender,
                files: row.files.map { .init(name: $0.name, sizeBytes: $0.sizeBytes, localPath: $0.localPath) },
                status: row.status, transferredBytes: row.transferredBytes, totalBytes: row.totalBytes, error: row.error)
        })
    }
    func configureFileTransfers() {
        guard !fixtureMode, let supportDir, fileObservation == nil else { return }
        FileTransferNotifications.registerActions()
        fileNotificationDelegate.onAction = { [weak self] id, action in
            guard let self else { return }
            self.highlightedFileTransfer = id
            self.fileTransfersRequested = true
            self.pendingFileNotificationAction = (id, action)
            self.processFileNotificationAction()
        }
        UNUserNotificationCenter.current().delegate = fileNotificationDelegate
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            Task { @MainActor in self?.fileNotificationsEnabled = settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional }
        }
        fileObservation = FileTransferObservation { [weak self] rows in
            Task { @MainActor in self?.observedFileTransfers = rows }
        }
        fileObservation?.start(in: supportDir)
    }

    func processFileNotificationAction() {
        guard !actionInFlight, let (id, action) = pendingFileNotificationAction else { return }
        pendingFileNotificationAction = nil
        if action == "accept" || action == "decline" { fileTransferAction(action, id: id) }
    }

    func enableFileNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { [weak self] granted, _ in
            Task { @MainActor in
                self?.fileNotificationsEnabled = granted
                if !granted { self?.statusMessage = "Allow nvpn notifications in Settings to see file alerts." }
            }
        }
    }

    func sendFiles(_ urls: [URL], to npub: String) {
        guard !urls.isEmpty, let supportDir, filePreparation == nil else { return }
        guard urls.count <= 32 else { statusMessage = "Choose up to 32 files."; return }
        let preparation = FilePreparation()
        filePreparation = preparation
        filePreparationText = "Preparing files…"
        filePreparationProgress = 0
        fileTransfersRequested = true
        preparation.progress = { [weak self, weak preparation] count, total, name in
            Task { @MainActor in
                guard let self, let preparation, self.filePreparation === preparation else { return }
                self.filePreparationText = "Preparing \(name) · \(FileTransferPresentation.bytes(count)) of \(FileTransferPresentation.bytes(total))"
                self.filePreparationProgress = total == 0 ? 0 : Double(count) / Double(total)
            }
        }
        Task {
            defer { filePreparation = nil; filePreparationText = "" }
            var staged: [String] = []
            do {
                staged = try await Task.detached(priority: .userInitiated) {
                    try FileTransferStorage.stage(urls, in: supportDir, preparation: preparation)
                }.value
                try preparation.checkCancellation()
                let queued = dispatch(["type": "send_files", "npub": npub, "paths": staged])
                if queued {
                    let recent = UserDefaults.standard.stringArray(forKey: "file-recent-recipients") ?? []
                    UserDefaults.standard.set(Array(([npub] + recent.filter { $0 != npub }).prefix(8)), forKey: "file-recent-recipients")
                    publishFileSharePeers()
                    statusMessage = state.vpnActive ? "Queued — waiting for the recipient" : "Files queued. Connect to send them."
                } else { FileTransferStorage.discard(staged) }
            } catch is CancellationError {
                FileTransferStorage.discard(staged)
                statusMessage = "Cancelled"
            } catch {
                FileTransferStorage.discard(staged)
                statusMessage = error.localizedDescription
            }
        }
    }

    func publishFileSharePeers() {
        guard let supportDir else { return }
        var seen = Set<String>()
        let recent = UserDefaults.standard.stringArray(forKey: "file-recent-recipients") ?? []
        let peers = state.networks.filter(\.enabled).flatMap { network in
            network.participants.filter { $0.npub != state.ownNpub && $0.rosterAccepted && seen.insert($0.npub).inserted }
                .map { peer in
                    FileSharePeer(npub: peer.npub,
                        name: peer.alias.isEmpty ? (peer.magicDnsAlias.isEmpty ? "Device …\(peer.npub.suffix(6))" : peer.magicDnsAlias) : peer.alias,
                        detail: "\(network.name) · …\(peer.npub.suffix(6))", reachable: state.vpnActive && peer.reachable)
                }
        }.sorted {
            let a = recent.firstIndex(of: $0.npub) ?? Int.max
            let b = recent.firstIndex(of: $1.npub) ?? Int.max
            return a == b ? $0.name.localizedStandardCompare($1.name) == .orderedAscending : a < b
        }
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
        .disabled(!enabled || model.actionInFlight || model.filePreparation != nil)
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
    @State private var preview: URL?
    var body: some View {
        let transfers = model.fileTransfersForDisplay
        AppCard {
            HStack {
                Text("Files").font(.headline)
                Spacer()
                if !model.fileNotificationsEnabled {
                    Button { model.enableFileNotifications() } label: { Image(systemName: "bell.badge.fill") }
                        .accessibilityLabel("Notify me about files")
                }
            }
            if !model.filePreparationText.isEmpty {
                Text(model.filePreparationText).font(.caption).lineLimit(2)
                ProgressView(value: model.filePreparationProgress)
                Button("Cancel") { model.filePreparation?.cancel() }
            }
            if !model.state.vpnActive {
                HStack {
                    Text("Connect to send and receive files.").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Connect") { model.setVpnEnabled(true) }.buttonStyle(.bordered)
                        .disabled(model.actionInFlight)
                }
            }
            if transfers.isEmpty && model.filePreparationText.isEmpty {
                Text("Choose a device to send files, or share them to nvpn from another app.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !transfers.isEmpty {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(transfers) { transfer in
                                VStack(alignment: .leading, spacing: 7) {
                                    Text(transfer.title).fontWeight(.medium).lineLimit(2)
                                    Text("\(transfer.isSender ? "To" : "From") \(transfer.person)")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Text(transfer.statusText(connected: model.state.vpnActive)).font(.caption)
                                    if ["preparing", "connecting", "transferring", "paused"].contains(transfer.status) {
                                        ProgressView(value: Double(transfer.transferredBytes), total: Double(max(1, transfer.totalBytes)))
                                    }
                                    if transfer.active { Text(transfer.progressText).font(.caption).foregroundStyle(.secondary) }
                                    if let error = transfer.error, !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                                    HStack {
                                        if transfer.status == "offered" && !transfer.isSender {
                                            Button("Accept") { model.fileTransferAction("accept", id: transfer.id) }
                                                .buttonStyle(.borderedProminent).disabled(!model.state.vpnActive)
                                            Button("Decline") { model.fileTransferAction("decline", id: transfer.id) }.buttonStyle(.bordered)
                                        } else if transfer.active {
                                            if transfer.status == "paused" {
                                                Button("Resume") { model.fileTransferAction("resume", id: transfer.id) }.disabled(!model.state.vpnActive)
                                            }
                                            Button("Cancel") { model.fileTransferAction("cancel", id: transfer.id) }
                                        }
                                    }.disabled(model.actionInFlight)
                                    if transfer.status == "completed" && !transfer.isSender {
                                        ForEach(Array(transfer.files.enumerated()), id: \.offset) { _, file in
                                            if let path = file.localPath {
                                                HStack {
                                                    Button { preview = URL(fileURLWithPath: path) } label: { Label(file.name, systemImage: "doc.fill") }.lineLimit(1)
                                                    Spacer()
                                                    ShareLink(item: URL(fileURLWithPath: path)) { Image(systemName: "square.and.arrow.up.fill") }
                                                        .accessibilityLabel("Save or share \(file.name)")
                                                }
                                            }
                                        }
                                    }
                                }.padding(.vertical, 4).id(transfer.id)
                                Divider()
                            }
                        }
                    }
                    .frame(height: min(300, CGFloat(transfers.count) * 170))
                    .onChange(of: model.highlightedFileTransfer) { _, id in if let id { proxy.scrollTo(id, anchor: .top) } }
                    .onAppear { if let id = model.highlightedFileTransfer { proxy.scrollTo(id, anchor: .top) } }
                }
            }
        }.quickLookPreview($preview)
    }
}
