import AppKit
import SwiftUI
import UserNotifications

extension AppManager {
    var fileTransfersForDisplay: [FileTransferPresentation] {
        mergedFileTransfers(live: observedFileTransfers, app: state.fileTransfers.map { row in
            FileTransferPresentation(id: row.id, peerNpub: row.peerNpub, peerName: row.peerName, isSender: row.isSender,
                files: row.files.map { .init(name: $0.name, sizeBytes: $0.sizeBytes, localPath: $0.localPath) },
                status: row.status, transferredBytes: row.transferredBytes, totalBytes: row.totalBytes, error: row.error)
        })
    }
    func configureFileTransfers() {
        guard !fixtureMode, !state.configPath.isEmpty else { return }
        if fileObservation == nil {
            FileTransferNotifications.registerActions()
            fileNotificationDelegate.onAction = { [weak self] id, action in
                guard let self else { return }
                self.highlightedFileTransfer = id
                self.fileTransfersRequested = true
                NSApp.unhide(nil)
                NSApp.activate()
                NSApp.windows.first(where: { $0.title == "Nostr VPN" })?.makeKeyAndOrderFront(nil)
                self.pendingFileNotificationAction = (id, action)
                self.processFileNotificationAction()
            }
            UNUserNotificationCenter.current().delegate = fileNotificationDelegate
            UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
                Task { @MainActor in self?.fileNotificationsEnabled = settings.authorizationStatus == .authorized }
            }
            fileObservation = FileTransferObservation { [weak self] rows in
                Task { @MainActor in
                    guard let self else { return }
                    self.observedFileTransfers = rows
                    self.fileNotifications.update(rows)
                }
            }
        }
        fileObservation?.start(in: URL(fileURLWithPath: state.configPath).deletingLastPathComponent())
    }

    func processFileNotificationAction() {
        guard !actionInFlight, let (id, action) = pendingFileNotificationAction else { return }
        pendingFileNotificationAction = nil
        if action == "accept" { dispatch(.acceptFileTransfer(id: id)) }
        if action == "decline" { dispatch(.declineFileTransfer(id: id)) }
    }

    func enableFileNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { [weak self] granted, _ in
            Task { @MainActor in
                self?.fileNotificationsEnabled = granted
                if !granted { self?.actionStatus = "Allow nvpn notifications in System Settings to see file alerts." }
            }
        }
    }

    func showReceivedFiles() {
        guard !state.configPath.isEmpty else { actionError = "Received files are not available yet."; return }
        let folder = URL(fileURLWithPath: state.configPath).deletingLastPathComponent()
            .appendingPathComponent("file-transfers/inbox", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            actionError = "No received files yet."; return
        }
        if !NSWorkspace.shared.open(folder) { actionError = "Could not open received files." }
    }

    func chooseFileRecipient(for urls: [URL]) {
        guard !urls.isEmpty else { return }
        fileTransfersRequested = true
        guard state.vpnActive else {
            pendingFileURLs = urls
            let alert = NSAlert()
            alert.messageText = "Connect to send files"
            alert.informativeText = fileSelectionSummary(urls)
            alert.addButton(withTitle: "Connect and send")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn {
                filePreparationText = "Waiting for VPN — your files are ready"
                if !state.vpnEnabled { toggleVpn() }
                else { refresh() }
            } else { pendingFileURLs = [] }
            return
        }
        let peers = fileSharePeers()
        let alert = NSAlert()
        alert.messageText = "Send files"
        guard !peers.isEmpty else {
            alert.informativeText = "Link another device to send files."
            alert.addButton(withTitle: "OK")
            alert.runModal(); return
        }
        alert.informativeText = fileSelectionSummary(urls) + "\nThe recipient will be asked to accept."
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 340, height: 28))
        picker.addItems(withTitles: peers.map { "\($0.name) · \($0.detail ?? "")\($0.reachable == false ? " · Offline" : "")" })
        alert.accessoryView = picker
        alert.addButton(withTitle: "Send")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { sendFiles(urls, to: peers[picker.indexOfSelectedItem].npub) }
    }

    func continuePendingFileShare() {
        guard state.vpnActive, !pendingFileURLs.isEmpty else { return }
        let urls = pendingFileURLs
        pendingFileURLs = []
        filePreparationText = ""
        chooseFileRecipient(for: urls)
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

    func beginFilePreparation() -> FilePreparation {
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
        return preparation
    }

    func cancelFilePreparation() {
        filePreparation?.cancel()
        pendingFileURLs = []
        filePreparationText = filePreparation == nil ? "" : "Cancelling…"
    }

    func sendFiles(_ urls: [URL], to npub: String, completion: ((Bool) -> Void)? = nil) {
        guard !urls.isEmpty, !state.configPath.isEmpty, filePreparation == nil else { completion?(false); return }
        guard state.vpnActive else { chooseFileRecipient(for: urls); completion?(false); return }
        guard urls.count <= 32 else { actionError = "Choose up to 32 files."; completion?(false); return }
        let parent = URL(fileURLWithPath: state.configPath).deletingLastPathComponent()
        let preparation = beginFilePreparation()
        Task {
            defer { filePreparation = nil; filePreparationText = "" }
            var paths: [String] = []
            do {
                paths = try await Task.detached(priority: .userInitiated) {
                    try FileTransferStorage.stage(urls, in: parent, preparation: preparation)
                }.value
                try preparation.checkCancellation()
                rememberFileRecipient(npub)
                let staged = paths
                dispatch(.sendFiles(npub: npub, paths: paths), status: "Queued — waiting for the recipient") { succeeded in
                    if !succeeded { FileTransferStorage.discard(staged) }
                    completion?(succeeded)
                }
            } catch is CancellationError { FileTransferStorage.discard(paths); actionStatus = "Cancelled"; completion?(false) }
            catch { FileTransferStorage.discard(paths); actionError = error.localizedDescription; actionStatus = ""; completion?(false) }
        }
    }
}

struct FileTransfersView: View {
    @ObservedObject var manager: AppManager
    var body: some View {
        let transfers = manager.fileTransfersForDisplay
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Files").font(.headline)
                Spacer()
                if !manager.fileNotificationsEnabled {
                    Button { manager.enableFileNotifications() } label: { Image(systemName: "bell.badge.fill") }
                        .help("Notify me about files")
                }
                Button("Received files") { manager.showReceivedFiles() }
            }
            if !manager.filePreparationText.isEmpty {
                VStack(alignment: .leading) {
                    Text(manager.filePreparationText).font(.caption).lineLimit(2)
                    if manager.filePreparation != nil { ProgressView(value: manager.filePreparationProgress) }
                    if manager.filePreparation != nil || !manager.pendingFileURLs.isEmpty {
                        Button("Cancel") { manager.cancelFilePreparation() }
                    } else if !manager.state.vpnActive {
                        Button("Connect and send") { if !manager.state.vpnEnabled { manager.toggleVpn() } }
                    }
                }
            }
            if !transfers.isEmpty {
                if !manager.state.vpnActive {
                    HStack {
                        Text("Connect to continue transfers.").font(.caption).foregroundStyle(.secondary)
                        Button("Connect") { if !manager.state.vpnEnabled { manager.toggleVpn() } }
                    }
                }
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(transfers) { transfer in
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(transfer.title).fontWeight(.medium).lineLimit(2)
                                    Text("\(transfer.isSender ? "To" : "From") \(transfer.person)").font(.caption).foregroundStyle(.secondary)
                                    Text(transfer.statusText(connected: manager.state.vpnActive)).font(.caption)
                                    if ["preparing", "connecting", "transferring", "paused"].contains(transfer.status) {
                                        ProgressView(value: Double(transfer.transferredBytes), total: Double(max(1, transfer.totalBytes)))
                                    }
                                    if transfer.active { Text(transfer.progressText).font(.caption).foregroundStyle(.secondary) }
                                    if let error = transfer.error, !error.isEmpty { Text(error).foregroundStyle(.red).font(.caption).textSelection(.enabled) }
                                    HStack {
                                        if transfer.status == "offered" && !transfer.isSender {
                                            Button("Accept") { manager.dispatch(.acceptFileTransfer(id: transfer.id)) }.disabled(!manager.state.vpnActive)
                                            Button("Decline") { manager.dispatch(.declineFileTransfer(id: transfer.id)) }
                                        } else if transfer.active {
                                            if transfer.status == "paused" { Button("Resume") { manager.dispatch(.resumeFileTransfer(id: transfer.id)) }.disabled(!manager.state.vpnActive) }
                                            Button("Cancel") { manager.dispatch(.cancelFileTransfer(id: transfer.id)) }
                                        }
                                        if transfer.status == "completed" && !transfer.isSender {
                                            Button("Show in Finder") {
                                                NSWorkspace.shared.activateFileViewerSelecting(transfer.files.compactMap { $0.localPath.map { URL(fileURLWithPath: $0) } })
                                            }
                                        }
                                    }.disabled(manager.actionInFlight)
                                }.id(transfer.id)
                                Divider()
                            }
                        }
                    }
                    .frame(height: min(300, CGFloat(transfers.count) * 160))
                    .onChange(of: manager.highlightedFileTransfer) { _, id in if let id { proxy.scrollTo(id, anchor: .top) } }
                    .onAppear { if let id = manager.highlightedFileTransfer { proxy.scrollTo(id, anchor: .top) } }
                }
            }
        }.padding(12)
    }
}
