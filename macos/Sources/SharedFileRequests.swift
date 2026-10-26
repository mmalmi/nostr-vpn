import Foundation

extension AppManager {
    func rememberFileRecipient(_ npub: String) {
        let recent = UserDefaults.standard.stringArray(forKey: "file-recent-recipients") ?? []
        UserDefaults.standard.set(Array(([npub] + recent.filter { $0 != npub }).prefix(8)), forKey: "file-recent-recipients")
        publishFileSharePeers()
    }

    func fileSharePeers() -> [FileSharePeer] {
        var seen = Set<String>()
        let recent = UserDefaults.standard.stringArray(forKey: "file-recent-recipients") ?? []
        return state.networks.filter(\.enabled).flatMap { network in
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
    }

    func publishFileSharePeers() {
        guard !fixtureMode, let root = MacShareStorage.root else { return }
        let peers = fileSharePeers()
        if let data = try? JSONEncoder().encode(peers) {
            try? data.write(to: root.appendingPathComponent("file-share-peers.json"), options: .atomic)
        }
    }

    func consumeFileShareRequests() {
        guard !processingFileShare, filePreparation == nil, !actionInFlight, !fixtureMode, !state.configPath.isEmpty,
              let root = MacShareStorage.root else { return }
        let requests = root.appendingPathComponent("requests", isDirectory: true)
        guard let pending = try? FileManager.default.contentsOfDirectory(at: requests, includingPropertiesForKeys: nil)
            .filter({ $0.pathExtension == "json" }).sorted(by: { $0.lastPathComponent < $1.lastPathComponent }),
              !pending.isEmpty else { return }
        guard state.vpnActive else {
            filePreparationText = "Shared files are queued. Connect to send them."
            fileTransfersRequested = true
            return
        }
        let parent = URL(fileURLWithPath: state.configPath).deletingLastPathComponent()
        for url in pending.prefix(32) {
        do {
            let properties = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey])
            guard properties.isRegularFile == true, properties.isSymbolicLink != true,
                  let size = properties.fileSize, size <= 65536 else { throw CocoaError(.fileReadTooLarge) }
            let data = try Data(contentsOf: url)
            guard data.count <= 65536 else { throw CocoaError(.fileReadTooLarge) }
            var request = try JSONDecoder().decode(MacShareRequest.self, from: data)
            guard request.paths.count <= 32, !request.paths.isEmpty, request.id == url.deletingPathExtension().lastPathComponent else { throw CocoaError(.fileReadCorruptFile) }
            guard state.networks.contains(where: { $0.enabled && $0.participants.contains(where: { $0.npub == request.npub && $0.rosterAccepted }) }) else {
                throw NSError(domain: "FileTransfer", code: 3, userInfo: [NSLocalizedDescriptionKey: "The selected device is no longer in this network."])
            }
            let sources = try validatedShareSources(request.paths, in: root)
            if let staged = request.stagedPaths { _ = try validatedShareSources(staged, in: parent) }
            processingFileShare = true
            let preparation = beginFilePreparation()
            Task {
                do {
                    if request.stagedPaths == nil {
                        request.stagedPaths = try await Task.detached(priority: .userInitiated) {
                            try FileTransferStorage.stage(sources, in: parent, preparation: preparation)
                        }.value
                        try JSONEncoder().encode(request).write(to: url, options: .atomic)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                    }
                    try preparation.checkCancellation()
                    rememberFileRecipient(request.npub)
                    dispatch(.sendFiles(npub: request.npub, paths: request.stagedPaths!), status: "Queued — waiting for the recipient") { [weak self] succeeded in
                        guard let self else { return }
                        self.processingFileShare = false
                        self.filePreparation = nil
                        self.filePreparationText = ""
                        if succeeded {
                            try? FileManager.default.removeItem(at: url)
                            for source in sources { try? FileManager.default.removeItem(at: source) }
                            self.consumeFileShareRequests()
                        }
                    }
                } catch {
                    processingFileShare = false
                    filePreparation = nil
                    filePreparationText = ""
                    rejectFileShareRequest(url, error: error)
                    consumeFileShareRequests()
                }
            }
            return
        } catch { rejectFileShareRequest(url, error: error) }
        }
    }

    private func validatedShareSources(_ paths: [String], in root: URL) throws -> [URL] {
        guard !paths.isEmpty, paths.count <= 32 else { throw CocoaError(.fileReadCorruptFile) }
        let outbox = root.appendingPathComponent("file-transfer-outbox", isDirectory: true).resolvingSymlinksInPath().path + "/"
        return try paths.map { path in
            let source = URL(fileURLWithPath: path)
            let properties = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard source.resolvingSymlinksInPath().path.hasPrefix(outbox), properties.isRegularFile == true,
                  properties.isSymbolicLink != true else { throw CocoaError(.fileReadNoPermission) }
            return source
        }
    }

    private func rejectFileShareRequest(_ url: URL, error: Error) {
        // Retain rejected request metadata and its files without blocking later shares.
        try? FileManager.default.moveItem(at: url, to: url.appendingPathExtension("rejected"))
        actionError = "Could not send shared files: \(error.localizedDescription)"
        actionStatus = ""
    }
}
