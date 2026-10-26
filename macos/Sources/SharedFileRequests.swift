import Foundation

extension AppManager {
    func publishFileSharePeers() {
        guard !fixtureMode, let root = MacShareStorage.root else { return }
        var seen = Set<String>()
        let peers = state.networks.filter { state.vpnActive && $0.enabled }.flatMap(\.participants)
            .filter { $0.npub != state.ownNpub && $0.rosterAccepted && $0.reachable && seen.insert($0.npub).inserted }
            .map { FileSharePeer(npub: $0.npub, name: $0.alias.isEmpty ? ($0.magicDnsAlias.isEmpty ? $0.npub : $0.magicDnsAlias) : $0.alias) }
        if let data = try? JSONEncoder().encode(peers) {
            try? data.write(to: root.appendingPathComponent("file-share-peers.json"), options: .atomic)
        }
    }

    func consumeFileShareRequests() {
        guard !processingFileShare, !actionInFlight, !fixtureMode, !state.configPath.isEmpty,
              let root = MacShareStorage.root else { return }
        let requests = root.appendingPathComponent("requests", isDirectory: true)
        guard let pending = try? FileManager.default.contentsOfDirectory(at: requests, includingPropertiesForKeys: nil)
            .filter({ $0.pathExtension == "json" }).sorted(by: { $0.lastPathComponent < $1.lastPathComponent }),
              !pending.isEmpty else { return }
        guard state.vpnActive else { actionError = "Connect VPN to send shared files."; return }
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
            actionStatus = "Preparing files…"
            Task {
                do {
                    if request.stagedPaths == nil {
                        request.stagedPaths = try await Task.detached(priority: .userInitiated) {
                            try FileTransferStorage.stage(sources, in: parent)
                        }.value
                        try JSONEncoder().encode(request).write(to: url, options: .atomic)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                    }
                    dispatch(.sendFiles(npub: request.npub, paths: request.stagedPaths!), status: "Offering files") { [weak self] succeeded in
                        guard let self else { return }
                        self.processingFileShare = false
                        if succeeded {
                            try? FileManager.default.removeItem(at: url)
                            for source in sources { try? FileManager.default.removeItem(at: source) }
                            self.consumeFileShareRequests()
                        }
                    }
                } catch {
                    processingFileShare = false
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
