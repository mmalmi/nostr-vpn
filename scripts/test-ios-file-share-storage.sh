#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-file-share.XXXXXX")"
trap 'rm -r "$TEST_DIR"' EXIT

cat >"$TEST_DIR/check.swift" <<'SWIFT'
import Foundation
import Darwin
import UniformTypeIdentifiers

@main struct FileShareCheck {
    static func require(_ condition: Bool, _ message: String) {
        precondition(condition, message)
    }

    static func checkFileObservation(in root: URL) throws {
        let manager = FileManager.default
        let support = root.appendingPathComponent("observation")
        let directory = support.appendingPathComponent("file-transfers")
        try manager.createDirectory(at: support, withIntermediateDirectories: true)
        let ready = DispatchSemaphore(value: 0)
        let offer = DispatchSemaphore(value: 0)
        let replacement = DispatchSemaphore(value: 0)
        let received = DispatchSemaphore(value: 0)
        let observer = FileTransferObservation { rows in
            switch rows.first?.id {
            case "ready": ready.signal()
            case "offer": offer.signal()
            case "replacement": replacement.signal()
            case "received": received.signal()
            default: break
            }
        }
        func writeState(_ id: String) throws {
            let row: [String: Any] = [
                "id": id, "peerNpub": "peer", "peerName": "Device", "isSender": false,
                "files": [], "status": "offered", "transferredBytes": 0, "totalBytes": 0,
            ]
            try JSONSerialization.data(withJSONObject: [row])
                .write(to: directory.appendingPathComponent("state.json"), options: .atomic)
        }
        observer.start(in: support)
        defer { observer.stop() }
        try manager.createDirectory(at: directory, withIntermediateDirectories: false)
        try writeState("ready")
        require(ready.wait(timeout: .now() + 3) == .success, "The initial transfer state was missed")
        try writeState("offer")
        let deadline = DispatchTime.now() + 2
        while offer.wait(timeout: .now() + .milliseconds(25)) != .success {
            require(DispatchTime.now() < deadline, "Unrelated writes delayed the offer")
            try Data([1]).write(to: support.appendingPathComponent("status"), options: .atomic)
        }
        try manager.moveItem(at: directory, to: support.appendingPathComponent("old"))
        try manager.createDirectory(at: directory, withIntermediateDirectories: false)
        try writeState("replacement")
        require(replacement.wait(timeout: .now() + 3) == .success, "Replacement directory was missed")
        try writeState("received")
        require(received.wait(timeout: .now() + 3) == .success, "New directory was not observed")
    }

    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try checkFileObservation(in: root)
        let support = root.appendingPathComponent("shared")
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        var peers = [FileSharePeer(npub: "fixture-peer", name: "Phone", reachable: true)]
        var lastWritten: [FileSharePeer]?
        let recipientFile = support.appendingPathComponent("file-share-peers.json")
        try FileTransferStorage.writeSharePeers(peers, in: support, lastWritten: &lastWritten)
        let originalInfo = try FileManager.default.attributesOfItem(atPath: recipientFile.path)
        try FileTransferStorage.writeSharePeers(peers, in: support, lastWritten: &lastWritten)
        let unchangedInfo = try FileManager.default.attributesOfItem(atPath: recipientFile.path)
        require(originalInfo[.systemFileNumber] as? NSNumber == unchangedInfo[.systemFileNumber] as? NSNumber,
                "An unchanged recipient list must not be replaced")
        peers[0].reachable = false
        try FileTransferStorage.writeSharePeers(peers, in: support, lastWritten: &lastWritten)
        let decoded = try JSONDecoder().decode([FileSharePeer].self, from: Data(contentsOf: recipientFile))
        require(decoded == peers, "A reachability change must reach the share extension")
        try FileManager.default.removeItem(at: recipientFile)
        try FileTransferStorage.writeSharePeers(peers, in: support, lastWritten: &lastWritten)
        require(FileManager.default.fileExists(atPath: recipientFile.path), "Restore a missing recipient list")
        let original = root.appendingPathComponent("selected.txt")
        let bytes = Data("complete file contents".utf8)
        try bytes.write(to: original)
        let staged = try FileTransferStorage.stage([original], in: support)
        try Data("changed original".utf8).write(to: original)
        require(try Data(contentsOf: URL(fileURLWithPath: staged[0])) == bytes, "staged bytes changed with the source")
        let id = try FileTransferStorage.enqueue(paths: staged, npub: "test-recipient", in: support)
        let commandURL = support.appendingPathComponent("file-transfers/commands/\(id).json")
        let command = try JSONSerialization.jsonObject(with: Data(contentsOf: commandURL)) as! [String: Any]
        let payload = command["command"] as! [String: Any]
        require(command["id"] as? String == id && payload["type"] as? String == "send", "invalid queue envelope")
        require(payload["paths"] as? [String] == staged && payload["npub"] as? String == "test-recipient", "queued the wrong file or recipient")
        for path in [commandURL.path, staged[0]] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            require((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "shared file is not private")
        }

        // The provider owns a temporary file. The extension must copy it while
        // the provider callback is valid, before the host removes that file.
        let temporary = root.appendingPathComponent("provider.txt")
        try bytes.write(to: temporary)
        let provider = NSItemProvider()
        provider.suggestedName = "shared.txt"
        provider.registerFileRepresentation(forTypeIdentifier: UTType.plainText.identifier, fileOptions: [], visibility: .all) { completion in
            completion(temporary, false, nil)
            try? FileManager.default.removeItem(at: temporary)
            return nil
        }
        let batch = try FileTransferStorage.makeBatch(in: support)
        let copied = try await FileTransferStorage.copyProvider(provider, to: batch)
        require(try Data(contentsOf: URL(fileURLWithPath: copied)) == bytes, "provider data did not outlive its callback")
        require(URL(fileURLWithPath: copied).lastPathComponent == "shared.txt", "lost the shared filename")

        let urlProvider = NSItemProvider(item: original as NSURL, typeIdentifier: UTType.fileURL.identifier)
        let urlBatch = try FileTransferStorage.makeBatch(in: support)
        let urlCopy = try await FileTransferStorage.copyProvider(urlProvider, to: urlBatch)
        require(try Data(contentsOf: URL(fileURLWithPath: urlCopy)) == Data(contentsOf: original), "file URL provider did not copy bytes")

        let link = root.appendingPathComponent("linked.txt")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: original)
        let pipe = root.appendingPathComponent("pipe")
        require(mkfifo(pipe.path, 0o600) == 0, "could not create the unsafe source fixture")
        _ = alarm(5) // A pipe must be rejected promptly instead of blocking the share extension.
        for invalid in [link, root, pipe] {
            do {
                _ = try FileTransferStorage.stage([invalid], in: support)
                fatalError("accepted a symbolic link, directory or pipe as a file")
            } catch { }
        }
        _ = alarm(0)

        let cancelled = FilePreparation()
        cancelled.cancel()
        do {
            _ = try FileTransferStorage.stage([original], in: support, preparation: cancelled)
            fatalError("cancelled preparation queued a file")
        } catch is CancellationError { }
        require(FileManager.default.fileExists(atPath: original.path), "cancellation removed the user's source")
        require(FileManager.default.fileExists(atPath: commandURL.path), "cancellation removed another queued transfer")
        require(try Data(contentsOf: URL(fileURLWithPath: staged[0])) == bytes, "cancellation removed another staged file")
        print("iOS file sharing: staging, durable command, permissions, provider lifetime, filename, unsafe source rejection and cancellation passed")
    }
}
SWIFT

xcrun swiftc -parse-as-library "$ROOT/ios/Shared/FileTransferStorage.swift" \
  "$ROOT/ios/Shared/FileTransferPresentation.swift" "$ROOT/ios/Shared/FileTransferObservation.swift" \
  "$TEST_DIR/check.swift" -o "$TEST_DIR/check"
"$TEST_DIR/check"
