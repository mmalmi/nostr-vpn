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

    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let support = root.appendingPathComponent("shared")
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
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

xcrun swiftc -parse-as-library "$ROOT/ios/Shared/FileTransferStorage.swift" "$TEST_DIR/check.swift" -o "$TEST_DIR/check"
"$TEST_DIR/check"
