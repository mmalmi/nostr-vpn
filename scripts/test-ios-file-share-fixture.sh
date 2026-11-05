#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-file-share-fixture.XXXXXX")"
trap 'rm -r "$TEST_DIR"' EXIT
cat > "$TEST_DIR/check.swift" <<'SWIFT'
import Foundation

enum PhysicalGateMarker { static func emit(_ marker: String) {} }

@main struct FixtureChecks {
    static let fm = FileManager.default
    static let bytes = Data("fixture data".utf8)
    static let filename = "nvpn-share-check-owned.txt"
    static let npub = "npub1" + String(repeating: "a", count: 58)
    static let snapshot = Data("[{\"name\":\"Prior\",\"npub\":\"prior\"}]".utf8)
    static func require(_ condition: Bool, _ message: String) { precondition(condition, message) }
    static func rejected(_ operation: () throws -> Void) {
        do { try operation(); fatalError("unsafe cleanup unexpectedly succeeded") } catch {}
    }
    static func context(_ root: URL, _ name: String) throws -> FileShareFixtureContext {
        let root = root.appendingPathComponent(name)
        let suite = "nvpn-file-share-check." + UUID().uuidString
        let c = FileShareFixtureContext(group: suite, support: root.appendingPathComponent("support"),
            documents: root.appendingPathComponent("documents"), journal: root.appendingPathComponent("private/journal.json"),
            defaults: UserDefaults(suiteName: suite)!)
        for p in [c.support, c.documents, c.support.appendingPathComponent("file-transfers/commands"),
                  c.support.appendingPathComponent("file-transfer-outbox/baseline")] {
            try fm.createDirectory(at: p, withIntermediateDirectories: true)
        }
        try snapshot.write(to: c.support.appendingPathComponent("file-share-peers.json"))
        try fm.setAttributes([.posixPermissions: 0o640], ofItemAtPath: c.support.appendingPathComponent("file-share-peers.json").path)
        try Data("prior command".utf8).write(to: c.support.appendingPathComponent("file-transfers/commands/baseline.json"))
        try Data("prior payload".utf8).write(to: c.support.appendingPathComponent("file-transfer-outbox/baseline/user.dat"))
        c.defaults.set(["prior"], forKey: "file-recent-recipients")
        return c
    }
    static func prepare(_ c: FileShareFixtureContext) throws -> FileShareFixture {
        try .prepare(recipient: "Test", filename: filename, bytes: bytes, npub: npub, context: c)
    }
    static func queue(_ c: FileShareFixtureContext, source: URL? = nil, recipient: String? = nil) throws -> (URL, URL) {
        let paths = try FileTransferStorage.stage([source ?? c.documents.appendingPathComponent(filename)], in: c.support)
        let id = try FileTransferStorage.enqueue(paths: paths, npub: recipient ?? npub, in: c.support)
        return (c.support.appendingPathComponent("file-transfers/commands/\(id).json"), URL(fileURLWithPath: paths[0]))
    }
    static func restored(_ c: FileShareFixtureContext) throws {
        require(try Data(contentsOf: c.support.appendingPathComponent("file-share-peers.json")) == snapshot, "snapshot not restored")
        require((try fm.attributesOfItem(atPath: c.support.appendingPathComponent("file-share-peers.json").path)[.posixPermissions] as? NSNumber)?.intValue == 0o640, "snapshot mode changed")
        require(c.defaults.stringArray(forKey: "file-recent-recipients") == ["prior"], "recents not restored")
        require(!fm.fileExists(atPath: c.journal.path), "journal not retired")
        require(!fm.fileExists(atPath: c.documents.appendingPathComponent(filename).path), "owned source remains")
        require(try Data(contentsOf: c.support.appendingPathComponent("file-transfers/commands/baseline.json")) == Data("prior command".utf8), "foreign command changed")
        require(try Data(contentsOf: c.support.appendingPathComponent("file-transfer-outbox/baseline/user.dat")) == Data("prior payload".utf8), "foreign payload changed")
    }
    static func main() throws {
        let root = fm.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        var suites: [String] = []
        defer { for suite in suites { UserDefaults.standard.removePersistentDomain(forName: suite) } }
        let collision = try context(root, "collision"); suites.append(collision.group)
        let foreignSource = collision.documents.appendingPathComponent(filename)
        try Data("foreign source".utf8).write(to: foreignSource)
        rejected { _ = try prepare(collision) }
        require(try Data(contentsOf: foreignSource) == Data("foreign source".utf8), "pre-existing source removed")
        require(!fm.fileExists(atPath: collision.journal.path), "collision created cleanup authority")

        let replacement = try context(root, "replacement"); suites.append(replacement.group)
        let fixture = try prepare(replacement)
        try bytes.write(to: replacement.documents.appendingPathComponent(filename), options: .atomic)
        rejected { try fixture.restore() }
        require(fm.fileExists(atPath: replacement.documents.appendingPathComponent(filename).path), "replacement removed")
        require(fm.fileExists(atPath: replacement.journal.path), "replacement failure lost journal")

        let foreign = try context(root, "foreign-batch"); suites.append(foreign.group)
        let own = try prepare(foreign)
        let otherSource = root.appendingPathComponent(filename)
        try bytes.write(to: otherSource)
        let (foreignCommand, foreignCopy) = try queue(foreign, source: otherSource, recipient: "another-recipient")
        rejected { try own.restore() }
        require(fm.fileExists(atPath: foreignCommand.path) && fm.fileExists(atPath: foreignCopy.path), "foreign same-name transfer deleted")
        require(fm.fileExists(atPath: foreign.journal.path), "unclaimed batch failure lost journal")

        for boundary in 0...2 {
            let c = try context(root, "interrupt-\(boundary)"); suites.append(c.group)
            let f = try prepare(c), (command, copy) = try queue(c)
            try f.verifyQueued(bytes: bytes)
            // Exact journal ownership survives command-only and command+copy deletion.
            if boundary >= 1 { try fm.removeItem(at: command) }
            if boundary >= 2 { try fm.removeItem(at: copy) }
            try FileShareFixture.pending(context: c).restore()
            require(!fm.fileExists(atPath: copy.deletingLastPathComponent().path), "empty owned batch survived recovery")
            try restored(c)
        }
        print("6 file-share fixture cases passed: foreign source, source replacement, foreign batch, normal restoration and two interrupted deletions")
    }
}
SWIFT
xcrun swiftc -parse-as-library "$ROOT/ios/UITests/FileShareFixture.swift" "$ROOT/ios/Shared/FileTransferStorage.swift" "$TEST_DIR/check.swift" -o "$TEST_DIR/check"
"$TEST_DIR/check"
