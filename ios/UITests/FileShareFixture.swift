import CryptoKit
import Foundation

struct FileShareFixtureContext {
    let group: String
    let support: URL
    let documents: URL
    let journal: URL
    let defaults: UserDefaults

    static func physical() throws -> Self {
        let fm = FileManager.default
        guard let group = ProcessInfo.processInfo.environment["NVPN_XCUITEST_FILE_SHARE_GROUP"],
              let container = fm.containerURL(forSecurityApplicationGroupIdentifier: group),
              let defaults = UserDefaults(suiteName: group) else { throw CocoaError(.fileReadNoPermission) }
        return Self(group: group, support: container.appendingPathComponent("Nostr VPN"),
            documents: fm.urls(for: .documentDirectory, in: .userDomainMask)[0],
            journal: fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("nvpn-file-share-fixture.json"), defaults: defaults)
    }
}

private struct FileShareFileIdentity: Codable, Equatable {
    let device: UInt64
    let inode: UInt64
    let digest: String
    static func read(_ url: URL) throws -> Self {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let device = attributes[.systemNumber] as? NSNumber,
              let inode = attributes[.systemFileNumber] as? NSNumber,
              ((attributes[.size] as? NSNumber)?.intValue ?? Int.max) <= 1_048_576,
              url.resolvingSymlinksInPath().path == url.standardizedFileURL.path else {
            throw CocoaError(.fileReadInvalidFileName)
        }
        return Self(device: device.uint64Value, inode: inode.uint64Value,
            digest: SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined())
    }
}

private struct FileShareOwnedTransfer: Codable {
    let commandName: String
    let command: FileShareFileIdentity
    let batchName: String
    let copy: FileShareFileIdentity
}

private struct FileShareBackup: Codable {
    let group: String
    let recipient: String
    let npub: String
    let filename: String
    let source: FileShareFileIdentity
    let snapshot: Data?
    let snapshotMode: Int?
    let recents: [String]?
    let commands: [String]
    let batches: [String]
    let existingDirectories: [String]
    var ownedTransfers: [FileShareOwnedTransfer] = []
}

/// The journal remains until every proven owned file is gone and baseline reads match.
final class FileShareFixture {
    private var backup: FileShareBackup
    private let context: FileShareFixtureContext
    private let fm = FileManager.default
    private let recentKey = "file-recent-recipients"
    private static let directories = ["file-transfers/commands", "file-transfers", "file-transfer-outbox"]
    private var snapshotURL: URL { context.support.appendingPathComponent("file-share-peers.json") }
    private var commandsURL: URL { context.support.appendingPathComponent("file-transfers/commands") }
    private var outboxURL: URL { context.support.appendingPathComponent("file-transfer-outbox") }
    private var sourceURL: URL { context.documents.appendingPathComponent(backup.filename) }
    private init(_ backup: FileShareBackup, context: FileShareFixtureContext) {
        self.backup = backup
        self.context = context
    }
    private static func names(_ url: URL) throws -> [String] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else { return [] }
        guard url.resolvingSymlinksInPath().path == url.standardizedFileURL.path else { throw CocoaError(.fileReadInvalidFileName) }
        return try fm.contentsOfDirectory(atPath: url.path).sorted()
    }
    private func saveJournal(exclusive: Bool = false) throws {
        try JSONEncoder().encode(backup).write(to: context.journal, options: exclusive ? .withoutOverwriting : .atomic)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: context.journal.path)
    }
    private func fixtureSnapshot() throws -> Data {
        try JSONSerialization.data(withJSONObject: [["name": backup.recipient, "npub": backup.npub,
            "detail": "Release verification fixture", "reachable": false]], options: .sortedKeys)
    }
    static func pending() throws -> FileShareFixture { try pending(context: .physical()) }
    static func pending(context: FileShareFixtureContext) throws -> FileShareFixture {
        let backup = try JSONDecoder().decode(FileShareBackup.self, from: Data(contentsOf: context.journal))
        guard backup.group == context.group, backup.filename.hasPrefix("nvpn-share-check-"),
              !backup.filename.contains("/"), backup.npub.hasPrefix("npub1"), backup.npub.count == 63,
              backup.ownedTransfers.allSatisfy({ !$0.commandName.contains("/") && UUID(uuidString: $0.batchName) != nil }) else {
            throw CocoaError(.coderReadCorrupt)
        }
        return FileShareFixture(backup, context: context)
    }
    static func prepare(recipient: String, filename: String, bytes: Data) throws -> FileShareFixture {
        guard let npub = ProcessInfo.processInfo.environment["NVPN_XCUITEST_FILE_SHARE_NPUB"] else { throw CocoaError(.coderValueNotFound) }
        return try prepare(recipient: recipient, filename: filename, bytes: bytes, npub: npub, context: .physical())
    }
    static func prepare(recipient: String, filename: String, bytes: Data, npub: String,
                        context: FileShareFixtureContext) throws -> FileShareFixture {
        let fm = FileManager.default
        guard !fm.fileExists(atPath: context.journal.path), npub.hasPrefix("npub1"), npub.count == 63,
              filename.hasPrefix("nvpn-share-check-"), !filename.contains("/"),
              context.support.resolvingSymlinksInPath().path == context.support.standardizedFileURL.path else {
            throw CocoaError(.fileWriteFileExists)
        }
        let snapshotURL = context.support.appendingPathComponent("file-share-peers.json")
        let attributes = fm.fileExists(atPath: snapshotURL.path) ? try fm.attributesOfItem(atPath: snapshotURL.path) : nil
        if attributes != nil { _ = try FileShareFileIdentity.read(snapshotURL) }
        let snapshot = attributes == nil ? nil : try Data(contentsOf: snapshotURL)
        let recentsObject = context.defaults.object(forKey: "file-recent-recipients")
        guard recentsObject == nil || recentsObject is [String],
              !(recentsObject as? [String] ?? []).contains(npub),
              !String(decoding: snapshot ?? Data(), as: UTF8.self).contains(npub) else { throw CocoaError(.fileWriteFileExists) }
        let commandNames = try names(context.support.appendingPathComponent("file-transfers/commands"))
        let batchNames = try names(context.support.appendingPathComponent("file-transfer-outbox"))
        let existing = directories.filter { fm.fileExists(atPath: context.support.appendingPathComponent($0).path) }
        let sourceURL = context.documents.appendingPathComponent(filename)
        // A refused pre-existing source never grants cleanup ownership.
        try bytes.write(to: sourceURL, options: .withoutOverwriting)
        let source = try FileShareFileIdentity.read(sourceURL)
        let backup = FileShareBackup(group: context.group, recipient: recipient, npub: npub, filename: filename,
            source: source, snapshot: snapshot, snapshotMode: (attributes?[.posixPermissions] as? NSNumber)?.intValue,
            recents: recentsObject as? [String], commands: commandNames, batches: batchNames, existingDirectories: existing)
        let fixture = FileShareFixture(backup, context: context)
        do {
            try fm.createDirectory(at: context.journal.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fixture.saveJournal(exclusive: true)
        } catch {
            if try FileShareFileIdentity.read(sourceURL) == source { try fm.removeItem(at: sourceURL) }
            throw error
        }
        do {
            // Prevent expiring real recipients' Siri donations during the fixture send.
            context.defaults.set([String](), forKey: fixture.recentKey)
            guard context.defaults.synchronize() else { throw CocoaError(.fileWriteUnknown) }
            try fixture.fixtureSnapshot().write(to: snapshotURL, options: .atomic)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: snapshotURL.path)
        } catch { try fixture.restore(); throw error }
        return fixture
    }
    private func claimQueuedTransfer() throws {
        for name in try Self.names(commandsURL) where !backup.commands.contains(name)
            && !backup.ownedTransfers.contains(where: { $0.commandName == name }) {
            let url = commandsURL.appendingPathComponent(name)
            guard name.hasSuffix(".json") else { continue }
            let identity = try FileShareFileIdentity.read(url)
            let row = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
            guard let command = row?["command"] as? [String: Any], command["npub"] as? String == backup.npub else { continue }
            guard let paths = command["paths"] as? [String], paths.count == 1,
                  command["type"] as? String == "send", row?["id"] as? String == url.deletingPathExtension().lastPathComponent else {
                throw CocoaError(.coderReadCorrupt)
            }
            let copy = URL(fileURLWithPath: paths[0]), batch = copy.deletingLastPathComponent()
            guard copy.lastPathComponent == backup.filename, batch.deletingLastPathComponent().path == outboxURL.path,
                  UUID(uuidString: batch.lastPathComponent) != nil, !backup.batches.contains(batch.lastPathComponent),
                  try Self.names(batch) == [backup.filename] else { throw CocoaError(.fileReadInvalidFileName) }
            backup.ownedTransfers.append(FileShareOwnedTransfer(commandName: name, command: identity,
                batchName: batch.lastPathComponent, copy: try FileShareFileIdentity.read(copy)))
        }
        // Persist exact ownership before deleting either command or payload.
        try saveJournal()
    }
    func verifyQueued(bytes: Data) throws {
        try claimQueuedTransfer()
        guard backup.ownedTransfers.count == 1, let transfer = backup.ownedTransfers.first else { throw CocoaError(.coderReadCorrupt) }
        let copy = outboxURL.appendingPathComponent(transfer.batchName).appendingPathComponent(backup.filename)
        guard try Data(contentsOf: copy) == bytes else { throw CocoaError(.fileReadCorruptFile) }
        for url in [commandsURL.appendingPathComponent(transfer.commandName), copy] {
            guard (try fm.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600 else {
                throw CocoaError(.fileReadNoPermission)
            }
        }
        let proof: [String: Any] = ["durableCommand": true, "copiedBytes": bytes.count, "sha256": transfer.copy.digest,
            "mainAppRequired": false, "delivered": false, "siriSuggestion": "retained task-owned synthetic recipient; deletion not claimed"]
        try JSONSerialization.data(withJSONObject: proof, options: .sortedKeys).write(
            to: context.documents.appendingPathComponent("nvpn-file-share-queue.json"), options: .atomic)
    }
    private func removeOwned(_ url: URL, identity: FileShareFileIdentity) throws {
        guard fm.fileExists(atPath: url.path) else { return }
        guard try FileShareFileIdentity.read(url) == identity else { throw CocoaError(.fileWriteFileExists) }
        try fm.removeItem(at: url)
    }
    func restore() throws {
        let current = fm.fileExists(atPath: snapshotURL.path) ? try Data(contentsOf: snapshotURL) : nil
        let expected = try fixtureSnapshot()
        let recentObject = context.defaults.object(forKey: recentKey)
        guard current == backup.snapshot || current == expected,
              recentObject == nil || recentObject is [String] else { throw CocoaError(.fileWriteFileExists) }
        let recent = recentObject as? [String]
        guard recent == backup.recents || recent == [] || recent == [backup.npub] else { throw CocoaError(.fileWriteFileExists) }
        try claimQueuedTransfer()
        // Same-name files in foreign/unclaimed batches do not establish our ownership.
        let owned = Set(backup.ownedTransfers.map(\.batchName))
        guard Set(try Self.names(outboxURL)).subtracting(backup.batches).isSubset(of: owned) else { throw CocoaError(.fileWriteFileExists) }
        for transfer in backup.ownedTransfers {
            let batch = outboxURL.appendingPathComponent(transfer.batchName)
            guard Set(try Self.names(batch)).isSubset(of: [backup.filename]) else { throw CocoaError(.fileWriteFileExists) }
            try removeOwned(commandsURL.appendingPathComponent(transfer.commandName), identity: transfer.command)
            try removeOwned(batch.appendingPathComponent(backup.filename), identity: transfer.copy)
            if fm.fileExists(atPath: batch.path) { try fm.removeItem(at: batch) }
        }
        try removeOwned(sourceURL, identity: backup.source)
        if let snapshot = backup.snapshot {
            try snapshot.write(to: snapshotURL, options: .atomic)
            guard let mode = backup.snapshotMode else { throw CocoaError(.coderReadCorrupt) }
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: snapshotURL.path)
        } else if fm.fileExists(atPath: snapshotURL.path) { try fm.removeItem(at: snapshotURL) }
        if let recents = backup.recents { context.defaults.set(recents, forKey: recentKey) }
        else { context.defaults.removeObject(forKey: recentKey) }
        guard context.defaults.synchronize() else { throw CocoaError(.fileWriteUnknown) }
        for path in Self.directories where !backup.existingDirectories.contains(path) {
            let url = context.support.appendingPathComponent(path)
            if fm.fileExists(atPath: url.path), try Self.names(url).isEmpty { try fm.removeItem(at: url) }
        }
        let restored = fm.fileExists(atPath: snapshotURL.path) ? try Data(contentsOf: snapshotURL) : nil
        guard restored == backup.snapshot, context.defaults.stringArray(forKey: recentKey) == backup.recents,
              !fm.fileExists(atPath: sourceURL.path), backup.ownedTransfers.allSatisfy({
                  !fm.fileExists(atPath: commandsURL.appendingPathComponent($0.commandName).path)
                    && !fm.fileExists(atPath: outboxURL.appendingPathComponent($0.batchName).path)
              }) else { throw CocoaError(.fileWriteUnknown) }
        try fm.removeItem(at: context.journal)
        PhysicalGateMarker.emit("NVPN_FILE_SHARE_FIXTURE_RESTORED=1")
    }
}
