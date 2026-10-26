import Foundation
import Darwin
import UniformTypeIdentifiers

struct FileSharePeer: Codable, Identifiable {
    var npub: String
    var name: String
    var detail: String? = nil
    var reachable: Bool? = nil
    var id: String { npub }
}

final class FilePreparation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    var progress: (@Sendable (UInt64, UInt64, String) -> Void)?

    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func checkCancellation() throws {
        lock.lock(); let stopped = cancelled; lock.unlock()
        if stopped { throw CancellationError() }
    }
}

enum FileTransferStorage {
    /// Only use for fresh copies returned by stage() when enqueue did not succeed.
    static func discard(_ stagedPaths: [String]) {
        for path in stagedPaths { try? FileManager.default.removeItem(atPath: path) }
    }
    static func makeBatch(in supportDir: URL) throws -> URL {
        let batch = supportDir.appendingPathComponent("file-transfer-outbox", isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: batch, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return batch
    }

    static func stage(_ sources: [URL], in supportDir: URL, preparation: FilePreparation? = nil) throws -> [String] {
        guard !sources.isEmpty, sources.count <= 32 else { throw CocoaError(.fileReadTooLarge) }
        var batches: [URL] = []
        do {
            return try sources.map { source in
                let access = source.startAccessingSecurityScopedResource()
                defer { if access { source.stopAccessingSecurityScopedResource() } }
                let batch = try makeBatch(in: supportDir)
                batches.append(batch)
                return try copy(source, to: batch, preparation: preparation).path
            }
        } catch {
            for batch in batches { try? FileManager.default.removeItem(at: batch) }
            throw error
        }
    }

    static func copy(_ source: URL, name: String? = nil, to batch: URL, preparation: FilePreparation? = nil) throws -> URL {
        try preparation?.checkCancellation()
        let filename = name ?? source.lastPathComponent
        let forbidden = CharacterSet.controlCharacters.union(CharacterSet(charactersIn: "/\\<>:\"|?*"))
        guard !filename.isEmpty, filename != ".", filename != "..", filename.utf8.count <= 240,
              filename.rangeOfCharacter(from: forbidden) == nil else {
            throw NSError(domain: "FileTransfer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Rename this file before sending it."])
        }
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              UInt64(values.fileSize ?? 0) <= 100 * 1024 * 1024 * 1024 else {
            throw NSError(domain: "FileTransfer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Choose regular files smaller than 100 GB."])
        }
        let target = batch.appendingPathComponent(filename)
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let descriptor = open(target.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        let output = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? output.close() }
        var copied: UInt64 = 0
        var lastProgress = 0.0
        let total = UInt64(max(0, values.fileSize ?? 0))
        while true {
            let count: UInt64 = try autoreleasepool {
                try preparation?.checkCancellation()
                guard let data = try input.read(upToCount: 1_048_576), !data.isEmpty else { return 0 }
                guard copied + UInt64(data.count) <= 100 * 1024 * 1024 * 1024 else { throw CocoaError(.fileReadTooLarge) }
                try output.write(contentsOf: data)
                return UInt64(data.count)
            }
            if count == 0 { break }
            copied += count
            let now = ProcessInfo.processInfo.systemUptime
            if now - lastProgress >= 0.1 {
                preparation?.progress?(copied, total, filename)
                lastProgress = now
            }
        }
        try preparation?.checkCancellation()
        try output.synchronize()
        preparation?.progress?(copied, copied, filename)
        return target
    }

    @discardableResult
    static func enqueue(paths: [String], npub: String, in supportDir: URL) throws -> String {
        let directory = supportDir.appendingPathComponent("file-transfers/commands", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let data = try JSONSerialization.data(withJSONObject: ["id": id, "command": ["type": "send", "npub": npub, "paths": paths]])
        guard data.count <= 65536 else { throw CocoaError(.fileWriteOutOfSpace) }
        let temporary = directory.appendingPathComponent("\(id).tmp")
        do {
            try data.write(to: temporary, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            try FileManager.default.moveItem(at: temporary, to: directory.appendingPathComponent("\(id).json"))
        } catch { try? FileManager.default.removeItem(at: temporary); throw error }
        return id
    }
    static func copyProvider(_ provider: NSItemProvider, to batch: URL, preparation: FilePreparation? = nil) async throws -> String {
        if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            return try await withCheckedThrowingContinuation { continuation in
                provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
                    guard let source = item as? URL, source.isFileURL else {
                        continuation.resume(throwing: error ?? CocoaError(.fileReadUnsupportedScheme))
                        return
                    }
                    let access = source.startAccessingSecurityScopedResource()
                    defer { if access { source.stopAccessingSecurityScopedResource() } }
                    do { continuation.resume(returning: try FileTransferStorage.copy(source, to: batch, preparation: preparation).path) }
                    catch { continuation.resume(throwing: error) }
                }
            }
        }
        guard let type = provider.registeredTypeIdentifiers.first(where: {
            guard let type = UTType($0) else { return false }
            return type.conforms(to: .data) || type.conforms(to: .content)
        }) else { throw CocoaError(.fileReadUnsupportedScheme) }
        return try await withCheckedThrowingContinuation { continuation in
            provider.loadFileRepresentation(forTypeIdentifier: type) { source, error in
                guard let source else { continuation.resume(throwing: error ?? CocoaError(.fileReadUnknown)); return }
                do {
                    var name = provider.suggestedName ?? source.lastPathComponent
                    if URL(fileURLWithPath: name).pathExtension.isEmpty, !source.pathExtension.isEmpty {
                        name += "." + source.pathExtension
                    }
                    let target = try FileTransferStorage.copy(source, name: name, to: batch, preparation: preparation)
                    continuation.resume(returning: target.path)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

}
