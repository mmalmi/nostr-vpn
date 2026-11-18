import Darwin
import Foundation
import UserNotifications

/// The service replaces state.json atomically. Observe its directory rather than
/// an old file inode, without increasing the app's expensive core refresh rate.
final class FileTransferObservation: @unchecked Sendable {
    private let queue = DispatchQueue(label: "nvpn.files.observe", qos: .utility)
    private var source: DispatchSourceFileSystemObject?
    private var work: DispatchWorkItem?
    private var root: URL?
    private var watchingTransfers = false
    private var generation = 0
    private var lastIdentity: String?
    private let onChange: @Sendable ([FileTransferPresentation]) -> Void

    init(onChange: @escaping @Sendable ([FileTransferPresentation]) -> Void) { self.onChange = onChange }

    func start(in supportDir: URL) {
        queue.async { [weak self] in
            guard let self, self.root != supportDir else { return }
            self.clear()
            self.root = supportDir
            self.watchDirectory()
        }
    }
    func stop() { queue.async { [weak self] in self?.clear() } }
    private func clear() {
        stopWatching()
        root = nil
    }
    private func stopWatching() {
        generation += 1
        work?.cancel(); work = nil
        source?.cancel(); source = nil
        watchingTransfers = false
        lastIdentity = nil
    }
    private func watchDirectory() {
        guard let root else { return }
        let transfers = root.appendingPathComponent("file-transfers", isDirectory: true)
        let flags = O_EVTONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        var fd = open(transfers.path, flags)
        let foundTransfers = fd >= 0
        if !foundTransfers {
            if source != nil, !watchingTransfers { return }
            fd = open(root.path, flags)
        }
        guard fd >= 0 else { return }
        stopWatching()
        let watchedFD = fd
        let expected = generation
        let invalidated: DispatchSource.FileSystemEvent = [.rename, .delete, .revoke]
        let watcher = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: watchedFD, eventMask: invalidated.union(.write), queue: queue
        )
        source = watcher
        watchingTransfers = foundTransfers
        watcher.setRegistrationHandler { [weak self] in
            guard let self, self.generation == expected else { return }
            // A replacement between open and registration may have sent its rename already.
            var opened = stat(), current = stat()
            let path = foundTransfers ? transfers.path : root.path
            if fstat(watchedFD, &opened) != 0 || lstat(path, &current) != 0
                || opened.st_dev != current.st_dev || opened.st_ino != current.st_ino {
                self.stopWatching()
                self.watchDirectory()
            } else if foundTransfers {
                self.read()
            } else {
                self.watchDirectory()
            }
        }
        watcher.setEventHandler { [weak self] in
            guard let self, self.generation == expected, let events = self.source?.data else { return }
            if !events.intersection(invalidated).isEmpty {
                self.stopWatching()
                self.watchDirectory()
            } else if foundTransfers {
                self.scheduleRead()
            } else {
                self.watchDirectory()
            }
        }
        watcher.setCancelHandler { close(watchedFD) }
        watcher.resume()
    }
    private func scheduleRead() {
        guard work == nil else { return }
        let expected = generation
        let next = DispatchWorkItem { [weak self] in
            guard let self, self.generation == expected else { return }
            self.work = nil
            self.read()
        }
        work = next
        queue.asyncAfter(deadline: .now() + .milliseconds(150), execute: next)
    }
    private func read() {
        guard let root else { return }
        let directory = root.appendingPathComponent("file-transfers", isDirectory: true)
        let fd = open(directory.appendingPathComponent("state.json").path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { return }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size >= 0, info.st_size <= 4 * 1024 * 1024 else { return }
        let identity = "\(info.st_dev):\(info.st_ino):\(info.st_size):\(info.st_mtimespec.tv_sec):\(info.st_mtimespec.tv_nsec)"
        guard identity != lastIdentity,
              let data = try? file.read(upToCount: 4 * 1024 * 1024 + 1), data.count <= 4 * 1024 * 1024,
              let rows = try? JSONDecoder().decode([FileTransferPresentation].self, from: data) else { return }
        lastIdentity = identity
        onChange(rows)
    }
    deinit { source?.cancel(); work?.cancel() }
}

/// The iOS tunnel is the only iOS notification producer, so alerts still work
/// while the containing app is suspended and do not duplicate app-side alerts.
final class FileTransferNotifications: @unchecked Sendable {
    static let offerCategory = "nvpn.files.offer"
    static let completedCategory = "nvpn.files.received"
    private var previous: [String: String] = [:]
    private var initialized = false
    private let lock = NSLock()
    private var pending: Set<String> = []
    private var retryAfter: [String: TimeInterval] = [:]
    private var sent = Set(UserDefaults.standard.stringArray(forKey: "file-notification-receipts") ?? [])

    static func registerActions() {
        let accept = UNNotificationAction(identifier: "accept", title: "Accept", options: [.foreground])
        let decline = UNNotificationAction(identifier: "decline", title: "Decline", options: [.foreground, .destructive])
        let show = UNNotificationAction(identifier: "show", title: "Show files", options: [.foreground])
        UNUserNotificationCenter.current().setNotificationCategories([
            UNNotificationCategory(identifier: offerCategory, actions: [accept, decline], intentIdentifiers: []),
            UNNotificationCategory(identifier: completedCategory, actions: [show], intentIdentifiers: [])
        ])
    }
    func update(_ rows: [FileTransferPresentation]) {
        lock.lock()
        defer { lock.unlock() }
        let center = UNUserNotificationCenter.current()
        for row in rows where !row.isSender {
            let key = "\(row.id):\(row.status)"
            let offered = row.status == "offered"
            let received = row.status == "completed" && initialized
                && previous[row.id].map { ["offered", "connecting", "transferring", "paused", "preparing"].contains($0) } == true
            if !offered && (previous[row.id] == "offered" || (!initialized && sent.contains("\(row.id):offered"))) {
                center.removeDeliveredNotifications(withIdentifiers: ["nvpn-file-\(row.id)-offered"])
                center.removePendingNotificationRequests(withIdentifiers: ["nvpn-file-\(row.id)-offered"])
            }
            guard offered || received, !sent.contains(key), !pending.contains(key),
                  (retryAfter[key] ?? 0) <= ProcessInfo.processInfo.systemUptime else { continue }
            pending.insert(key)
            let content = UNMutableNotificationContent()
            content.title = offered ? "Files from \(row.person)" : "Received from \(row.person)"
            content.body = "\(row.title) · \(FileTransferPresentation.bytes(row.totalBytes))"
            content.categoryIdentifier = offered ? Self.offerCategory : Self.completedCategory
            content.userInfo = ["fileTransferID": row.id]
            content.threadIdentifier = "nvpn-files"
            center.getNotificationSettings { [weak self] settings in
                guard let self, self.isCurrent(row.id, status: row.status),
                      settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
                    self?.finished(key, scheduled: false)
                    return
                }
                center.add(UNNotificationRequest(identifier: "nvpn-file-\(row.id)-\(row.status)", content: content, trigger: nil)) { error in
                    self.finished(key, scheduled: error == nil)
                    if error == nil && !self.isCurrent(row.id, status: row.status) {
                        let identifier = "nvpn-file-\(row.id)-\(row.status)"
                        center.removeDeliveredNotifications(withIdentifiers: [identifier])
                        center.removePendingNotificationRequests(withIdentifiers: [identifier])
                    }
                }
            }
        }
        previous = Dictionary(rows.map { ($0.id, $0.status) }, uniquingKeysWith: { _, latest in latest })
        initialized = true
        if sent.count > 256 {
            let current = Set(rows.map(\.id))
            sent = Set(sent.filter { current.contains(String($0.prefix(while: { $0 != ":" }))) })
        }
        retryAfter = retryAfter.filter { previous[String($0.key.prefix(while: { $0 != ":" }))] != nil }
    }
    private func finished(_ key: String, scheduled: Bool) {
        lock.lock(); defer { lock.unlock() }
        pending.remove(key)
        if scheduled {
            sent.insert(key)
            UserDefaults.standard.set(sent.sorted(), forKey: "file-notification-receipts")
        } else { retryAfter[key] = ProcessInfo.processInfo.systemUptime + 30 }
    }
    private func isCurrent(_ id: String, status: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return previous[id] == status
    }
}

final class FileNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    var onAction: (@MainActor (String, String) -> Void)?
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if let id = response.notification.request.content.userInfo["fileTransferID"] as? String {
            DispatchQueue.main.async { [weak self] in self?.onAction?(id, response.actionIdentifier) }
        }
        completionHandler()
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list])
    }
}
