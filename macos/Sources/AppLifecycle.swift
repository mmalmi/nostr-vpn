import AppKit
import Darwin
import Foundation

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private let singleInstance = SingleInstanceCoordinator()
    private weak var manager: AppManager?
    private var pendingUrls: [URL] = []
    private var startsHidden = false
    private var trayController: TrayController?

    func applicationWillFinishLaunching(_ notification: Notification) {
        singleInstance.onOpen = { [weak self] urls, activate in
            self?.route(urls: urls, activate: activate)
        }
        if !singleInstance.claimOrNotifyCurrentLaunch() {
            NSApp.terminate(nil)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installApplicationIcon()
        observeWindows()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showMainWindow()
        return false
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        route(urls: urls, activate: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        singleInstance.release()
    }

    func configure(manager: AppManager) {
        self.manager = manager
        startsHidden = manager.launchedHidden && !Self.launchArgumentsContainDeepLink && pendingUrls.isEmpty
        observeWindows()
        if trayController == nil {
            trayController = TrayController(manager: manager) { [weak self] in
                self?.showMainWindow()
            }
        }
        route(urls: pendingUrls, activate: !startsHidden)
        pendingUrls.removeAll()
        if startsHidden {
            hideMainWindowSoon()
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard sender.title == "Nostr VPN", manager?.state?.closeToTrayOnClose == true else {
            return true
        }
        sender.orderOut(nil)
        return false
    }

    func showMainWindow() {
        startsHidden = false
        manager?.refresh()
        NSApp.unhide(nil)
        NSApp.activate()
        observeWindows()
        if let window = NSApp.windows.first(where: { $0.title == "Nostr VPN" }) ?? NSApp.windows.first {
            window.makeKeyAndOrderFront(nil)
        }
    }

    private func route(urls: [URL], activate: Bool) {
        guard !urls.isEmpty else {
            if activate {
                showMainWindow()
            }
            return
        }
        guard let manager else {
            pendingUrls.append(contentsOf: urls)
            return
        }
        for url in urls {
            manager.handle(url: url)
        }
        if activate {
            showMainWindow()
        }
    }

    private func observeWindows() {
        for window in NSApp.windows where window.title == "Nostr VPN" {
            window.delegate = self
            configureMainWindow(window)
        }
    }

    private func configureMainWindow(_ window: NSWindow) {
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isOpaque = true
        window.backgroundColor = .windowBackgroundColor
        window.isMovableByWindowBackground = true
        window.styleMask.insert(.fullSizeContentView)
        window.toolbar?.isVisible = false
        if Self.launchArgumentsContainScreenshotMode {
            window.level = .floating
            sizeWindowForScreenshot(window)
        } else {
            window.level = .normal
        }
    }

    private func sizeWindowForScreenshot(_ window: NSWindow) {
        let visibleFrame = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame ?? window.frame
        let width = min(CGFloat(1280), max(CGFloat(880), visibleFrame.width - 80))
        let height = min(CGFloat(1040), max(CGFloat(620), visibleFrame.height - 80))
        let originX = visibleFrame.minX + 40
        let originY = max(visibleFrame.minY, visibleFrame.maxY - height - 40)
        window.setFrame(NSRect(x: originX, y: originY, width: width, height: height), display: true)
    }

    private func installApplicationIcon() {
        let icon =
            Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
                .flatMap(NSImage.init(contentsOf:))
            ?? NSImage(named: "AppIcon")
            ?? NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath)
        NSApp.applicationIconImage = icon
    }

    private func hideMainWindowSoon() {
        DispatchQueue.main.async { [weak self] in
            guard self?.startsHidden == true else { return }
            NSApp.windows.first(where: { $0.title == "Nostr VPN" })?.orderOut(nil)
        }
    }

    private static var launchArgumentsContainDeepLink: Bool {
        CommandLine.arguments.contains { $0.starts(with: "nvpn://") }
    }

    private static var launchArgumentsContainScreenshotMode: Bool {
        CommandLine.arguments.contains { $0.starts(with: "--nvpn-screenshot-") }
    }
}

final class SingleInstanceCoordinator: NSObject {
    private let notificationName = Notification.Name("fi.siriusbusiness.nvpn.open")
    private var lockFds: [Int32] = []
    var onOpen: (([URL], Bool) -> Void)?

    func claimOrNotifyCurrentLaunch() -> Bool {
        var acquiredFds: [Int32] = []
        for lockPath in Self.lockFilePaths() {
            let fd = open(lockPath, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
            guard fd >= 0 else {
                continue
            }
            if flock(fd, LOCK_EX | LOCK_NB) == 0 {
                acquiredFds.append(fd)
                continue
            }

            close(fd)
            Self.release(fds: acquiredFds)
            notifyCurrentLaunch()
            return false
        }

        if acquiredFds.isEmpty {
            if Self.activateRunningCopy(activate: Self.shouldActivateCurrentLaunch) {
                notifyCurrentLaunch()
                return false
            }
        }

        lockFds = acquiredFds
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(receiveOpenNotification(_:)),
            name: notificationName,
            object: nil
        )
        return true
    }

    func release() {
        DistributedNotificationCenter.default().removeObserver(self)
        Self.release(fds: lockFds)
        lockFds = []
    }

    @objc private func receiveOpenNotification(_ notification: Notification) {
        let urls = (notification.userInfo?["urls"] as? [String] ?? [])
            .compactMap(URL.init(string:))
        let activate = notification.userInfo?["activate"] as? Bool ?? true
        onOpen?(urls, activate)
    }

    private func notifyCurrentLaunch() {
        DistributedNotificationCenter.default().postNotificationName(
            notificationName,
            object: nil,
            userInfo: [
                "urls": Self.startupUrls().map(\.absoluteString),
                "activate": Self.shouldActivateCurrentLaunch,
            ],
            deliverImmediately: true
        )
    }

    private static func lockFilePaths() -> [String] {
        if let isolatedDataDir = ProcessInfo.processInfo.environment["NVPN_APP_DATA_DIR"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !isolatedDataDir.isEmpty {
            let dir = URL(fileURLWithPath: isolatedDataDir, isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return [dir.appendingPathComponent("NostrVpnMac.lock").path]
        }
        var paths = ["/tmp/fi.siriusbusiness.nvpn.gui.\(getuid()).lock"]
        if let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?
            .appendingPathComponent("nvpn", isDirectory: true) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            paths.append(dir.appendingPathComponent("NostrVpnMac.lock").path)
        }
        return paths
    }

    private static func release(fds: [Int32]) {
        for fd in fds {
            flock(fd, LOCK_UN)
            close(fd)
        }
    }

    private static func activateRunningCopy(activate: Bool) -> Bool {
        let currentPid = getpid()
        guard let app = NSWorkspace.shared.runningApplications.first(where: { app in
            app.processIdentifier != currentPid
                && app.activationPolicy == .regular
                && app.bundleIdentifier == "fi.siriusbusiness.nvpn"
        }) else {
            return false
        }
        if activate {
            app.activate(options: [.activateAllWindows])
        }
        return true
    }

    private static func startupUrls() -> [URL] {
        CommandLine.arguments.compactMap { argument in
            guard argument.starts(with: "nvpn://") else {
                return nil
            }
            return URL(string: argument)
        }
    }

    private static var shouldActivateCurrentLaunch: Bool {
        if !startupUrls().isEmpty {
            return true
        }
        return !CommandLine.arguments.contains("--hidden")
    }
}
