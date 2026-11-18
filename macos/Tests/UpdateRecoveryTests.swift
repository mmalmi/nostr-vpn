import AppKit
import SwiftUI

@main
struct UpdateRecoveryTests {
    @MainActor static func main() throws {
        NSApplication.shared.setActivationPolicy(.prohibited)
        let manager = AppManager()
        precondition(manager.fixtureMode)
        manager.autoCheckUpdates = true
        manager.autoInstallUpdates = false
        defer { manager.stopAutomaticUpdateChecks() }
        let outputDir = CommandLine.arguments.count > 1 ? URL(fileURLWithPath: CommandLine.arguments[1]) : nil

        let asset = ReleaseAsset(name: "nostr-vpn-v99.0.0-macos-arm64.app.tar.gz", path: "")
        let unverified = UpdateCheck(
            manifest: ReleaseManifest(tag: "v99.0.0", assets: [asset]),
            asset: asset, isNewer: true, verified: false
        )
        manager.applyUpdateCheck(unverified, manual: false)
        precondition(manager.updateAvailable)
        precondition(manager.updateInstallEnabled, "Install must be available so the download can perform verification")
        precondition(manager.updateRetryTask != nil, "An inconclusive check must retry without waiting six hours")
        let root = RootView(manager: manager)
        precondition(root.updateStripeText == manager.updateStatus)
        let verified = UpdateCheck(
            manifest: unverified.manifest, asset: asset,
            isNewer: true, verified: true
        )
        manager.applyUpdateCheck(verified, manual: false)
        precondition(manager.updateInstallEnabled, "Verification must enable installation")
        precondition(manager.updateRetryTask == nil, "Success must cancel the pending retry")
        try snapshot(manager, "01-available", to: outputDir)

        // The core reports how an install that restarted the app ended.
        let configDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nvpn-update-recovery-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: configDir) }
        let configPath = configDir.appendingPathComponent("config.toml").path
        let marker = configDir.appendingPathComponent("update-pending.json")

        try Data(#"{"version":"v99.0.0"}"#.utf8).write(to: marker)
        let unfinished = runDesktopUpdate("resume", currentVersion: "4.1.22", configPath: configPath)
        manager.applyUpdateView(unfinished)
        precondition(unfinished.step == "failed" && unfinished.active && !unfinished.busy)
        precondition(root.updateStripeText == "The update to v99.0.0 didn't finish.", root.updateStripeText)
        precondition(unfinished.primaryAction == "retry" && unfinished.primaryLabel == "Retry")
        precondition(unfinished.secondaryLabel == "Download page", "Without a download the fallback is the website")
        precondition(manager.updateBannerVisible)
        try snapshot(manager, "02-did-not-finish", to: outputDir)
        try snapshotSettings(manager, "03-did-not-finish-settings", to: outputDir)

        manager.updateAvailable = false
        try Data(#"{"version":"v99.0.0"}"#.utf8).write(to: marker)
        let updated = runDesktopUpdate("resume", currentVersion: "99.0.0", configPath: configPath)
        manager.applyUpdateView(updated)
        precondition(updated.step == "updated" && root.updateStripeText == "Updated to v99.0.0")
        precondition(manager.updateBannerVisible, "The result shows even when no update is pending")
        precondition(!FileManager.default.fileExists(atPath: marker.path), "The result is reported once")
        try snapshot(manager, "04-updated", to: outputDir)
        print("Update steps, failure with Retry, and the result after restart passed")
    }

    @MainActor static func snapshot(_ manager: AppManager, _ name: String, to dir: URL?) throws {
        try render(NSHostingView(rootView: UpdateBanner(manager: manager)), width: 1100, height: 44, name, to: dir)
    }

    @MainActor static func snapshotSettings(_ manager: AppManager, _ name: String, to dir: URL?) throws {
        try render(NSHostingView(rootView: SystemSettings(manager: manager)), width: 900, height: 230, name, to: dir)
    }

    @MainActor static func render(_ view: NSView, width: CGFloat, height: CGFloat, _ name: String, to dir: URL?) throws {
        let rect = NSRect(x: 0, y: 0, width: width, height: height)
        let window = NSWindow(contentRect: rect, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = view
        view.frame = rect
        view.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        guard let dir else {
            return
        }
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            fatalError("Could not render \(name)")
        }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try bitmap.representation(using: .png, properties: [:])!
            .write(to: dir.appendingPathComponent("\(name).png"))
    }
}

private struct UpdateBanner: View {
    @ObservedObject var manager: AppManager
    var body: some View { RootView(manager: manager).updateStripe }
}

private struct SystemSettings: View {
    @ObservedObject var manager: AppManager
    var body: some View {
        RootView(manager: manager).systemSettings
            .padding(16)
            .background(Color(nsColor: .windowBackgroundColor))
    }
}
