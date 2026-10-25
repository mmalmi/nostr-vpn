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

        let view = NSHostingView(rootView: UpdateBanner(manager: manager))
        let rect = NSRect(x: 0, y: 0, width: 1100, height: 70)
        let window = NSWindow(contentRect: rect, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = view
        view.frame = rect
        view.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        manager.updateInstalling = true
        precondition(!manager.updateInstallEnabled, "Installing must prevent duplicate requests")
        manager.updateInstalling = false

        let verified = UpdateCheck(
            manifest: unverified.manifest, asset: asset,
            isNewer: true, verified: true
        )
        manager.applyUpdateCheck(verified, manual: false)
        precondition(manager.updateInstallEnabled, "Verification must enable installation")
        precondition(manager.updateRetryTask == nil, "Success must cancel the pending retry")
        manager.updateStatus = UpdateError.noNewerVerifiedRelease.localizedDescription
        precondition(root.updateStripeText == manager.updateStatus, "Installation errors must appear in the banner")
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))

        if CommandLine.arguments.count > 1 {
            manager.applyUpdateCheck(unverified, manual: false)
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
            view.layoutSubtreeIfNeeded()
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                fatalError("Could not render the update banner")
            }
            view.cacheDisplay(in: view.bounds, to: bitmap)
            try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
        }
        print("Update verification recovery and banner passed")
    }
}

private struct UpdateBanner: View {
    @ObservedObject var manager: AppManager
    var body: some View { RootView(manager: manager).updateStripe }
}
