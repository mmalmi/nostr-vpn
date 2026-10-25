import AppKit
import Darwin
import Foundation
import SwiftUI

extension AppManager {
    func checkForUpdates(manual: Bool = true) {
        guard !fixtureMode else {
            updateStatus = manual ? "Fixture mode" : ""
            return
        }
        guard !updateChecking, !updateInstalling else {
            return
        }
        if manual {
            updateRetryTask?.cancel()
            updateRetryTask = nil
        }
        updateTask?.cancel()
        updateChecking = true
        updateStatus = "Checking for updates"
        updateTask = Task { [weak self] in
            guard let self else {
                return
            }
            do {
                let check = try await self.fetchUpdateCheck()
                await MainActor.run {
                    self.applyUpdateCheck(check, manual: manual)
                }
            } catch {
                await MainActor.run {
                    self.updateChecking = false
                    self.updateStatus = error.localizedDescription
                    if self.autoCheckUpdates {
                        self.scheduleAutomaticUpdateCheck(
                            after: defaultUpdateRetryDelayNanoseconds
                        )
                    }
                }
            }
        }
    }

    func startAutomaticUpdateChecks() {
        guard !fixtureMode else {
            return
        }
        guard autoCheckUpdates else {
            stopAutomaticUpdateChecks()
            return
        }
        if !startupUpdateCheckDone {
            startupUpdateCheckDone = true
            scheduleAutomaticUpdateCheck(after: defaultUpdateStartupDelayNanoseconds)
        }
        guard updatePollTask == nil else {
            return
        }
        updatePollTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.updatePollIntervalNanoseconds)
                guard let self, !Task.isCancelled else {
                    return
                }
                guard self.autoCheckUpdates else {
                    self.stopAutomaticUpdateChecks()
                    return
                }
                self.checkForUpdates(manual: false)
            }
        }
    }

    func stopAutomaticUpdateChecks() {
        startupUpdateCheckDone = false
        updateRetryTask?.cancel()
        updateRetryTask = nil
        updatePollTask?.cancel()
        updatePollTask = nil
    }

    func scheduleAutomaticUpdateCheck(after delayNanoseconds: UInt64) {
        guard autoCheckUpdates else {
            return
        }
        updateRetryTask?.cancel()
        updateRetryTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(nanoseconds: delayNanoseconds)
            } catch {
                return
            }
            guard let self, self.autoCheckUpdates, !Task.isCancelled else {
                return
            }
            self.updateRetryTask = nil
            self.checkForUpdates(manual: false)
        }
    }

    func installUpdate() {
        guard updateInstallEnabled else { return }
        installCoreDownloadedUpdate()
    }

    func fetchUpdateCheck() async throws -> UpdateCheck {
        let (currentVersion, configPath) = await MainActor.run {
            (self.state.appVersion, self.state.configPath)
        }
        let result = try await runCoreUpdateCheck(
            currentVersion: currentVersion,
            configPath: configPath
        )
        let asset = result.asset.isEmpty ? nil : ReleaseAsset(name: result.asset, path: result.url ?? "")
        return UpdateCheck(
            manifest: ReleaseManifest(tag: result.tag, assets: asset.map { [$0] } ?? []),
            asset: asset,
            isNewer: result.available,
            verified: result.verified
        )
    }

    @MainActor
    func applyUpdateCheck(_ check: UpdateCheck, manual: Bool, allowAutoInstall: Bool = true) {
        updateRetryTask?.cancel()
        updateRetryTask = nil
        updateChecking = false
        updateAvailable = check.isNewer
        updateVersion = check.manifest.tag
        if check.isNewer {
            updateStatus = check.asset != nil ? "Update \(check.manifest.tag) available" : "Update \(check.manifest.tag) found without a macOS asset"
            if !check.verified || check.asset == nil {
                scheduleAutomaticUpdateCheck(after: defaultUpdateRetryDelayNanoseconds)
            } else if allowAutoInstall, autoInstallUpdates {
                installUpdate()
            }
        } else if manual {
            updateStatus = "Up to date"
        } else {
            updateStatus = ""
        }
    }

    func installCoreDownloadedUpdate() {
        guard !updateInstalling else {
            return
        }
        updateInstalling = true
        updateStatus = "Downloading \(updateVersion)"
        Task { [weak self] in
            guard let self else {
                return
            }
            do {
                let downloadDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent("NostrVpnDownloads", isDirectory: true)
                let (currentVersion, configPath) = await MainActor.run {
                    (self.state.appVersion, self.state.configPath)
                }
                let result = try await runCoreUpdateDownload(
                    currentVersion: currentVersion,
                    downloadDir: downloadDir,
                    configPath: configPath
                )
                guard result.verified else {
                    throw UpdateError.unverifiedSource(result.source)
                }
                guard result.available else {
                    throw UpdateError.noNewerVerifiedRelease
                }
                guard let path = result.path, !path.isEmpty else {
                    throw UpdateError.missingDownloadedPath
                }
                try await MainActor.run {
                    try self.installDownloadedUpdate(URL(fileURLWithPath: path))
                }
            } catch {
                await MainActor.run {
                    self.updateInstalling = false
                    self.updateStatus = error.localizedDescription
                }
            }
        }
    }

    func drainStartupUrls() {
        guard !startupUrlsDrained else {
            return
        }
        startupUrlsDrained = true
        for argument in CommandLine.arguments where argument.starts(with: "nvpn://") {
            if let url = URL(string: argument) {
                handle(url: url)
            }
        }
    }

    func syncLaunchAgentWithSettings() {
        do {
            try configureLaunchAgent(
                enabled: state.startupSettingsSupported && state.launchOnStartup,
                loadCurrentSession: false
            )
        } catch {
            actionStatus = error.localizedDescription
        }
    }

    func configureLaunchAgent(enabled: Bool, loadCurrentSession: Bool) throws {
        let manager = FileManager.default
        let agentsDir = manager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        let plistUrl = agentsDir.appendingPathComponent("fi.siriusbusiness.nvpn.plist")
        if enabled {
            guard let executable = Bundle.main.executableURL?.path else {
                throw LaunchAgentError.missingExecutable
            }
            try manager.createDirectory(at: agentsDir, withIntermediateDirectories: true)
            try launchAgentPlist(executable: executable).write(to: plistUrl, atomically: true, encoding: .utf8)
            if loadCurrentSession {
                _ = runLaunchctl(["bootstrap", "gui/\(getuid())", plistUrl.path])
            }
        } else {
            if loadCurrentSession {
                _ = runLaunchctl(["bootout", "gui/\(getuid())", plistUrl.path])
            }
            if manager.fileExists(atPath: plistUrl.path) {
                try manager.removeItem(at: plistUrl)
            }
        }
    }

    func installDownloadedUpdate(_ archiveUrl: URL) throws {
        updateStatus = "Installing \(updateVersion)"
        if archiveUrl.lastPathComponent.hasSuffix(".app.tar.gz") {
            let unpackDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("NostrVpnUpdate-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
            try runProcess("/usr/bin/tar", arguments: ["-xzf", archiveUrl.path, "-C", unpackDir.path])
            guard let newApp = findAppBundle(in: unpackDir) else {
                throw UpdateError.missingAppBundle
            }
            let script = try updateInstallScript()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = [script.path, Bundle.main.bundleURL.path, newApp.path]
            try process.run()
            NSApp.terminate(nil)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([archiveUrl])
            updateInstalling = false
            updateStatus = "Downloaded \(archiveUrl.lastPathComponent)"
        }
    }

    func startServiceSettlementPolling(attempts: Int = 8) {
        serviceSettlementTask?.cancel()
        serviceSettling = true
        serviceSettlementTask = Task { [weak self] in
            for _ in 0..<attempts {
                guard !Task.isCancelled else {
                    return
                }
                try? await Task.sleep(nanoseconds: 700_000_000)
                guard let self else {
                    return
                }
                await self.performRefresh()
            }
            await MainActor.run {
                self?.serviceSettling = false
            }
        }
    }
}
