import AppKit
import Darwin
import Foundation
import SwiftUI

let githubUpdateManifestUrl = URL(string: "https://api.github.com/repos/mmalmi/nostr-vpn/releases/latest")!
let defaultUpdateManifestUrl = URL(string: "https://upload.iris.to/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/releases%2Fnostr-vpn/latest/release.json")!
let updateRequestTimeout: TimeInterval = 8
let updateUserAgent = "nvpn-updater"
let defaultUpdateStartupDelayNanoseconds: UInt64 = 10 * 1_000_000_000
let defaultUpdateRetryDelayNanoseconds: UInt64 = 60 * 1_000_000_000
let defaultUpdatePollIntervalNanoseconds: UInt64 = 6 * 60 * 60 * 1_000_000_000

@MainActor
final class AppManager: ObservableObject {
    @Published var state: NativeAppState
    @Published var actionInFlight = false
    @Published var actionStatus = ""
    @Published var actionError = ""
    @Published var copiedValue: CopyValue?
    @Published var copiedPeerNpub: String?
    @Published var serviceSettling = false
    @Published var updateChecking = false
    @Published var updateInstalling = false
    @Published var updateAvailable = false
    @Published var updateVersion = ""
    @Published var updateStatus = ""
    @Published var autoCheckUpdates = UserDefaults.standard.object(forKey: "updates.autoCheck") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(autoCheckUpdates, forKey: "updates.autoCheck")
            if autoCheckUpdates {
                startAutomaticUpdateChecks()
            } else {
                stopAutomaticUpdateChecks()
            }
        }
    }
    @Published var autoInstallUpdates = UserDefaults.standard.bool(forKey: "updates.autoInstall") {
        didSet {
            UserDefaults.standard.set(autoInstallUpdates, forKey: "updates.autoInstall")
        }
    }
    let app: FfiApp?
    let fixtureMode: Bool
    var refreshTask: Task<Void, Never>?
    var copyClearTask: Task<Void, Never>?
    var actionStatusClearTask: Task<Void, Never>?
    var serviceSettlementTask: Task<Void, Never>?
    var updateTask: Task<Void, Never>?
    var updateRetryTask: Task<Void, Never>?
    var updatePollTask: Task<Void, Never>?
    var refreshInFlight = false
    var refreshPending = false
    var startupUrlsDrained = false
    var startupUpdateCheckDone = false
    var updateAssetUrl: URL?
    var updateUsesCoreDownload = false
    let updateManifestUrls: [URL] = {
        if let overrideUrl = ProcessInfo.processInfo.environment["NVPN_UPDATE_MANIFEST_URL"]
            .flatMap(URL.init(string:)) {
            return [overrideUrl]
        }
        return [defaultUpdateManifestUrl, githubUpdateManifestUrl]
    }()
    let launchedHidden: Bool

    static var updatePollIntervalNanoseconds: UInt64 {
        if let raw = ProcessInfo.processInfo.environment["NVPN_UPDATE_POLL_SECONDS"],
           let seconds = Double(raw),
           seconds > 0 {
            return UInt64(seconds * 1_000_000_000)
        }
        return defaultUpdatePollIntervalNanoseconds
    }

    init() {
        let fixtureMode = Self.fixtureModeRequested()
        self.fixtureMode = fixtureMode
        self.launchedHidden = CommandLine.arguments.contains("--hidden") && !fixtureMode
        if fixtureMode {
            self.app = nil
            self.state = Self.screenshotFixtureState()
            self.autoCheckUpdates = false
            return
        }

        let dataDir = Self.appDataDir()
        // Pass empty so the FFI falls back to its own CARGO_PKG_VERSION
        // (workspace-inherited). Avoids drift between MARKETING_VERSION in the
        // xcodeproj and the bundled nvpn binary.
        let app = FfiApp(dataDir: dataDir, appVersion: "")
        app.setPrivilegedCommandRunner(runner: AuthorizationServicesPrivilegedCommandRunner())
        self.app = app
        self.state = app.state()
    }

    private static func appDataDir() -> String {
        if let isolatedDataDir = ProcessInfo.processInfo.environment["NVPN_APP_DATA_DIR"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !isolatedDataDir.isEmpty {
            return isolatedDataDir
        }
        return FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?
            .appendingPathComponent("nvpn", isDirectory: true)
            .path ?? ""
    }

    var activeNetwork: NativeNetworkState? {
        state.networks.first(where: { $0.enabled })
    }

    var inactiveNetworks: [NativeNetworkState] {
        state.networks.filter { !$0.enabled }
    }

    var serviceUpdateRecommended: Bool {
        Self.serviceUpdateRecommended(in: state)
    }

    var vpnSwitchEnabled: Bool {
        state.vpnEnabled
    }

    /// Status line shown next to the VPN switch in the header and the tray.
    /// Single source of truth so both stay in sync.
    var vpnStatusText: String {
        if !actionStatus.isEmpty {
            return actionStatus
        }
        if state.exitNodeBlocked {
            return state.exitNodeStatusText.isEmpty ? "Internet blocked" : state.exitNodeStatusText
        }
        if state.exitNodeActive, !state.exitNodeStatusText.isEmpty {
            return state.exitNodeStatusText
        }
        if state.vpnActive {
            return state.vpnStatus.isEmpty ? "VPN on" : state.vpnStatus
        }
        if state.vpnEnabled {
            return state.vpnStatus.isEmpty ? "Turning on" : state.vpnStatus
        }
        if Self.daemonStarting(in: state) {
            return state.vpnStatus
        }
        if Self.serviceUpdateRecommended(in: state) {
            return "Background service needs update"
        }
        return "Off"
    }

    var updateInstallEnabled: Bool {
        updateAvailable && updateUsesCoreDownload && !updateChecking && !updateInstalling
    }

    func start() {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["NVPN_ROSTER_E2E_READY_PATH"],
           !path.isEmpty {
            _ = FileManager.default.createFile(atPath: path, contents: Data())
        }
        #endif
        drainStartupUrls()
        guard !fixtureMode else {
            return
        }
        syncLaunchAgentWithSettings()
        startAutomaticUpdateChecks()
        refresh()
        guard refreshTask == nil else {
            return
        }
        refreshTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                await self?.performRefresh()
                let interval = self?.refreshIntervalNanoseconds ?? Self.idleRefreshIntervalNanoseconds
                try? await Task.sleep(nanoseconds: interval)
            }
        }
    }

    deinit {
        refreshTask?.cancel()
        copyClearTask?.cancel()
        actionStatusClearTask?.cancel()
        serviceSettlementTask?.cancel()
        updateTask?.cancel()
        updateRetryTask?.cancel()
        updatePollTask?.cancel()
    }

    func refresh() {
        Task { @MainActor [weak self] in
            await self?.performRefresh()
        }
    }

    func performRefresh() async {
        guard let app else {
            return
        }
        if refreshInFlight {
            refreshPending = true
            return
        }
        refreshInFlight = true
        defer {
            refreshInFlight = false
        }

        repeat {
            refreshPending = false
            let nextState = await Task.detached {
                app.refresh()
            }.value
            guard !Task.isCancelled else {
                return
            }
            state = nextState
            maybePromptServiceUpdate(nextState)
        } while refreshPending && !Task.isCancelled
    }

    // A refresh shells out to the daemon and republishes the full SwiftUI
    // state. Ten seconds keeps live payment state responsive without making
    // an existing paid session keep the otherwise idle app above the CPU gate.
    static let paidRouteRefreshIntervalNanoseconds: UInt64 = 10_000_000_000
    static let activeVpnRefreshIntervalNanoseconds: UInt64 = 15_000_000_000
    static let idleRefreshIntervalNanoseconds: UInt64 = 30_000_000_000

    var refreshIntervalNanoseconds: UInt64 {
        if actionInFlight || serviceSettling || updateChecking || updateInstalling {
            return 1_000_000_000
        }
        if paidRouteLiveRefreshWanted {
            return Self.paidRouteRefreshIntervalNanoseconds
        }
        if state.vpnEnabled {
            return Self.activeVpnRefreshIntervalNanoseconds
        }
        return Self.idleRefreshIntervalNanoseconds
    }

    var paidRouteLiveRefreshWanted: Bool {
        if state.paidRouteMarket.wallet.lastAction.kind == "topup" {
            return true
        }
        if !state.paidExitSeller.sessions.isEmpty {
            return true
        }
        return state.paidRouteMarket.sessions.contains { session in
            session.allowRouting
                || ["opening", "probing", "active", "paused"].contains(session.lifecycleStatus)
                || ["paid", "free_probe", "grace", "suspended"].contains(session.accessState)
        }
    }

    func dispatch(
        _ action: NativeAppAction,
        status: String = "",
        successStatus: String = "",
        settleService: Bool = false,
        completion: ((Bool) -> Void)? = nil
    ) {
        guard !actionInFlight else {
            completion?(false)
            return
        }
        guard let app else {
            completion?(false)
            return
        }
        actionStatusClearTask?.cancel()
        actionInFlight = true
        actionStatus = status
        actionError = ""
        let joiningDevice: Bool
        switch action {
        case .importJoinRequest, .acceptJoinRequest, .addParticipant:
            joiningDevice = true
        default:
            joiningDevice = false
        }
        Task {
            let nextState = await Task.detached {
                app.dispatch(action: action)
            }.value
            await MainActor.run {
                self.state = nextState
                self.actionInFlight = false
                self.actionStatus = nextState.error.isEmpty ? successStatus : nextState.error
                self.actionError = nextState.error
                self.maybePromptServiceUpdate(nextState)
                if nextState.error.isEmpty, !successStatus.isEmpty {
                    self.clearActionStatus(after: 3)
                }
                if settleService {
                    self.startServiceSettlementPolling()
                } else if joiningDevice, nextState.error.isEmpty {
                    // Approval delivery continues after the local roster is saved.
                    // Observe its receipt without waiting for the idle refresh.
                    self.startServiceSettlementPolling(attempts: 30)
                }
                completion?(nextState.error.isEmpty)
            }
        }
    }

    func toggleVpn() {
        let enabled = !state.vpnEnabled
        if enabled, state.serviceSupported, !state.serviceInstalled {
            installService()
            return
        }
        dispatch(
            enabled ? .connectVpn : .disconnectVpn,
            status: enabled ? "Turning VPN on" : "Turning VPN off"
        )
    }
}
