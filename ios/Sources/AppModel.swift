import Foundation
import Darwin
import SwiftUI
import UIKit

@MainActor
final class AppModel: ObservableObject {
    nonisolated static let appGroupIdentifier: String = {
        guard let value = Bundle.main.object(
            forInfoDictionaryKey: "NVPNAppGroupIdentifier"
        ) as? String,
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            fatalError("NVPNAppGroupIdentifier is missing from Info.plist")
        }
        return value
    }()
    static let configFileName = "config.toml"
    static let mobileRuntimeStateFileName = "mobile-runtime-state.json"
    static let vpnDisclosureAcceptedKey = "vpnDisclosureAccepted"
    static let vpnDisclosurePromptMessage = "Review VPN data use before turning VPN on."
    private static let normalRefreshNanoseconds: UInt64 = 4_000_000_000
    private static let onboardingRefreshNanoseconds: UInt64 = 1_000_000_000

    @Published var state: AppState
    @Published var actionInFlight = false
    @Published var statusMessage = ""
    @Published var copiedValue = ""
    @Published var vpnDisclosurePromptVisible = false

    var core: NativeCoreClient?
    let vpnController = PacketTunnelController()
    let vpnDesiredState = VpnDesiredStateStore()
    let supportDir: URL?
    let fixtureMode: Bool
    private var refreshTask: Task<Void, Never>?
    var copyClearTask: Task<Void, Never>?
    var tunnelConfigSyncTask: Task<Void, Never>?
    var packetTunnelTransitionTask: Task<Void, Never>?
    var packetTunnelTransitionGeneration: UInt64 = 0
    var pendingVpnTransitionEnabled: Bool?
    var startupTunnelReconciliationTask: Task<Void, Never>?
    var startupTunnelReconciliationGeneration: UInt64 = 0
    private var sceneIsActive = false
    private var pendingOpenURLs: [URL] = []
    var launchAutomationHandled = false
    var tunnelAppConfigRefreshInFlight = false
    var tunnelRuntimeRefreshInFlight = false
    var tunnelStateRefreshGeneration: UInt64 = 0
    var appStoreTunnelRefreshPending = false
    #if DEBUG
    var lifecycleProbeResultName: String?
    var lifecycleProbeRunId = ""
    var lifecycleProbeTransition = 0
    var lifecycleProbeHistory: [[String: Any]] = []
    #endif

    enum PacketTunnelOperation {
        case setEnabled(Bool, force: Bool)
        case syncConfig(reason: String, force: Bool)
    }

    init() {
        fixtureMode = Self.fixtureModeRequested()
        if fixtureMode {
            supportDir = nil
            core = nil
            state = ScreenshotFixtures.state()
            return
        }

        guard let appGroupSupportDir = Self.supportDirectory() else {
            supportDir = nil
            core = nil
            var unavailable = AppState()
            unavailable.error = "Shared app storage is unavailable. Reinstall a correctly signed build."
            state = unavailable
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: appGroupSupportDir,
                withIntermediateDirectories: true
            )
            try Self.migrateLegacySupportDirectoryIfNeeded(to: appGroupSupportDir)
            try Self.seedMobileConfig(in: appGroupSupportDir, deviceName: Self.deviceName())
        } catch {
            supportDir = nil
            core = nil
            var unavailable = AppState()
            unavailable.error = "Shared app storage setup failed: \(error.localizedDescription)"
            state = unavailable
            NSLog("nvpn-app: shared storage setup failed: \(String(describing: error))")
            return
        }
        supportDir = appGroupSupportDir
        // Pass empty so the FFI falls back to its own CARGO_PKG_VERSION
        // (workspace-inherited). Avoids drift between MARKETING_VERSION in the
        // xcodeproj and the bundled nvpn binary.
        let client = NativeCoreClient(dataDir: appGroupSupportDir.path, appVersion: "")
        core = client
        let compatibility = Self.appStoreCompatibleState(client.state(), core: client)
        state = compatibility.state
        appStoreTunnelRefreshPending =
            compatibility.removedPaidConfiguration && compatibility.vpnWasRunning
        #if DEBUG
        NSLog("nvpn-app: shared storage ready at \(appGroupSupportDir.path)")
        #endif
        debugLog("init args=\(Self.redactedDebugArguments(ProcessInfo.processInfo.arguments))")
    }

    deinit {
        refreshTask?.cancel()
        tunnelConfigSyncTask?.cancel()
        packetTunnelTransitionTask?.cancel()
        startupTunnelReconciliationTask?.cancel()
        core?.close()
    }

    var activeNetwork: NetworkState? {
        state.activeNetwork
    }

    func start() {
        guard !fixtureMode else {
            return
        }
        let appStoreReconciliationScheduled =
            reconcileAppStoreTunnelAfterSanitization(reason: "startup")
        guard refreshTask == nil else {
            return
        }
        let desiredVpnEnabled = vpnDesiredState.restore(runtimeEnabled: state.vpnEnabled)
        let restoredStartAllowed = !desiredVpnEnabled
            || AppStorePolicy.allowsVpnStart(
                disclosureAccepted: UserDefaults.standard.bool(
                    forKey: Self.vpnDisclosureAcceptedKey
                )
            )
        if !restoredStartAllowed {
            requireVpnDisclosureReview()
            if pendingVpnTransitionEnabled != false {
                setVpnEnabled(false, force: true)
            }
        } else if pendingVpnTransitionEnabled == nil,
                  desiredVpnEnabled != state.vpnEnabled
        {
            state.vpnEnabled = desiredVpnEnabled
        }
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                let delay = self?.activeNetwork == nil
                    ? Self.onboardingRefreshNanoseconds
                    : Self.normalRefreshNanoseconds
                do {
                    try await Task.sleep(nanoseconds: delay)
                } catch {
                    return
                }
                self?.refresh()
            }
        }
        let launchAutomationHandled = runLaunchAutomationIfRequested()
        if !launchAutomationHandled {
            if let pendingVpnTransitionEnabled, packetTunnelTransitionTask == nil {
                enqueuePacketTunnelOperation(
                    .setEnabled(pendingVpnTransitionEnabled, force: true)
                )
            } else if pendingVpnTransitionEnabled == nil && !appStoreReconciliationScheduled {
                reconcilePacketTunnelAtStartup()
            }
        }
    }

    func handleScenePhase(_ phase: ScenePhase) {
        guard !fixtureMode else {
            return
        }
        switch phase {
        case .background:
            sceneIsActive = false
            suspendNativeCore()
        case .active:
            sceneIsActive = true
            resumeNativeCore()
            drainPendingOpenURLs()
        case .inactive:
            sceneIsActive = false
            break
        @unknown default:
            break
        }
    }

    private func suspendNativeCore() {
        refreshTask?.cancel()
        refreshTask = nil
        tunnelConfigSyncTask?.cancel()
        tunnelConfigSyncTask = nil
        let preservePendingVpnTransition = pendingVpnTransitionEnabled != nil
            && packetTunnelTransitionTask != nil
        if !preservePendingVpnTransition {
            packetTunnelTransitionGeneration &+= 1
            packetTunnelTransitionTask?.cancel()
            packetTunnelTransitionTask = nil
        }
        startupTunnelReconciliationGeneration &+= 1
        startupTunnelReconciliationTask?.cancel()
        startupTunnelReconciliationTask = nil
        actionInFlight = false
        // A provider-message task can be frozen while iOS suspends the app.
        // Invalidate it so foregrounding can immediately pull transactional
        // state (notably a join approval) from the still-running packet tunnel.
        tunnelStateRefreshGeneration &+= 1
        tunnelAppConfigRefreshInFlight = false
        tunnelRuntimeRefreshInFlight = false
        core?.close()
        core = nil
        #if DEBUG
        writeDebugLifecycleProbe(phase: "background")
        #endif
    }

    private func resumeNativeCore() {
        if core == nil, let supportDir {
            let client = NativeCoreClient(dataDir: supportDir.path, appVersion: "")
            core = client
            adoptAppStoreCompatibleState(client.state(), core: client, reason: "foreground")
        }
        #if DEBUG
        writeDebugLifecycleProbe(phase: "active")
        #endif
        start()
        refresh()
    }

    func refresh() {
        guard let core else {
            state.rev += 1
            return
        }
        let hadActiveNetwork = activeNetwork != nil
        let removedPaidConfiguration = adoptAppStoreCompatibleState(
            core.refresh(),
            core: core,
            reason: "app refresh"
        )
        if !removedPaidConfiguration {
            refreshTunnelSidecarState()
        }
        if !hadActiveNetwork, activeNetwork != nil {
            ensureAutoconnectPacketTunnel(reason: "network joined")
        }
    }

    @discardableResult
    func dispatch(_ action: [String: Any], status: String = "") -> Bool {
        guard !actionInFlight else {
            return false
        }
        let actionType = action["type"] as? String ?? ""
        if AppStorePolicy.blocks(action) {
            var unavailable = state
            unavailable.error = "Cashu wallet and paid exit-node features are unavailable in the iOS build."
            state = unavailable
            statusMessage = unavailable.error
            return false
        }
        actionInFlight = true
        statusMessage = status
        let updateSettingKeys = (action["patch"] as? [String: Any])
            .map { Set($0.keys) } ?? []
        let requiresPacketTunnelConfigSync = actionRequiresPacketTunnelConfigSync(
            actionType,
            updateSettingKeys: updateSettingKeys
        )
        if fixtureMode {
            state = ScreenshotFixtures.dispatch(action, state: state)
        } else if let core {
            let nativeStateBeforeAction = core.state()
            let nativeState = core.dispatch(action)
            adoptAppStoreCompatibleState(
                nativeState,
                core: core,
                reason: actionType,
                successfulTransportStart: requiresPacketTunnelConfigSync
                    && !nativeStateBeforeAction.vpnEnabled
                    && nativeState.error.isEmpty
                    && nativeState.vpnEnabled
            )
        }
        actionInFlight = false
        statusMessage = state.error
        debugLog(
            "dispatch action=\(actionType) error=\(!state.error.isEmpty) vpn=\(state.vpnEnabled)/\(state.vpnActive) network=\(activeNetwork?.id ?? "nil")"
        )
        if state.error.isEmpty && requiresPacketTunnelConfigSync {
            let force = actionType == "remove_network"
                && activeNetwork == nil
                && !state.joinRequestQrCodeOrLink.isEmpty
            schedulePacketTunnelConfigSync(reason: actionType, force: force)
        }
        return state.error.isEmpty
    }

    private struct AppStoreCompatibleStateResult {
        let state: AppState
        let removedPaidConfiguration: Bool
        let vpnWasRunning: Bool
    }

    private static func appStoreCompatibleState(
        _ current: AppState,
        core: NativeCoreClient
    ) -> AppStoreCompatibleStateResult {
        let patch = AppStorePolicy.compatibilityPatch(for: current)
        guard !patch.isEmpty else {
            return AppStoreCompatibleStateResult(
                state: current,
                removedPaidConfiguration: false,
                vpnWasRunning: false
            )
        }
        return AppStoreCompatibleStateResult(
            state: core.dispatch(NativeActions.updateSettings(patch)),
            removedPaidConfiguration: true,
            vpnWasRunning: current.vpnEnabled || current.vpnActive
        )
    }

    @discardableResult
    func adoptAppStoreCompatibleState(
        _ current: AppState,
        core: NativeCoreClient,
        reason: String,
        successfulTransportStart: Bool = false
    ) -> Bool {
        let compatibility = Self.appStoreCompatibleState(current, core: core)
        state = compatibility.state
        state.vpnEnabled = vpnDesiredState.adoptNativeState(
            runtimeEnabled: state.vpnEnabled,
            successfulTransportStart: successfulTransportStart
        )
        if compatibility.removedPaidConfiguration && compatibility.vpnWasRunning {
            appStoreTunnelRefreshPending = true
            _ = reconcileAppStoreTunnelAfterSanitization(reason: reason)
        }
        return compatibility.removedPaidConfiguration
    }

    private func reconcileAppStoreTunnelAfterSanitization(reason: String) -> Bool {
        guard appStoreTunnelRefreshPending else {
            return false
        }
        appStoreTunnelRefreshPending = false
        guard UserDefaults.standard.bool(forKey: Self.vpnDisclosureAcceptedKey) else {
            requireVpnDisclosureReview()
            setVpnEnabled(false, force: true)
            return true
        }
        schedulePacketTunnelConfigSync(
            reason: "removed unavailable paid configuration during \(reason)",
            force: true
        )
        return true
    }

    func toggleVpn() {
        setVpnEnabled(!state.vpnEnabled)
    }

    func requireVpnDisclosureReview() {
        vpnDisclosurePromptVisible = true
        statusMessage = Self.vpnDisclosurePromptMessage
    }

    func markVpnDisclosureAccepted() {
        UserDefaults.standard.set(true, forKey: Self.vpnDisclosureAcceptedKey)
        vpnDisclosurePromptVisible = false
        if statusMessage == Self.vpnDisclosurePromptMessage {
            statusMessage = ""
        }
    }

    func startVpnAfterDisclosure() {
        if state.vpnEnabled {
            setVpnEnabled(true, force: true)
        } else {
            toggleVpn()
        }
    }

    func packetTunnelStartAllowed(reason: String) -> Bool {
        guard AppStorePolicy.allowsVpnStart(
            disclosureAccepted: UserDefaults.standard.bool(
                forKey: Self.vpnDisclosureAcceptedKey
            )
        ) else {
            debugLog("PacketTunnel start blocked reason=\(reason) disclosure pending")
            requireVpnDisclosureReview()
            return false
        }
        return true
    }

    func ensureAutoconnectPacketTunnel(reason: String) {
        let canReceiveDeviceApproval = !state.joinRequestQrCodeOrLink.isEmpty
        guard vpnDesiredState.permitsAutomaticStart(),
              state.autoconnect,
              activeNetwork != nil || canReceiveDeviceApproval
        else {
            return
        }
        guard UserDefaults.standard.bool(forKey: Self.vpnDisclosureAcceptedKey) else {
            requireVpnDisclosureReview()
            return
        }
        let transitionGeneration = packetTunnelTransitionGeneration
        Task { [weak self] in
            guard let self else { return }
            let status = await vpnController.statusRawValue()
            guard packetTunnelTransitionGeneration == transitionGeneration,
                  pendingVpnTransitionEnabled != false,
                  state.autoconnect
            else {
                return
            }
            guard Self.packetTunnelNeedsStart(statusRawValue: status) else {
                debugLog("autoconnect skipped reason=\(reason) tunnelStatus=\(status ?? -1)")
                return
            }
            debugLog("autoconnect starting PacketTunnel reason=\(reason) tunnelStatus=\(status ?? -1)")
            setVpnEnabled(true, force: true)
        }
    }

    static func packetTunnelNeedsStart(statusRawValue: Int?) -> Bool {
        guard let statusRawValue else {
            return true
        }
        // NEVPNStatus: invalid=0, disconnected=1, connecting=2,
        // connected=3, reasserting=4, disconnecting=5.
        return statusRawValue <= 1 || statusRawValue == 5
    }

    func setVpnEnabled(_ enabled: Bool, force: Bool = false) {
        debugLog("setVpnEnabled enabled=\(enabled) force=\(force) stateEnabled=\(state.vpnEnabled)")
        if fixtureMode {
            state.vpnEnabled = enabled
            state.vpnActive = enabled
            state.vpnStatus = enabled ? "Connected" : "Disconnected"
            state.connectedPeerCount = enabled ? min(state.expectedPeerCount, 3) : 0
            state.fipsConnectedPeerCount = enabled ? min(state.fipsRosterPeerCount, 3) : 0
            state.rev += 1
            statusMessage = ""
            return
        }
        if enabled,
           !AppStorePolicy.allowsVpnStart(
               disclosureAccepted: UserDefaults.standard.bool(
                   forKey: Self.vpnDisclosureAcceptedKey
               )
           )
        {
            requireVpnDisclosureReview()
            return
        }
        vpnDesiredState.recordRequest(enabled)
        guard !enabled || core != nil else {
            statusMessage = "Native core unavailable"
            return
        }
        pendingVpnTransitionEnabled = enabled
        enqueuePacketTunnelOperation(.setEnabled(enabled, force: force))
    }

    func vpnStartIsDesired() -> Bool {
        vpnDesiredState.restore(runtimeEnabled: state.vpnEnabled)
    }

    func schedulePacketTunnelConfigSync(reason: String, force: Bool = false) {
        guard !fixtureMode else {
            return
        }
        guard vpnStartIsDesired(),
              force || state.vpnEnabled || state.vpnActive
        else {
            debugLog("PacketTunnel config sync skipped reason=\(reason) vpn off")
            return
        }
        guard packetTunnelStartAllowed(reason: reason) else {
            return
        }
        guard pendingVpnTransitionEnabled == nil else {
            debugLog("PacketTunnel config sync skipped reason=\(reason) VPN transition pending")
            return
        }
        tunnelConfigSyncTask?.cancel()
        tunnelConfigSyncTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: 250_000_000)
            } catch {
                return
            }
            guard let self,
                  pendingVpnTransitionEnabled == nil,
                  vpnStartIsDesired()
            else {
                return
            }
            enqueuePacketTunnelOperation(
                .syncConfig(reason: reason, force: force)
            )
        }
    }

    func syncPacketTunnelConfig(
        reason: String,
        force: Bool,
        generation: UInt64
    ) async throws {
        try requirePacketTunnelTransition(generation)
        guard let core else {
            statusMessage = "Native core unavailable"
            return
        }
        guard vpnStartIsDesired(),
              force || state.vpnEnabled || state.vpnActive
        else {
            debugLog("PacketTunnel config sync aborted reason=\(reason) vpn off")
            return
        }
        guard packetTunnelStartAllowed(reason: reason) else {
            return
        }
        var tunnelConfigJson = core.mobileTunnelConfigJson()
        let queuedApprovalClock = ContinuousClock()
        let queuedApprovalDeadline = queuedApprovalClock.now.advanced(by: .seconds(12))
        while Self.tunnelConfigHasQueuedJoinRosters(tunnelConfigJson),
              queuedApprovalClock.now < queuedApprovalDeadline
        {
            debugLog("PacketTunnel config sync waiting for queued join approval delivery")
            try await Task.sleep(nanoseconds: 250_000_000)
            try requirePacketTunnelTransition(generation)
            tunnelConfigJson = core.mobileTunnelConfigJson()
        }
        let providerOptionsConfigJson = core.mobileTunnelProviderOptionsConfigJson()
        debugLog(
            "PacketTunnel config sync begin reason=\(reason) configLen=\(tunnelConfigJson.count) network=\(activeNetwork?.id ?? "nil")"
        )
        statusMessage = "Updating VPN"
        try await vpnController.start(
            state: state,
            network: activeNetwork,
            tunnelConfigJson: tunnelConfigJson,
            providerOptionsConfigJson: providerOptionsConfigJson,
            onActiveTunnelDisconnected: { [weak self] in
                self?.statusMessage = "Reconnecting VPN"
            }
        )
        try requirePacketTunnelTransition(generation)
        debugLog("PacketTunnel config sync start returned")
        refresh()
        statusMessage = state.error
    }

    static func tunnelConfigHasQueuedJoinRosters(_ configJson: String) -> Bool {
        guard let data = configJson.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let config = object as? [String: Any],
              let queued = config["queuedJoinRosters"] as? [Any]
        else {
            return false
        }
        return !queued.isEmpty
    }

    private func actionRequiresPacketTunnelConfigSync(
        _ type: String,
        updateSettingKeys: Set<String> = []
    ) -> Bool {
        switch type {
        case "import_join_request",
             "manual_add_network",
             "add_network",
             "rename_network",
             "remove_network",
             "set_network_enabled",
             "set_network_mesh_id",
             "set_network_join_requests_enabled",
             "add_participant",
             "set_participant_endpoint_hints",
             "add_admin",
             "remove_participant",
             "remove_admin",
             "accept_join_request",
             "set_manual_paid_exit_provider",
             "clear_manual_paid_exit_provider",
             "set_participant_alias":
            return true
        case "update_settings":
            return !updateSettingKeys.isDisjoint(with: Self.packetTunnelSettingKeys)
        default:
            return false
        }
    }

    private static let packetTunnelSettingKeys: Set<String> = [
        "internetSource",
        "listenPort",
        "endpoint",
        "relays",
        "disabledRelays",
        "exitNode",
        "exitNodeLeakProtection",
        "exitDnsMode",
        "exitDnsDohProvider",
        "exitDnsCustomDohUrl",
        "exitDnsCustomDohBootstrapIps",
        "exitDnsThroughExitServers",
        "advertiseExitNode",
        "advertisedRoutes",
        "wireguardExitEnabled",
        "wireguardExitInterface",
        "wireguardExitAddress",
        "wireguardExitPrivateKey",
        "wireguardExitPeerPublicKey",
        "wireguardExitPeerPresharedKey",
        "wireguardExitEndpoint",
        "wireguardExitAllowedIps",
        "wireguardExitDns",
        "wireguardExitMtu",
        "wireguardExitPersistentKeepaliveSecs",
        "wireguardExitConfig",
    ]

    func handle(url: URL) {
        debugLog("handle url scheme=\(url.scheme ?? "") host=\(url.host ?? "") path=\(url.path)")
        // iOS may deliver a deep link while the scene is inactive or
        // backgrounded. Reopening the native core there would make its shared
        // state suspendable again, which is the crash class this lifecycle
        // boundary prevents. Preserve ordering and drain only after the scene
        // becomes active.
        guard sceneIsActive else {
            pendingOpenURLs.append(url)
            return
        }
        handleActive(url: url)
    }

    private func drainPendingOpenURLs() {
        guard sceneIsActive, !pendingOpenURLs.isEmpty else {
            return
        }
        let urls = pendingOpenURLs
        pendingOpenURLs.removeAll(keepingCapacity: true)
        for url in urls {
            handleActive(url: url)
        }
    }

    private func handleActive(url: URL) {
        if core == nil {
            resumeNativeCore()
        }
        let raw = url.absoluteString
        if raw.lowercased().hasPrefix("nvpn://join-request") {
            dispatch(NativeActions.importJoinRequest(raw), status: "Adding device")
            return
        }

        guard url.scheme == "nvpn", url.host == "debug" else {
            return
        }

        let action = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        #if DEBUG
        if action == "automation" {
            guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let encoded = components.queryItems?.first(where: { $0.name == "arguments" })?.value,
                  let arguments = Self.debugArguments(fromBase64URL: encoded)
            else {
                debugLog("debug automation URL rejected: invalid arguments")
                return
            }
            _ = runDebugAutomation(arguments: arguments)
        } else if action == "tick" {
            refresh()
        } else if action == "connect" {
            setVpnEnabled(true, force: true)
        } else if action == "disconnect" {
            setVpnEnabled(false, force: true)
        }
        #endif
    }

}
