import Foundation
import NetworkExtension

private struct PacketTunnelProcessMetrics: Decodable {
    let pid: Int
    let cpuSeconds: Double
}

private actor ProviderSnapshotGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        if waiters.isEmpty {
            held = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

enum PacketTunnelControllerError: LocalizedError {
    case managerUnavailable
    case replacementStateUnavailable
    case preferencesTimedOut(String)
    case providerMessageTimedOut(String)
    case connectionFailed(Int)
    case connectionTimedOut(Int)
    case disconnectTimedOut(Int)

    var errorDescription: String? {
        switch self {
        case .managerUnavailable:
            return "VPN manager unavailable"
        case .replacementStateUnavailable:
            return "VPN transaction state unavailable"
        case .preferencesTimedOut(let operation):
            return "\(operation) VPN preferences timed out; approve any iOS VPN configuration prompt and retry"
        case .providerMessageTimedOut(let message):
            return "\(message) packet-tunnel response timed out"
        case .connectionFailed(let status):
            return "VPN connection failed with status \(status)"
        case .connectionTimedOut(let status):
            return "VPN connection timed out with status \(status)"
        case .disconnectTimedOut(let status):
            return "VPN disconnect timed out with status \(status); refusing to start a replacement tunnel"
        }
    }
}

struct PacketTunnelRouteState: Equatable {
    let hasDefaultRoute: Bool
    let hasWireGuardExit: Bool
}

final class PacketTunnelController {
    private static let preferencesOperationTimeoutSeconds: TimeInterval = 10
    private static let providerMessageTimeoutSeconds: TimeInterval = 1
    private let runtimeStateGate = ProviderSnapshotGate()
    private let providerBundleIdentifier = Bundle.main.object(
        forInfoDictionaryKey: "NVPNPacketTunnelBundleIdentifier"
    ) as? String ?? "fi.siriusbusiness.nvpn.PacketTunnel"
    private var activeManager: NETunnelProviderManager?
    private let replacementState: PacketTunnelReplacementStateStore?

    init(replacementState: PacketTunnelReplacementStateStore? = nil) {
        self.replacementState = replacementState ?? AppModel.supportDirectory().map {
            PacketTunnelReplacementStateStore(
                markerURL: $0.appendingPathComponent(
                    PacketTunnelReplacementStateStore.markerFileName
                )
            )
        }
    }

    func start(
        state: AppState,
        network: NetworkState?,
        tunnelConfigJson: String,
        providerOptionsConfigJson: String,
        onActiveTunnelDisconnected: (@MainActor () -> Void)? = nil
    ) async throws {
        try Task.checkCancellation()
        let update = Task { [self] in
            try await PacketTunnelStartPreparation().perform(
                operation: {
                    try await updateAndStart(
                        state: state,
                        network: network,
                        tunnelConfigJson: tunnelConfigJson,
                        providerOptionsConfigJson: providerOptionsConfigJson,
                        onActiveTunnelDisconnected: onActiveTunnelDisconnected
                    )
                },
                confirmDisconnected: {
                    _ = try await stopAndWaitForDisconnected()
                }
            )
        }
        try await update.value
    }

    private func updateAndStart(
        state: AppState,
        network: NetworkState?,
        tunnelConfigJson: String,
        providerOptionsConfigJson: String,
        onActiveTunnelDisconnected: (@MainActor () -> Void)?
    ) async throws {
        debugLog("PacketTunnelController.start begin")
        let (manager, managerIsNew) = try await loadOrCreateManager()
        guard let replacementState else {
            throw PacketTunnelControllerError.replacementStateUnavailable
        }
        activeManager = manager
        let hadActiveTunnel = manager.connection.status != .invalid
            && manager.connection.status != .disconnected
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = network?.displayName ?? "Nostr VPN"
        proto.providerConfiguration = [
            "networkName": network?.displayName ?? "Nostr VPN",
            "tunnelIp": state.tunnelIp.isEmpty ? "10.44.0.1/32" : state.tunnelIp,
            "mtu": 1150,
            "mobileTunnelConfigJson": tunnelConfigJson,
        ]
        // Tell iOS to actually use the includedRoutes we install
        // (without this iOS sometimes lets system services bypass the
        // tunnel, which is also the only condition under which the
        // VPN status badge stays hidden).
        proto.enforceRoutes = true
        if #available(iOS 14.0, *) {
            proto.includeAllNetworks =
                Self.routeState(in: providerOptionsConfigJson)?.hasDefaultRoute == true
        }
        // Don't tear the tunnel down when the screen locks — for a
        // utility VPN we want it to keep running.
        proto.disconnectOnSleep = false
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Nostr VPN"
        manager.isEnabled = true
        let transaction = PacketTunnelReplacementTransaction(state: replacementState)
        try await transaction.perform(
            replacingActiveTunnel: hadActiveTunnel,
            saveAndReload: { [self] in
                debugLog("saving preferences")
                try await save(manager, waitsForUserApproval: managerIsNew)
                debugLog("reloading preferences")
                try await reload(manager)
            },
            disconnect: { [self] in
                debugLog(
                    "stopping tunnel after preferences update status=\(manager.connection.status.rawValue)"
                )
                let status = try await stopAndWaitForDisconnected(manager)
                debugLog("confirmed tunnel stopped status=\(status)")
            },
            startAndWait: { [self] in
                if hadActiveTunnel {
                    await onActiveTunnelDisconnected?()
                }
                debugLog("calling startVPNTunnel status=\(manager.connection.status.rawValue)")
                // Keep providerConfiguration redacted in VPN preferences; the full
                // config is delivered only to this start attempt.
                let options: [String: NSObject] = [
                    "mobileTunnelConfigJson": providerOptionsConfigJson as NSString,
                ]
                try manager.connection.startVPNTunnel(options: options)
                let connectedStatus = try await waitForConnected(manager)
                debugLog("confirmed connected status=\(connectedStatus)")
            }
        )
    }

    func replacementRestartRequired() -> Bool {
        replacementState?.restartRequired() == true
    }

    static func routeState(in configJson: String) -> PacketTunnelRouteState? {
        guard let data = configJson.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        let tunnel = object["tunnel"] as? [String: Any] ?? object
        guard let routes = tunnel["routeTargets"] as? [String] else {
            return nil
        }
        return PacketTunnelRouteState(
            hasDefaultRoute: routes.contains("0.0.0.0/0"),
            hasWireGuardExit: tunnel["wireguardExit"] is [String: Any]
        )
    }

    func stopAndWaitForDisconnected() async throws -> Int {
        try Task.checkCancellation()
        debugLog("PacketTunnelController.stopAndWaitForDisconnected begin")
        guard let manager = try await loadExistingManager() else {
            debugLog("confirmed disconnected: no existing manager")
            return NEVPNStatus.invalid.rawValue
        }
        try Task.checkCancellation()
        activeManager = manager
        return try await stopAndWaitForDisconnected(manager)
    }

    private func stopAndWaitForDisconnected(
        _ manager: NETunnelProviderManager
    ) async throws -> Int {
        if manager.connection.status != .disconnecting {
            manager.connection.stopVPNTunnel()
        }
        return try await waitForDisconnected(manager)
    }

    private func waitForDisconnected(_ manager: NETunnelProviderManager) async throws -> Int {
        var status = manager.connection.status.rawValue
        for _ in 0..<20 {
            if status <= NEVPNStatus.disconnected.rawValue {
                debugLog("confirmed disconnected status=\(status)")
                return status
            }
            try await Task.sleep(nanoseconds: 500_000_000)
            status = manager.connection.status.rawValue
        }
        debugLog("disconnect confirmation timed out status=\(status)")
        throw PacketTunnelControllerError.disconnectTimedOut(status)
    }

    private func waitForConnected(_ manager: NETunnelProviderManager) async throws -> Int {
        let connection = manager.connection
        let statuses = AsyncStream<Int>(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let observer = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange,
                object: connection,
                queue: nil
            ) { notification in
                guard let connection = notification.object as? NEVPNConnection else {
                    return
                }
                continuation.yield(connection.status.rawValue)
            }
            continuation.onTermination = { @Sendable _ in
                NotificationCenter.default.removeObserver(observer)
            }
            continuation.yield(connection.status.rawValue)
        }
        do {
            return try await withThrowingTaskGroup(of: Int.self) { group in
                group.addTask {
                    var observedStartingStatus = false
                    for await status in statuses {
                        try Task.checkCancellation()
                        if status == NEVPNStatus.connected.rawValue {
                            return status
                        }
                        if status == NEVPNStatus.connecting.rawValue
                            || status == NEVPNStatus.reasserting.rawValue
                        {
                            observedStartingStatus = true
                        } else if observedStartingStatus,
                                  status == NEVPNStatus.invalid.rawValue
                                    || status == NEVPNStatus.disconnected.rawValue
                        {
                            throw PacketTunnelControllerError.connectionFailed(status)
                        }
                    }
                    throw CancellationError()
                }
                group.addTask {
                    try await Task.sleep(
                        nanoseconds: UInt64(
                            Self.preferencesOperationTimeoutSeconds * 1_000_000_000
                        )
                    )
                    throw ConnectionWaitTimeout()
                }
                defer { group.cancelAll() }
                guard let status = try await group.next() else {
                    throw CancellationError()
                }
                return status
            }
        } catch is ConnectionWaitTimeout {
            throw PacketTunnelControllerError.connectionTimedOut(
                connection.status.rawValue
            )
        }
    }

    func statusRawValue() async -> Int? {
        do {
            guard let manager = try await loadExistingManager() else {
                return nil
            }
            return manager.connection.status.rawValue
        } catch {
            debugLog("status failed: \(String(describing: error))")
            return nil
        }
    }

    func installedRouteState() async -> PacketTunnelRouteState? {
        do {
            guard let manager = try await loadExistingManager(),
                  let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let configJson = proto.providerConfiguration?["mobileTunnelConfigJson"] as? String
            else {
                return nil
            }
            return Self.routeState(in: configJson)
        } catch {
            debugLog("installed route state failed: \(String(describing: error))")
            return nil
        }
    }

    func providerIsResponsive() async -> Bool {
        await providerMessage("health") == "ok"
    }

    func packetTunnelProcessMetrics() async -> (pid: Int, cpuSeconds: Double)? {
        guard let data = await providerMessageData("processMetrics"),
              let metrics = try? JSONDecoder().decode(PacketTunnelProcessMetrics.self, from: data),
              metrics.pid > 0,
              metrics.cpuSeconds >= 0
        else {
            return nil
        }
        return (metrics.pid, metrics.cpuSeconds)
    }

    func runtimeStateJson() async -> String? {
        await runtimeStateGate.acquire()
        let result = await readRuntimeStateJson()
        await runtimeStateGate.release()
        return result
    }

    private func readRuntimeStateJson() async -> String? {
        guard let sizeData = await providerMessageData("runtimeStateBegin"),
              let sizeText = String(data: sizeData, encoding: .utf8),
              let expectedSize = Int(sizeText),
              expectedSize >= 0,
              expectedSize <= 1_048_576
        else {
            return nil
        }
        var response = Data()
        response.reserveCapacity(expectedSize)
        while response.count < expectedSize {
            guard let chunk = await providerMessageData("runtimeStateChunk:\(response.count)"),
                  !chunk.isEmpty
            else {
                return nil
            }
            response.append(chunk)
        }
        guard response.count == expectedSize else {
            return nil
        }
        return String(data: response, encoding: .utf8)
    }

    func takeAppConfigToml() async -> String? {
        await readAppConfigToml()
    }

    private func readAppConfigToml() async -> String? {
        guard let sizeData = await providerMessageData("appConfigBegin"),
              let sizeText = String(data: sizeData, encoding: .utf8),
              let expectedSize = Int(sizeText),
              expectedSize >= 0,
              expectedSize <= 4_194_304
        else {
            return nil
        }
        var response = Data()
        response.reserveCapacity(expectedSize)
        while response.count < expectedSize {
            guard let chunk = await providerMessageData("appConfigChunk:\(response.count)"),
                  !chunk.isEmpty
            else {
                return nil
            }
            response.append(chunk)
        }
        guard response.count == expectedSize else {
            return nil
        }
        return String(data: response, encoding: .utf8)
    }

    func acknowledgeAppConfigToml() async -> Bool {
        guard let response = await providerMessage("appConfigCommit") else {
            return false
        }
        return response == "ok" || response == "stale"
    }

    private func providerMessage(_ message: String) async -> String? {
        guard let response = await providerMessageData(message) else {
            return nil
        }
        return String(data: response, encoding: .utf8)
    }

    private func providerMessageData(_ message: String) async -> Data? {
        do {
            guard let manager = try await loadExistingManager() else {
                debugLog("providerMessage \(message) skipped: no existing manager")
                return nil
            }
            guard manager.connection.status == .connected else {
                debugLog("providerMessage \(message) skipped status=\(manager.connection.status.rawValue)")
                return nil
            }
            guard let session = manager.connection as? NETunnelProviderSession else {
                return nil
            }
            let data = message.data(using: .utf8) ?? Data()
            return try await withCheckedThrowingContinuation { continuation in
                let completion = ProviderMessageCompletion(continuation)
                do {
                    try session.sendProviderMessage(data) { response in
                        _ = completion.resume(returning: response)
                    }
                } catch {
                    _ = completion.resume(throwing: error)
                }
                let timeoutSeconds = Self.providerMessageTimeoutSeconds
                Task.detached(priority: .utility) {
                    try? await Task.sleep(
                        nanoseconds: UInt64(timeoutSeconds * 1_000_000_000)
                    )
                    _ = completion.resume(
                        throwing: PacketTunnelControllerError.providerMessageTimedOut(message)
                    )
                }
            }
        } catch {
            debugLog("providerMessage \(message) failed: \(String(describing: error))")
            return nil
        }
    }

    private func loadOrCreateManager() async throws -> (NETunnelProviderManager, Bool) {
        if let existing = try await loadExistingManager() {
            debugLog("using existing manager status=\(existing.connection.status.rawValue)")
            return (existing, false)
        }
        debugLog("creating new manager")
        return (NETunnelProviderManager(), true)
    }

    private func loadExistingManager() async throws -> NETunnelProviderManager? {
        let managers = try await loadAllManagers()
        debugLog("loaded managers count=\(managers.count)")
        let matching = managers.filter { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == providerBundleIdentifier
        }
        return matching.first(where: { manager in
            switch manager.connection.status {
            case .invalid, .disconnected:
                return false
            default:
                return true
            }
        }) ?? matching.first
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            let completion = PreferenceManagerLoadCompletion(continuation)
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    _ = completion.resume(throwing: error)
                } else {
                    _ = completion.resume(returning: managers ?? [])
                }
            }
            let timeoutSeconds = Self.preferencesOperationTimeoutSeconds
            Task.detached(priority: .utility) {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                _ = completion.resume(
                    throwing: PacketTunnelControllerError.preferencesTimedOut("load")
                )
            }
        }
    }

    private func save(
        _ manager: NETunnelProviderManager,
        waitsForUserApproval: Bool
    ) async throws {
        try await withPreferencesCompletion(
            operation: "save",
            timeoutSeconds: waitsForUserApproval ? nil : Self.preferencesOperationTimeoutSeconds
        ) { finish in
            manager.saveToPreferences { error in
                finish(error)
            }
        }
    }

    private func reload(_ manager: NETunnelProviderManager) async throws {
        try await withPreferencesCompletion(
            operation: "reload",
            timeoutSeconds: Self.preferencesOperationTimeoutSeconds
        ) { finish in
            manager.loadFromPreferences { error in
                finish(error)
            }
        }
    }

    private func withPreferencesCompletion(
        operation: String,
        timeoutSeconds: TimeInterval?,
        start: (@escaping (Error?) -> Void) -> Void
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let completion = PreferenceOperationCompletion(continuation)
            start { error in
                if let error {
                    _ = completion.resume(throwing: error)
                } else {
                    _ = completion.resume(returning: ())
                }
            }
            if let timeoutSeconds {
                Task.detached(priority: .utility) {
                    try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                    _ = completion.resume(
                        throwing: PacketTunnelControllerError.preferencesTimedOut(operation)
                    )
                }
            }
        }
    }

    private func debugLog(_ message: String) {
        #if DEBUG
        guard let supportDir = AppModel.supportDirectory() else {
            return
        }
        try? FileManager.default.createDirectory(at: supportDir, withIntermediateDirectories: true)
        let logUrl = supportDir.appendingPathComponent("app-debug.log")
        appendIosDebugLog(message, to: logUrl)
        #endif
    }
}

private final class ProviderMessageCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private let continuation: CheckedContinuation<Data?, Error>

    init(_ continuation: CheckedContinuation<Data?, Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func resume(returning value: Data?) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(returning: value)
        return true
    }

    @discardableResult
    func resume(throwing error: Error) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(throwing: error)
        return true
    }

    private func markCompleted() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else {
            return false
        }
        completed = true
        return true
    }
}

private struct ConnectionWaitTimeout: Error {}

private final class PreferenceOperationCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private let continuation: CheckedContinuation<Void, Error>

    init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func resume(returning value: Void) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(returning: value)
        return true
    }

    @discardableResult
    func resume(throwing error: Error) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(throwing: error)
        return true
    }

    private func markCompleted() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else {
            return false
        }
        completed = true
        return true
    }
}

private final class PreferenceManagerLoadCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private let continuation: CheckedContinuation<[NETunnelProviderManager], Error>

    init(_ continuation: CheckedContinuation<[NETunnelProviderManager], Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func resume(returning managers: [NETunnelProviderManager]) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(returning: managers)
        return true
    }

    @discardableResult
    func resume(throwing error: Error) -> Bool {
        guard markCompleted() else {
            return false
        }
        continuation.resume(throwing: error)
        return true
    }

    private func markCompleted() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else {
            return false
        }
        completed = true
        return true
    }
}
