import Darwin
import Foundation
import Network
import NetworkExtension

private let appGroupIdentifier: String = {
    guard let value = Bundle.main.object(
        forInfoDictionaryKey: "NVPNAppGroupIdentifier"
    ) as? String,
    !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
        fatalError("NVPNAppGroupIdentifier is missing from Info.plist")
    }
    return value
}()
private let defaultMobileMtu = 1150
private let packetDebugLogLimitBytes = 1_048_576

private enum UnderlayPathSource: Hashable {
    case general
    case physicalWiFi
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let appMessageChunkSize = 3_072
    private var tunnelHandle: OpaquePointer?
    private var tunnelRunning = false
    private var tunnelGeneration: UInt64 = 0
    private var activeTunnelCalls = 0
    private var packetFlowBridge: PacketFlowBridge?
    private let tunnelCondition = NSCondition()
    private let appMessageSnapshotLock = NSLock()
    private let underlayMonitorLock = NSLock()
    private let underlayMonitorQueue = DispatchQueue(
        label: "fi.siriusbusiness.nvpn.packet-tunnel.underlay"
    )
    private var runtimeStateSnapshot = Data()
    private var appConfigSnapshot = Data()
    private var underlayMonitors: [NWPathMonitor] = []
    private var underlayMonitorGeneration: UInt64?
    private var initializedUnderlaySources: Set<UnderlayPathSource> = []
    private var underlayRefreshWorkItem: DispatchWorkItem?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let startedAt = ProcessInfo.processInfo.systemUptime
        NSLog("nvpn-pkt: startTunnel entered")
        packetDebugLog("startTunnel entered options=\(options.map { Array($0.keys).sorted() } ?? [])")
        let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        packetDebugLog("providerConfiguration keys=\(Array(configuration.keys).sorted())")
        let optionConfigJson = options?["mobileTunnelConfigJson"] as? String
        let configJson = optionConfigJson ?? configuration["mobileTunnelConfigJson"] as? String ?? ""
        let parsedConfig = MobileTunnelConfig(json: configJson)
        if let error = parsedConfig.errorText {
            NSLog("nvpn-pkt: config parse failed: \(error)")
            packetDebugLog("config parse failed: \(error)")
            completionHandler(error)
            return
        }
        NSLog("nvpn-pkt: calling nostr_vpn_mobile_tunnel_new (configLen=\(configJson.count))")
        packetDebugLog("calling nostr_vpn_mobile_tunnel_new configLen=\(configJson.count)")
        let startGeneration = beginRustTunnelStart()
        guard let handle = configJson.withCString({ nostr_vpn_mobile_tunnel_new($0) }) else {
            NSLog("nvpn-pkt: nostr_vpn_mobile_tunnel_new returned NULL")
            packetDebugLog("nostr_vpn_mobile_tunnel_new returned NULL")
            stopRustTunnel(generation: startGeneration)
            completionHandler(PacketTunnelError.startFailed)
            return
        }
        guard installRustTunnel(handle, generation: startGeneration) else {
            NSLog("nvpn-pkt: tunnel stopped before Rust runtime install")
            packetDebugLog("tunnel stopped before Rust runtime install")
            completionHandler(PacketTunnelError.startFailed)
            return
        }
        NSLog("nvpn-pkt: rust runtime up, handle=\(handle)")
        packetDebugLog("rust runtime up")
        var excludedRoutes = parsedConfig.excludedRoutes
        guard let resolvedWgExcludedRoute = withTunnelHandle(generation: startGeneration, { handle in
            consumeCString(nostr_vpn_mobile_tunnel_wg_excluded_route(handle))
        })?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            NSLog("nvpn-pkt: tunnel stopped before WG excluded route lookup")
            packetDebugLog("tunnel stopped before WG excluded route lookup")
            stopRustTunnel(generation: startGeneration)
            completionHandler(PacketTunnelError.startFailed)
            return
        }
        if !resolvedWgExcludedRoute.isEmpty && !excludedRoutes.contains(resolvedWgExcludedRoute) {
            excludedRoutes.append(resolvedWgExcludedRoute)
            packetDebugLog("added resolved WG excluded route \(resolvedWgExcludedRoute)")
        }

        // iOS requires tunnelRemoteAddress to be an IP. Use the endpoint route
        // resolved by the running WireGuard transport; Direct/FIPS mode has no
        // single remote tunnel server, so retain a valid display-only address.
        let remoteAddress = parseIPv4CIDR(resolvedWgExcludedRoute)?.address ?? "1.1.1.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = NSNumber(value: parsedConfig.mtu)
        packetDebugLog("remoteAddress=\(remoteAddress) mtu=\(parsedConfig.mtu)")

        if let parsed = parseIPv4CIDR(parsedConfig.localAddress) {
            let ipv4 = NEIPv4Settings(addresses: [parsed.address], subnetMasks: [parsed.mask])
            // Use NEIPv4Route.default() for 0.0.0.0/0 — iOS recognizes
            // it as the catch-all default route, vs an explicit
            // (0.0.0.0, 0.0.0.0) which can be treated as a host route
            // in some kernel paths.
            ipv4.includedRoutes = parsedConfig.routeTargets.compactMap(ipv4Route)
            // When WG upstream is on, the Rust runtime has expanded
            // `routeTargets` to include 0.0.0.0/0 so all outbound
            // traffic enters the tun. We then exclude the resolved WG
            // endpoint IP itself so the encrypted UDP can actually
            // escape the tunnel and reach the upstream.
            if !excludedRoutes.isEmpty {
                ipv4.excludedRoutes = excludedRoutes.compactMap(ipv4Route)
            }
            settings.ipv4Settings = ipv4
            NSLog(
                "nvpn-pkt: ipv4 addr=\(parsed.address)/\(parsed.mask) "
                    + "included=\(parsedConfig.routeTargets) "
                    + "excluded=\(excludedRoutes)"
            )
        }

        // The Rust tunnel owns DNS whenever an exit is active. It answers
        // MagicDNS locally and sends public queries only through authenticated
        // DNS-over-HTTPS. Never allow iOS to fall back to underlay DNS.
        let dnsConfig = iosDnsConfig(
            from: parsedConfig.dnsServers,
            magicDnsServer: parsedConfig.magicDnsServer,
            matchDomains: parsedConfig.dnsMatchDomains
        )
        if !dnsConfig.servers.isEmpty {
            let dns = NEDNSSettings(servers: dnsConfig.servers)
            dns.matchDomains = dnsConfig.matchDomains
            settings.dnsSettings = dns
            NSLog(
                "nvpn-pkt: dns servers=\(dnsConfig.servers) "
                    + "match=\(dnsConfig.matchDomains) failover=false"
            )
        }

        NSLog("nvpn-pkt: calling setTunnelNetworkSettings")
        packetDebugLog("calling setTunnelNetworkSettings")
        let settingsStartedAt = ProcessInfo.processInfo.systemUptime
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                let settingsMs = elapsedMs(since: settingsStartedAt)
                NSLog("nvpn-pkt: setTunnelNetworkSettings failed after \(settingsMs)ms: \(error)")
                packetDebugLog("setTunnelNetworkSettings failed after \(settingsMs)ms: \(error)")
                self?.stopRustTunnel(generation: startGeneration)
                completionHandler(error)
                return
            }
            guard let self else {
                completionHandler(PacketTunnelError.startFailed)
                return
            }
            let packetFlowBridge = PacketFlowBridge(
                packetFlow: self.packetFlow,
                provider: self,
                generation: startGeneration
            )
            guard self.installPacketFlowBridge(
                packetFlowBridge,
                generation: startGeneration
            ) else {
                let settingsMs = elapsedMs(since: settingsStartedAt)
                NSLog("nvpn-pkt: tunnel stopped before packet flow install after \(settingsMs)ms")
                packetDebugLog("tunnel stopped before packet flow install after \(settingsMs)ms")
                self.stopRustTunnel(generation: startGeneration)
                completionHandler(PacketTunnelError.startFailed)
                return
            }
            let attachResult = self.withTunnelHandle(generation: startGeneration) { handle in
                packetFlowBridge.attach(to: handle)
            }
            guard attachResult == true else {
                let reason = attachResult == nil
                    ? "tunnel stopped before packet flow attach"
                    : "failed to attach NEPacketTunnelFlow to Rust"
                let settingsMs = elapsedMs(since: settingsStartedAt)
                NSLog("nvpn-pkt: \(reason) after \(settingsMs)ms")
                packetDebugLog("\(reason) after \(settingsMs)ms")
                self.stopRustTunnel(generation: startGeneration)
                completionHandler(PacketTunnelError.startFailed)
                return
            }
            let settingsMs = elapsedMs(since: settingsStartedAt)
            let totalMs = elapsedMs(since: startedAt)
            NSLog(
                "nvpn-pkt: setTunnelNetworkSettings succeeded in \(settingsMs)ms; "
                    + "NEPacketTunnelFlow attached total=\(totalMs)ms"
            )
            packetDebugLog("setTunnelNetworkSettings succeeded settingsMs=\(settingsMs) totalMs=\(totalMs)")
            guard packetFlowBridge.startReading(),
                  self.startUnderlayNetworkMonitor(
                      generation: startGeneration,
                      bridge: packetFlowBridge
                  )
            else {
                NSLog("nvpn-pkt: tunnel stopped before packet flow activation")
                packetDebugLog("tunnel stopped before packet flow activation")
                self.stopRustTunnel(generation: startGeneration)
                completionHandler(PacketTunnelError.startFailed)
                return
            }
            NSLog("nvpn-pkt: completionHandler(nil) — VPN should transition to connected")
            packetDebugLog("completionHandler nil totalMs=\(totalMs)")
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        packetDebugLog("stopTunnel reason=\(reason.rawValue)")
        stopRustTunnel()
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        let message = String(data: messageData, encoding: .utf8) ?? ""
        switch message {
        case "health":
            let runtimeIsAlive = withTunnelHandle { _ in true } == true
            completionHandler?(runtimeIsAlive ? Data("ok".utf8) : nil)
        case "processMetrics":
            completionHandler?(processMetricsData())
        case "runtimeStateBegin":
            let data = runtimeStateData()
            appMessageSnapshotLock.lock()
            runtimeStateSnapshot = data
            appMessageSnapshotLock.unlock()
            completionHandler?(String(data.count).data(using: .utf8))
        case let chunkRequest where chunkRequest.hasPrefix("runtimeStateChunk:"):
            let offsetText = chunkRequest.dropFirst("runtimeStateChunk:".count)
            guard let offset = Int(offsetText), offset >= 0 else {
                completionHandler?(nil)
                return
            }
            appMessageSnapshotLock.lock()
            let end = min(runtimeStateSnapshot.count, offset + Self.appMessageChunkSize)
            let chunk = offset <= end && offset < runtimeStateSnapshot.count
                ? runtimeStateSnapshot.subdata(in: offset..<end)
                : Data()
            if end == runtimeStateSnapshot.count {
                runtimeStateSnapshot.removeAll(keepingCapacity: false)
            }
            appMessageSnapshotLock.unlock()
            completionHandler?(chunk)
        case "appConfigBegin":
            completionHandler?(String(appConfigSnapshotData().count).data(using: .utf8))
        case let chunkRequest where chunkRequest.hasPrefix("appConfigChunk:"):
            let offsetText = chunkRequest.dropFirst("appConfigChunk:".count)
            guard let offset = Int(offsetText), offset >= 0 else {
                completionHandler?(nil)
                return
            }
            appMessageSnapshotLock.lock()
            let end = min(appConfigSnapshot.count, offset + Self.appMessageChunkSize)
            let chunk = offset <= end && offset < appConfigSnapshot.count
                ? appConfigSnapshot.subdata(in: offset..<end)
                : Data()
            appMessageSnapshotLock.unlock()
            completionHandler?(chunk)
        case "appConfigCommit":
            appMessageSnapshotLock.lock()
            let snapshot = appConfigSnapshot
            appMessageSnapshotLock.unlock()
            guard let toml = String(data: snapshot, encoding: .utf8) else {
                completionHandler?(nil)
                return
            }
            let acknowledged = withTunnelHandle { handle in
                toml.withCString { expectedToml in
                    nostr_vpn_mobile_tunnel_ack_app_config_toml(handle, expectedToml)
                }
            }
            guard let acknowledged else {
                completionHandler?(nil)
                return
            }
            appMessageSnapshotLock.lock()
            if appConfigSnapshot == snapshot {
                appConfigSnapshot.removeAll(keepingCapacity: false)
            }
            appMessageSnapshotLock.unlock()
            completionHandler?((acknowledged ? "ok" : "stale").data(using: .utf8))
        default:
            completionHandler?(nil)
        }
    }

    private func runtimeStateData() -> Data {
        let json = withTunnelHandle { handle in
            consumeCString(nostr_vpn_mobile_tunnel_runtime_state_json(handle))
        } ?? #"{"error":"mobile tunnel stopped"}"#
        return json.data(using: .utf8) ?? Data()
    }

    private func processMetricsData() -> Data? {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else {
            return nil
        }
        let cpuSeconds = Double(usage.ru_utime.tv_sec)
            + Double(usage.ru_utime.tv_usec) / 1_000_000
            + Double(usage.ru_stime.tv_sec)
            + Double(usage.ru_stime.tv_usec) / 1_000_000
        return try? JSONSerialization.data(withJSONObject: [
            "pid": Int(getpid()),
            "cpuSeconds": cpuSeconds,
        ])
    }

    private func appConfigSnapshotData() -> Data {
        appMessageSnapshotLock.lock()
        if !appConfigSnapshot.isEmpty {
            let snapshot = appConfigSnapshot
            appMessageSnapshotLock.unlock()
            return snapshot
        }
        appMessageSnapshotLock.unlock()

        let toml = withTunnelHandle { handle in
            consumeCString(nostr_vpn_mobile_tunnel_take_app_config_toml(handle))
        } ?? ""
        let loaded = toml.data(using: .utf8) ?? Data()

        appMessageSnapshotLock.lock()
        if appConfigSnapshot.isEmpty {
            appConfigSnapshot = loaded
        }
        let snapshot = appConfigSnapshot
        appMessageSnapshotLock.unlock()
        return snapshot
    }

    private func iosDnsConfig(
        from servers: [String],
        magicDnsServer: String,
        matchDomains: [String]
    ) -> (servers: [String], matchDomains: [String]) {
        let normalized = servers
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let normalizedMatchDomains = matchDomains.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let magicDnsServer = magicDnsServer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !magicDnsServer.isEmpty else {
            return (normalized, normalizedMatchDomains)
        }
        guard normalized.contains(magicDnsServer) else {
            return (normalized, normalizedMatchDomains)
        }
        return ([magicDnsServer], normalizedMatchDomains)
    }

    private func beginRustTunnelStart() -> UInt64 {
        stopRustTunnel()
        tunnelCondition.lock()
        tunnelGeneration &+= 1
        let generation = tunnelGeneration
        tunnelRunning = true
        activeTunnelCalls = 0
        tunnelCondition.unlock()
        return generation
    }

    private func installRustTunnel(_ handle: OpaquePointer, generation: UInt64) -> Bool {
        var shouldFree = false
        var installed = false
        tunnelCondition.lock()
        if tunnelRunning, tunnelGeneration == generation, tunnelHandle == nil {
            tunnelHandle = handle
            installed = true
        } else {
            shouldFree = true
        }
        tunnelCondition.unlock()
        if shouldFree {
            nostr_vpn_mobile_tunnel_free(handle)
        }
        return installed
    }

    private func installPacketFlowBridge(
        _ bridge: PacketFlowBridge,
        generation: UInt64
    ) -> Bool {
        tunnelCondition.lock()
        defer { tunnelCondition.unlock() }
        guard tunnelRunning,
              tunnelGeneration == generation,
              tunnelHandle != nil,
              packetFlowBridge == nil
        else {
            return false
        }
        packetFlowBridge = bridge
        return true
    }

    private func stopRustTunnel(generation expectedGeneration: UInt64? = nil) {
        tunnelCondition.lock()
        if let expectedGeneration, tunnelGeneration != expectedGeneration {
            tunnelCondition.unlock()
            return
        }
        tunnelRunning = false
        let packetFlowBridge = self.packetFlowBridge
        self.packetFlowBridge = nil
        packetFlowBridge?.stop()
        let handle = tunnelHandle
        tunnelHandle = nil
        while activeTunnelCalls > 0 {
            tunnelCondition.wait()
        }
        tunnelCondition.unlock()
        stopUnderlayNetworkMonitor()

        if let handle {
            nostr_vpn_mobile_tunnel_free(handle)
        }
    }

    func sendPacketFlowBatch(
        _ bytes: Data,
        lengths: [Int],
        generation: UInt64
    ) -> Bool {
        let sent = withTunnelHandle(generation: generation) { handle in
            bytes.withUnsafeBytes { rawBytes in
                lengths.withUnsafeBufferPointer { rawLengths in
                    guard let bytes = rawBytes.bindMemory(to: UInt8.self).baseAddress,
                          let lengths = rawLengths.baseAddress
                    else {
                        return false
                    }
                    return nostr_vpn_mobile_tunnel_packet_flow_send(
                        handle,
                        bytes,
                        rawBytes.count,
                        lengths,
                        rawLengths.count
                    )
                }
            }
        }
        return sent == true
    }

    func packetFlowDidFail(_ message: String, generation: UInt64) {
        guard tunnelIsActive(generation: generation) else {
            return
        }
        NSLog("nvpn-pkt: packet flow failed: \(message)")
        packetDebugLog("packet flow failed: \(message)")
        let error = PacketTunnelError.packetFlowFailed(message)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self, self.tunnelIsActive(generation: generation) else {
                return
            }
            self.cancelTunnelWithError(error)
        }
    }

    private func startUnderlayNetworkMonitor(
        generation: UInt64,
        bridge: PacketFlowBridge
    ) -> Bool {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.handleUnderlayPathUpdate(
                path,
                generation: generation,
                source: .general
            )
        }
        // A generic monitor can remain satisfied through the VPN default route
        // while the physical Wi-Fi disappears. Observe Wi-Fi independently so
        // its OFF→ON transition promptly refreshes the live tunnel.
        let physicalWiFiMonitor = NWPathMonitor(requiredInterfaceType: .wifi)
        physicalWiFiMonitor.pathUpdateHandler = { [weak self] path in
            self?.handleUnderlayPathUpdate(
                path,
                generation: generation,
                source: .physicalWiFi
            )
        }
        let monitors = [monitor, physicalWiFiMonitor]

        tunnelCondition.lock()
        guard tunnelRunning,
              tunnelGeneration == generation,
              tunnelHandle != nil,
              packetFlowBridge === bridge
        else {
            tunnelCondition.unlock()
            return false
        }
        underlayMonitorLock.lock()
        let previousMonitors = underlayMonitors
        underlayMonitors = monitors
        underlayMonitorGeneration = generation
        initializedUnderlaySources.removeAll()
        underlayRefreshWorkItem?.cancel()
        underlayRefreshWorkItem = nil
        underlayMonitorLock.unlock()
        previousMonitors.forEach { $0.cancel() }
        monitors.forEach { $0.start(queue: underlayMonitorQueue) }
        tunnelCondition.unlock()
        return true
    }

    private func stopUnderlayNetworkMonitor() {
        underlayMonitorLock.lock()
        let monitors = underlayMonitors
        underlayMonitors.removeAll()
        underlayMonitorGeneration = nil
        initializedUnderlaySources.removeAll()
        underlayRefreshWorkItem?.cancel()
        underlayRefreshWorkItem = nil
        underlayMonitorLock.unlock()
        monitors.forEach { $0.cancel() }
    }

    private func handleUnderlayPathUpdate(
        _ path: Network.NWPath,
        generation: UInt64,
        source: UnderlayPathSource
    ) {
        underlayMonitorLock.lock()
        guard underlayMonitorGeneration == generation else {
            underlayMonitorLock.unlock()
            return
        }
        if initializedUnderlaySources.insert(source).inserted {
            underlayMonitorLock.unlock()
            packetDebugLog("\(source) underlay monitor ready status=\(path.status)")
            return
        }
        underlayRefreshWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            self?.refreshFipsAfterUnderlayChange(generation: generation)
        }
        underlayRefreshWorkItem = workItem
        underlayMonitorLock.unlock()
        underlayMonitorQueue.asyncAfter(
            deadline: .now() + .milliseconds(250),
            execute: workItem
        )
    }

    private func refreshFipsAfterUnderlayChange(generation: UInt64) {
        underlayMonitorLock.lock()
        guard underlayMonitorGeneration == generation else {
            underlayMonitorLock.unlock()
            return
        }
        underlayRefreshWorkItem = nil
        underlayMonitorLock.unlock()
        let refreshed = withTunnelHandle(generation: generation) { handle in
            nostr_vpn_mobile_tunnel_network_changed(handle)
        }
        if refreshed == true {
            NSLog("nvpn-pkt: physical network changed; live FIPS carriers refreshed")
            packetDebugLog("physical network changed; live FIPS carriers refreshed")
        } else {
            NSLog("nvpn-pkt: physical network changed; live FIPS carrier refresh failed")
            packetDebugLog("physical network changed; live FIPS carrier refresh failed")
        }
    }

    private func withTunnelHandle<T>(
        generation expectedGeneration: UInt64? = nil,
        _ body: (OpaquePointer) -> T
    ) -> T? {
        tunnelCondition.lock()
        guard tunnelRunning,
              expectedGeneration == nil || tunnelGeneration == expectedGeneration,
              let handle = tunnelHandle
        else {
            tunnelCondition.unlock()
            return nil
        }
        activeTunnelCalls += 1
        tunnelCondition.unlock()

        defer {
            tunnelCondition.lock()
            activeTunnelCalls -= 1
            if activeTunnelCalls == 0 {
                tunnelCondition.broadcast()
            }
            tunnelCondition.unlock()
        }

        return body(handle)
    }

    private func tunnelIsActive(generation: UInt64) -> Bool {
        tunnelCondition.lock()
        let result = tunnelRunning
            && tunnelGeneration == generation
            && tunnelHandle != nil
            && packetFlowBridge?.generation == generation
        tunnelCondition.unlock()
        return result
    }
}

private enum PacketTunnelError: LocalizedError {
    case startFailed
    case invalidConfig(String)
    case packetFlowFailed(String)

    var errorDescription: String? {
        switch self {
        case .startFailed:
            return "Failed to start FIPS tunnel"
        case .invalidConfig(let message):
            return message
        case .packetFlowFailed(let message):
            return "Packet tunnel I/O failed: \(message)"
        }
    }
}

private struct MobileTunnelConfig {
    let localAddress: String
    let routeTargets: [String]
    let excludedRoutes: [String]
    let dnsServers: [String]
    let magicDnsServer: String
    let dnsMatchDomains: [String]
    let mtu: Int
    let errorText: Error?

    init(json: String) {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            localAddress = "10.44.0.1/32"
            routeTargets = []
            excludedRoutes = []
            dnsServers = []
            magicDnsServer = ""
            dnsMatchDomains = []
            mtu = defaultMobileMtu
            errorText = PacketTunnelError.invalidConfig("Invalid tunnel configuration")
            return
        }
        let error = object["error"] as? String ?? ""
        localAddress = object["localAddress"] as? String ?? "10.44.0.1/32"
        routeTargets = object["routeTargets"] as? [String] ?? []
        excludedRoutes = object["excludedRoutes"] as? [String] ?? []
        dnsServers = object["dnsServers"] as? [String] ?? []
        magicDnsServer = object["magicDnsServer"] as? String ?? ""
        dnsMatchDomains = object["dnsMatchDomains"] as? [String] ?? []
        mtu = object["mtu"] as? Int ?? defaultMobileMtu
        errorText = error.isEmpty ? nil : PacketTunnelError.invalidConfig(error)
    }
}

private func parseIPv4CIDR(_ value: String) -> (address: String, mask: String)? {
    let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
    guard let address = parts.first.map(String.init), !address.isEmpty else {
        return nil
    }
    let prefix = parts.count == 2 ? Int(parts[1]) ?? 32 : 32
    guard (0...32).contains(prefix) else {
        return nil
    }
    return (address, ipv4Mask(prefixLength: prefix))
}

private func ipv4Route(_ value: String) -> NEIPv4Route? {
    guard let parsed = parseIPv4CIDR(value) else {
        return nil
    }
    if parsed.address == "0.0.0.0" && parsed.mask == "0.0.0.0" {
        // iOS treats `NEIPv4Route.default()` and an explicit
        // (0.0.0.0/0) differently in some kernel paths — the former
        // is the documented default route. Always normalize.
        return NEIPv4Route.default()
    }
    return NEIPv4Route(destinationAddress: parsed.address, subnetMask: parsed.mask)
}

private func consumeCString(_ pointer: UnsafeMutablePointer<CChar>?) -> String {
    guard let pointer else {
        return ""
    }
    defer { nostr_vpn_string_free(pointer) }
    return String(cString: pointer)
}

private func packetDebugLog(_ message: String) {
    #if DEBUG
    guard let logDir = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)?
        .appendingPathComponent("Nostr VPN", isDirectory: true)
    else {
        return
    }
    try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
    let logUrl = logDir.appendingPathComponent("nvpn-pkt-debug.log")
    let line = "[\(Date())] \(message)\n"
    guard let data = line.data(using: .utf8) else {
        return
    }
    let existingBytes = (
        try? FileManager.default.attributesOfItem(atPath: logUrl.path)[.size] as? NSNumber
    )?.intValue ?? 0
    if existingBytes + data.count > packetDebugLogLimitBytes {
        let previousURL = logUrl.appendingPathExtension("previous")
        try? FileManager.default.removeItem(at: previousURL)
        try? FileManager.default.moveItem(at: logUrl, to: previousURL)
    }
    if FileManager.default.fileExists(atPath: logUrl.path),
       let handle = try? FileHandle(forWritingTo: logUrl)
    {
        handle.seekToEndOfFile()
        handle.write(data)
        try? handle.close()
    } else {
        try? data.write(to: logUrl, options: .atomic)
    }
    #endif
}

private func elapsedMs(since start: TimeInterval) -> Int {
    max(0, Int((ProcessInfo.processInfo.systemUptime - start) * 1000))
}

private func ipv4Mask(prefixLength: Int) -> String {
    guard prefixLength > 0 else {
        return "0.0.0.0"
    }
    let value = prefixLength == 32 ? UInt32.max : UInt32.max << UInt32(32 - prefixLength)
    return [
        String((value >> 24) & 0xff),
        String((value >> 16) & 0xff),
        String((value >> 8) & 0xff),
        String(value & 0xff),
    ].joined(separator: ".")
}
