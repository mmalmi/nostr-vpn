import Darwin
import Foundation

private struct DebugProcessCpuSample {
    let pid: Int
    let cpuSeconds: Double
}

extension AppModel {
    func runLaunchAutomationIfRequested() -> Bool {
        #if DEBUG
        guard !launchAutomationHandled else {
            return false
        }
        launchAutomationHandled = true

        let rawArguments = ProcessInfo.processInfo.arguments
        return runDebugAutomation(arguments: rawArguments)
        #else
        return false
        #endif
    }

    func runDebugAutomation(arguments rawArguments: [String]) -> Bool {
        #if DEBUG
        let arguments = Set(rawArguments)
        debugLog("debug automation args=\(Self.redactedDebugArguments(rawArguments))")
        let lifecycleProbeArmed = armDebugLifecycleProbeIfRequested(arguments: rawArguments)
        let addedNetwork = addDebugNetworkIfPresent(arguments: rawArguments)
        let exportedSupportFile = exportDebugSupportFileIfRequested(arguments: rawArguments)
        if arguments.contains("--nvpn-debug-idle-cpu-probe") {
            Task {
                await runDebugIdleCpuProbe(arguments: rawArguments)
            }
            return true
        }
        if arguments.contains("--nvpn-debug-exit-probe") {
            Task {
                await runDebugExitProbe(arguments: rawArguments)
            }
            return true
        }
        if let resultName = Self.argumentValue(
            after: "--nvpn-debug-disconnect-result",
            in: rawArguments
        ) {
            Task {
                await runDebugDisconnect(resultName: resultName)
            }
            return true
        }
        if let resultName = Self.argumentValue(
            after: "--nvpn-debug-connect-result",
            in: rawArguments
        ) {
            Task {
                await runDebugConnect(resultName: resultName)
            }
            return true
        }
        if let resultName = Self.argumentValue(
            after: "--nvpn-debug-runtime-result",
            in: rawArguments
        ) {
            Task {
                await writeDebugRuntimeSnapshot(resultName: resultName)
            }
            return true
        }
        if arguments.contains("--nvpn-connect") {
            setVpnEnabled(true, force: true)
            return true
        }
        if arguments.contains("--nvpn-disconnect") {
            setVpnEnabled(false, force: true)
            return true
        }
        return lifecycleProbeArmed || addedNetwork || exportedSupportFile
        #else
        return false
        #endif
    }

    private func addDebugNetworkIfPresent(arguments: [String]) -> Bool {
        #if DEBUG
        guard let name = Self.argumentValue(after: "--nvpn-debug-add-network", in: arguments) else {
            return false
        }
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines)
        dispatch(NativeActions.addNetwork(normalized.isEmpty ? "iOS smoke" : normalized))
        tunnelConfigSyncTask?.cancel()
        tunnelConfigSyncTask = nil
        refresh()
        return true
        #else
        return false
        #endif
    }

    private func exportDebugSupportFileIfRequested(arguments: [String]) -> Bool {
        #if DEBUG
        guard let sourceName = Self.argumentValue(
            after: "--nvpn-debug-export-support-file",
            in: arguments
        ),
        let supportDir,
        let debugResultsDir = Self.debugResultsDirectory()
        else {
            return false
        }
        let safeSourceName = sourceName.split(separator: "/").last.map(String.init) ?? ""
        guard !safeSourceName.isEmpty,
              let data = try? Data(
                contentsOf: supportDir.appendingPathComponent(safeSourceName)
              )
        else {
            return false
        }
        let requestedResultName = Self.argumentValue(
            after: "--nvpn-debug-export-result",
            in: arguments
        ) ?? safeSourceName
        let safeResultName = requestedResultName
            .split(separator: "/")
            .last
            .map(String.init) ?? safeSourceName
        do {
            try FileManager.default.createDirectory(
                at: debugResultsDir,
                withIntermediateDirectories: true
            )
            try data.write(
                to: debugResultsDir.appendingPathComponent(safeResultName),
                options: .atomic
            )
            return true
        } catch {
            return false
        }
        #else
        return false
        #endif
    }

    private func runDebugIdleCpuProbe(arguments: [String]) async {
        #if DEBUG
        let resultName = Self.argumentValue(after: "--nvpn-debug-idle-cpu-result", in: arguments)
            ?? "debug-idle-cpu.json"
        let sampleSeconds = Self.clampedDoubleArgument(
            "--nvpn-debug-idle-cpu-sample-seconds",
            in: arguments,
            defaultValue: 10,
            minValue: 0.1,
            maxValue: 120
        )
        let settleSeconds = Self.clampedDoubleArgument(
            "--nvpn-debug-idle-cpu-settle-seconds",
            in: arguments,
            defaultValue: 3,
            minValue: 0,
            maxValue: 120
        )
        let maxPercent = Self.clampedDoubleArgument(
            "--nvpn-debug-idle-cpu-max-percent",
            in: arguments,
            defaultValue: 5,
            minValue: 0,
            maxValue: 100
        )
        let process = Self.argumentValue(
            after: "--nvpn-debug-idle-cpu-process",
            in: arguments
        ) ?? "app"
        let label = process == "packet-tunnel" ? "iOS packet tunnel" : "iOS app"
        let startedAt = Date()
        var result: [String: Any] = [
            "ok": false,
            "phase": "settling",
            "label": label,
            "process": process,
            "maxPercent": maxPercent,
            "sampleSeconds": sampleSeconds,
            "settleSeconds": settleSeconds,
            "startedAt": ISO8601DateFormatter().string(from: startedAt),
        ]
        for (key, value) in Self.appBuildMetadata() {
            result[key] = value
        }
        writeDebugProbeResult(result, name: resultName)
        if settleSeconds > 0 {
            try? await Task.sleep(nanoseconds: UInt64(settleSeconds * 1_000_000_000))
        }
        guard let start = await debugProcessCpuSample(process: process) else {
            result["phase"] = "finished"
            result["error"] = "idle CPU process metrics unavailable"
            result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
            writeDebugProbeResult(result, name: resultName)
            return
        }
        let sampleStartedAt = Date()
        result["phase"] = "sampling"
        result["pid"] = start.pid
        result["sampleStartedAt"] = ISO8601DateFormatter().string(from: sampleStartedAt)
        writeDebugProbeResult(result, name: resultName)
        try? await Task.sleep(nanoseconds: UInt64(sampleSeconds * 1_000_000_000))
        let elapsed = max(0.001, Date().timeIntervalSince(sampleStartedAt))
        guard let end = await debugProcessCpuSample(process: process) else {
            result["phase"] = "finished"
            result["error"] = "idle CPU process exited during sampling"
            result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
            writeDebugProbeResult(result, name: resultName)
            return
        }
        guard end.pid == start.pid, end.cpuSeconds >= start.cpuSeconds else {
            result["phase"] = "finished"
            result["error"] = "idle CPU process restarted during sampling"
            result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
            writeDebugProbeResult(result, name: resultName)
            return
        }
        let cpuSeconds = end.cpuSeconds - start.cpuSeconds
        let cpuPercent = cpuSeconds * 100.0 / elapsed
        result["phase"] = "finished"
        result["ok"] = cpuPercent <= maxPercent
        result["cpuPercent"] = cpuPercent
        result["elapsedSeconds"] = elapsed
        result["cpuSeconds"] = cpuSeconds
        result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
        result["debugProbeElapsedMs"] = Self.elapsedMilliseconds(since: startedAt)
        writeDebugProbeResult(result, name: resultName)
        #endif
    }

    private func debugProcessCpuSample(process: String) async -> DebugProcessCpuSample? {
        if process == "packet-tunnel" {
            guard let metrics = await vpnController.packetTunnelProcessMetrics() else {
                return nil
            }
            return DebugProcessCpuSample(pid: metrics.pid, cpuSeconds: metrics.cpuSeconds)
        }
        guard process == "app", let cpuSeconds = Self.processCpuSeconds() else {
            return nil
        }
        return DebugProcessCpuSample(pid: Int(getpid()), cpuSeconds: cpuSeconds)
    }

    private func runDebugDisconnect(resultName: String) async {
        #if DEBUG
        let startedAt = Date()
        var result: [String: Any] = [
            "ok": false,
            "phase": "stopping",
            "startedAt": ISO8601DateFormatter().string(from: startedAt),
        ]
        for (key, value) in Self.appBuildMetadata() {
            result[key] = value
        }
        writeDebugProbeResult(result, name: resultName)

        refresh()
        if state.vpnEnabled {
            dispatch(NativeActions.disconnectVpn())
        }
        var status: Int?
        do {
            status = try await vpnController.stopAndWaitForDisconnected()
        } catch {
            result["stopError"] = error.localizedDescription
            debugLog("debug disconnect stop failed: \(String(describing: error))")
        }
        refresh()
        if let status {
            result["packetTunnelStatusRawValue"] = status
        }
        result["ok"] = status.map { $0 <= 1 } ?? false
        result["phase"] = "finished"
        result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
        result["debugProbeElapsedMs"] = Self.elapsedMilliseconds(since: startedAt)
        writeDebugProbeResult(result, name: resultName)
        #endif
    }

    private func runDebugConnect(resultName: String) async {
        #if DEBUG
        let startedAt = Date()
        var result: [String: Any] = [
            "ok": false,
            "phase": "starting",
            "startedAt": ISO8601DateFormatter().string(from: startedAt),
        ]
        for (key, value) in Self.appBuildMetadata() {
            result[key] = value
        }
        writeDebugProbeResult(result, name: resultName)

        if let error = await startVpnForDebugProbe() {
            result["startError"] = error
        } else {
            for _ in 0..<30 {
                if await vpnController.statusRawValue() == 3 {
                    break
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
        let status = await vpnController.statusRawValue()
        if let status {
            result["packetTunnelStatusRawValue"] = status
        }
        result["ok"] = status == 3
        result["phase"] = "finished"
        result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
        result["debugProbeElapsedMs"] = Self.elapsedMilliseconds(since: startedAt)
        writeDebugProbeResult(result, name: resultName)
        if status != 3 {
            await stopFailedDebugProbeTunnel()
        }
        #endif
    }

    private func writeDebugRuntimeSnapshot(resultName: String) async {
        #if DEBUG
        var result: [String: Any] = ["ok": false]
        if let json = await vpnController.runtimeStateJson(),
           let data = json.data(using: .utf8),
           let runtime = try? JSONSerialization.jsonObject(with: data)
        {
            result["ok"] = true
            result["runtime"] = runtime
        }
        writeDebugProbeResult(result, name: resultName)
        #endif
    }

    private func runDebugExitProbe(arguments: [String]) async {
        #if DEBUG
        let urlString = Self.argumentValue(after: "--nvpn-debug-fetch-url", in: arguments)
            ?? "https://am.i.mullvad.net/json"
        let resultName = Self.argumentValue(after: "--nvpn-debug-result", in: arguments)
            ?? "debug-exit-probe.json"
        let waitSeconds = Self.argumentValue(after: "--nvpn-debug-wait-seconds", in: arguments)
            .flatMap(Double.init) ?? 12
        let awaitActiveTunnelLifecycle = arguments.contains(
            "--nvpn-debug-await-active-tunnel-lifecycle"
        )
        let resolveHost = Self.argumentValue(after: "--nvpn-debug-resolve-host", in: arguments)
        let skipFetch = arguments.contains("--nvpn-debug-skip-fetch")
        let verifyDirectRestoration = arguments.contains("--nvpn-debug-verify-direct-restoration")
        let directFetchUrl = Self.argumentValue(
            after: "--nvpn-debug-direct-fetch-url",
            in: arguments
        )
        let directResolveHost = Self.argumentValue(
            after: "--nvpn-debug-direct-resolve-host",
            in: arguments
        )
        let probeStartedAt = Date()
        var result: [String: Any] = [
            "debugDnsInjected":
                Self.argumentValue(after: "--nvpn-debug-exit-dns-mode", in: arguments) != nil,
            "url": urlString,
            "phase": "starting",
            "startedAt": ISO8601DateFormatter().string(from: probeStartedAt),
        ]
        for (key, value) in Self.appBuildMetadata() {
            result[key] = value
        }

        await stopVpnForDebugProbe()
        if verifyDirectRestoration {
            for (key, value) in await debugNetworkProbe(
                urlString: directFetchUrl,
                resolveHost: directResolveHost
            ) {
                result["directBefore\(key.prefix(1).uppercased())\(key.dropFirst())"] = value
            }
            result["directBeforePacketTunnelStatusRawValue"] =
                await vpnController.statusRawValue()
        }

        let settingsPatch = Self.debugExitSettingsPatch(
            arguments: arguments,
            supportDir: supportDir
        )
        if !settingsPatch.isEmpty {
            dispatch(NativeActions.updateSettings(settingsPatch))
        }
        refresh()

        writeDebugProbeResult(result, name: resultName)
        let vpnStartStartedAt = Date()
        let startError = await startVpnForDebugProbe()
        result["vpnStartElapsedMs"] = Self.elapsedMilliseconds(since: vpnStartStartedAt)
        result["vpnStartFinishedAt"] = ISO8601DateFormatter().string(from: Date())
        if let error = startError {
            result["startError"] = error
            result["phase"] = "start_failed"
            writeDebugProbeResult(result, name: resultName)
        } else if waitSeconds > 0 {
            result["phase"] = "waiting_for_tunnel"
            result["vpnWaitRequestedMs"] = Int(waitSeconds * 1000)
            writeDebugProbeResult(result, name: resultName)
            try? await Task.sleep(nanoseconds: UInt64(waitSeconds * 1_000_000_000))
        }
        refresh()
        result["phase"] = "collecting_status"
        writeDebugProbeResult(result, name: resultName)
        let statusStartedAt = Date()
        result["phase"] = "finished"
        let packetTunnelStatus = await vpnController.statusRawValue()
        if let packetTunnelStatus {
            result["packetTunnelStatusRawValue"] = packetTunnelStatus
        }
        let packetTunnelConnected = packetTunnelStatus == 3
        result["packetTunnelConnected"] = packetTunnelConnected
        if packetTunnelConnected, awaitActiveTunnelLifecycle {
            result.merge(
                await runDebugActiveTunnelLifecycle(
                    arguments: arguments,
                    resultName: resultName,
                    baseResult: result
                )
            ) { _, new in new }
        }
        if packetTunnelConnected {
            for (key, value) in await runDebugTunPacketProbe(arguments: arguments) {
                result[key] = value
            }
        } else {
            await stopFailedDebugProbeTunnel()
        }
        if let runtimeJson = await vpnController.runtimeStateJson() {
            result["packetTunnelRuntimeStateJson"] = runtimeJson
        }
        refresh()
        result["exitNode"] = state.exitNode
        result["vpnEnabled"] = state.vpnEnabled
        result["vpnActive"] = state.vpnActive
        result["connectedPeerCount"] = state.connectedPeerCount
        result["expectedPeerCount"] = state.expectedPeerCount
        result["fipsConnectedPeerCount"] = state.fipsConnectedPeerCount
        result["fipsRosterPeerCount"] = state.fipsRosterPeerCount
        result["nonFipsRosterPeerCount"] = state.nonFipsRosterPeerCount
        result["exitNodeLeakProtection"] = state.exitNodeLeakProtection
        result["wireguardExitEnabled"] = state.wireguardExitEnabled
        result["wireguardExitConfigured"] = state.wireguardExitConfigured
        result["wireguardExitEndpoint"] = state.wireguardExitEndpoint
        result.merge(debugExitDnsStateResult()) { _, new in new }
        result["statusCollectionElapsedMs"] = Self.elapsedMilliseconds(since: statusStartedAt)

        if let host = resolveHost?.trimmingCharacters(in: .whitespacesAndNewlines),
           !host.isEmpty {
            let resolved = Self.resolveDebugHost(host)
            result["resolvedHost"] = host
            result["resolvedAddresses"] = resolved.addresses
            if let error = resolved.error {
                result["resolveError"] = error
            }
        }

        if !skipFetch {
            let fetchStartedAt = Date()
            for (key, value) in await fetchDebugProbe(urlString: urlString) {
                result[key] = value
            }
            result["fetchElapsedMs"] = Self.elapsedMilliseconds(since: fetchStartedAt)
        }
        if awaitActiveTunnelLifecycle {
            result["postForegroundProbe"] =
                result["activeTunnelLifecycleObserved"] as? Bool == true
        }
        if arguments.contains("--nvpn-debug-await-direct-ui-while-connected") {
            result.merge(await runDebugDirectWhileConnected(
                waitSeconds: waitSeconds,
                fetchUrl: directFetchUrl,
                resolveHost: directResolveHost
            )) { _, new in new }
        }
        if verifyDirectRestoration {
            await stopVpnForDebugProbe()
            result["directAfterPacketTunnelStatusRawValue"] =
                await vpnController.statusRawValue()
            for (key, value) in await debugNetworkProbe(
                urlString: directFetchUrl,
                resolveHost: directResolveHost
            ) {
                result["directAfter\(key.prefix(1).uppercased())\(key.dropFirst())"] = value
            }
        }
        result["debugProbeElapsedMs"] = Self.elapsedMilliseconds(since: probeStartedAt)
        result["finishedAt"] = ISO8601DateFormatter().string(from: Date())
        writeDebugProbeResult(result, name: resultName)
        if awaitActiveTunnelLifecycle {
            statusMessage = "VPN lifecycle release probe finished"
        }
        #endif
    }

    private func runDebugActiveTunnelLifecycle(
        arguments: [String],
        resultName: String,
        baseResult: [String: Any]
    ) async -> [String: Any] {
        #if DEBUG
        let requiredCycles = Self.clampedIntArgument(
            "--nvpn-debug-active-lifecycle-cycles",
            in: arguments,
            defaultValue: 3,
            minValue: 1,
            maxValue: 5
        )
        let timeoutSeconds = Self.clampedDoubleArgument(
            "--nvpn-debug-active-lifecycle-timeout-seconds",
            in: arguments,
            defaultValue: 45,
            minValue: 5,
            maxValue: 600
        )
        let baselineTransition = lifecycleProbeTransition
        var progress = baseResult
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        var completedCycles = 0
        var cycleResults: [[String: Any]] = []
        var statusBeforeBackground = await vpnController.statusRawValue() ?? -1
        statusMessage = "Active VPN ready for lifecycle cycle 1"

        for cycle in 1...requiredCycles {
            progress["activeTunnelLifecycleCycles"] = completedCycles
            progress["activeTunnelLifecycleCycleResults"] = cycleResults
            progress["activeTunnelLifecycleObserved"] = false
            progress["phase"] = "awaiting_active_tunnel_lifecycle_cycle_\(cycle)"
            writeDebugProbeResult(progress, name: resultName)

            repeat {
                completedCycles = completedDebugLifecycleCycles(
                    after: baselineTransition
                )
                if completedCycles >= cycle {
                    break
                }
                try? await Task.sleep(nanoseconds: 100_000_000)
            } while Date() < deadline
            guard completedCycles >= cycle else {
                break
            }

            var cycleResult = await runDebugActiveTunnelCycleProbe(
                arguments: arguments,
                cycle: cycle,
                statusBeforeBackground: statusBeforeBackground
            )
            cycleResult["cycle"] = cycle
            cycleResults.append(cycleResult)
            progress["activeTunnelLifecycleCycles"] = completedCycles
            progress["activeTunnelLifecycleCycleResults"] = cycleResults
            progress["phase"] = "verified_active_tunnel_lifecycle_cycle_\(cycle)"
            writeDebugProbeResult(progress, name: resultName)
            if cycle < requiredCycles {
                statusMessage =
                    "Active VPN lifecycle verified \(cycle)/\(requiredCycles); "
                    + "ready for cycle \(cycle + 1)"
                statusBeforeBackground = await vpnController.statusRawValue() ?? -1
            } else {
                statusMessage =
                    "Active VPN lifecycle verified \(cycle)/\(requiredCycles)"
            }
        }

        let observed =
            completedCycles >= requiredCycles && cycleResults.count == requiredCycles
        if !observed {
            statusMessage = "Active VPN lifecycle timed out"
        }
        let firstStatus =
            cycleResults.first?["statusBeforeBackgroundRawValue"] ?? statusBeforeBackground
        let lastStatus: Any
        if let recorded = cycleResults.last?["statusAfterForegroundRawValue"] {
            lastStatus = recorded
        } else {
            lastStatus = await vpnController.statusRawValue() ?? -1
        }
        return [
            "activeTunnelLifecycleCycles": completedCycles,
            "activeTunnelLifecycleCycleResults": cycleResults,
            "activeTunnelLifecycleObserved": observed,
            "activeTunnelStatusBeforeBackgroundRawValue": firstStatus,
            "activeTunnelStatusAfterForegroundRawValue": lastStatus,
        ]
        #else
        return [:]
        #endif
    }

    private func runDebugActiveTunnelCycleProbe(
        arguments: [String],
        cycle: Int,
        statusBeforeBackground: Int
    ) async -> [String: Any] {
        #if DEBUG
        let urlString = Self.argumentValue(after: "--nvpn-debug-fetch-url", in: arguments)
            ?? "https://am.i.mullvad.net/json"
        let resolveHost = Self.argumentValue(after: "--nvpn-debug-resolve-host", in: arguments)
        let skipFetch = arguments.contains("--nvpn-debug-skip-fetch")
        let statusAfterForeground = await vpnController.statusRawValue() ?? -1
        var result: [String: Any] = [
            "cycle": cycle,
            "postForegroundProbe": true,
            "statusAfterForegroundRawValue": statusAfterForeground,
            "statusBeforeBackgroundRawValue": statusBeforeBackground,
        ]
        if statusAfterForeground == 3 {
            result.merge(await runDebugTunPacketProbe(arguments: arguments)) { _, new in new }
        }
        if let runtimeJson = await vpnController.runtimeStateJson() {
            result["packetTunnelRuntimeStateJson"] = runtimeJson
        }
        refresh()
        result["vpnEnabled"] = state.vpnEnabled
        result["vpnActive"] = state.vpnActive
        result["wireguardExitEnabled"] = state.wireguardExitEnabled
        result["wireguardExitConfigured"] = state.wireguardExitConfigured
        result["wireguardExitEndpoint"] = state.wireguardExitEndpoint
        result.merge(debugExitDnsStateResult()) { _, new in new }

        if let host = resolveHost?.trimmingCharacters(in: .whitespacesAndNewlines),
           !host.isEmpty {
            let resolved = Self.resolveDebugHost(host)
            result["resolvedHost"] = host
            result["resolvedAddresses"] = resolved.addresses
            if let error = resolved.error {
                result["resolveError"] = error
            }
        }
        if !skipFetch {
            result["url"] = urlString
            for (key, value) in await fetchDebugProbe(urlString: urlString) {
                result[key] = value
            }
        }
        return result
        #else
        return [:]
        #endif
    }

    private func completedDebugLifecycleCycles(after baselineTransition: Int) -> Int {
        #if DEBUG
        var waitingForActive = false
        var completed = 0
        for event in lifecycleProbeHistory {
            guard let transition = event["transition"] as? Int,
                  transition > baselineTransition,
                  let phase = event["phase"] as? String
            else {
                continue
            }
            if phase == "background" {
                waitingForActive = true
            } else if phase == "active", waitingForActive {
                completed += 1
                waitingForActive = false
            }
        }
        return completed
        #else
        return 0
        #endif
    }

    private func stopVpnForDebugProbe() async {
        refresh()
        guard state.vpnEnabled else {
            return
        }
        dispatch(NativeActions.disconnectVpn())
        do {
            _ = try await vpnController.stopAndWaitForDisconnected()
        } catch {
            debugLog("debug probe stop failed: \(String(describing: error))")
        }
        refresh()
    }

    private func stopFailedDebugProbeTunnel() async {
        if state.vpnEnabled {
            dispatch(NativeActions.disconnectVpn())
        }
        do {
            _ = try await vpnController.stopAndWaitForDisconnected()
        } catch {
            debugLog("debug probe failed-state stop failed: \(String(describing: error))")
        }
    }

    private func startVpnForDebugProbe() async -> String? {
        guard let core else {
            return "Native core unavailable"
        }
        guard packetTunnelStartAllowed(reason: "debug probe") else {
            return Self.vpnDisclosurePromptMessage
        }
        if !state.vpnEnabled {
            dispatch(NativeActions.connectVpn())
        }
        guard state.error.isEmpty, state.vpnEnabled else {
            return state.error.isEmpty ? "Native VPN state did not enable" : state.error
        }
        let tunnelConfigJson = core.mobileTunnelConfigJson()
        let providerOptionsConfigJson = core.mobileTunnelProviderOptionsConfigJson()
        do {
            try await vpnController.start(
                state: state,
                network: activeNetwork,
                tunnelConfigJson: tunnelConfigJson,
                providerOptionsConfigJson: providerOptionsConfigJson
            )
            return nil
        } catch {
            dispatch(NativeActions.disconnectVpn())
            let message = error.localizedDescription
            debugLog("debug probe start failed: \(message)")
            return message
        }
    }

    private func fetchDebugProbe(urlString: String) async -> [String: Any] {
        var result: [String: Any] = [:]
        guard let url = URL(string: urlString) else {
            result["fetchError"] = "Invalid URL"
            return result
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 25
        let session = URLSession(configuration: configuration)
        do {
            let (data, response) = try await session.data(from: url)
            if let http = response as? HTTPURLResponse {
                result["statusCode"] = http.statusCode
            }
            if let body = String(data: data, encoding: .utf8) {
                result["body"] = String(body.prefix(4096))
            } else {
                result["byteCount"] = data.count
            }
        } catch {
            result["fetchError"] = String(describing: error)
        }
        return result
    }

    func debugNetworkProbe(
        urlString: String?,
        resolveHost: String?
    ) async -> [String: Any] {
        var result: [String: Any] = [:]
        if let host = resolveHost?.trimmingCharacters(in: .whitespacesAndNewlines),
           !host.isEmpty {
            let resolved = Self.resolveDebugHost(host)
            result["resolvedHost"] = host
            result["resolvedAddresses"] = resolved.addresses
            if let error = resolved.error {
                result["resolveError"] = error
            }
        }
        if let urlString = urlString?.trimmingCharacters(in: .whitespacesAndNewlines),
           !urlString.isEmpty {
            for (key, value) in await fetchDebugProbe(urlString: urlString) {
                result[key] = value
            }
        }
        return result
    }

    nonisolated static func elapsedMilliseconds(since start: Date) -> Int {
        max(0, Int(Date().timeIntervalSince(start) * 1000))
    }

    nonisolated private static func processCpuSeconds() -> Double? {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else {
            return nil
        }
        return Double(usage.ru_utime.tv_sec)
            + Double(usage.ru_utime.tv_usec) / 1_000_000
            + Double(usage.ru_stime.tv_sec)
            + Double(usage.ru_stime.tv_usec) / 1_000_000
    }

    nonisolated private static func appBuildMetadata() -> [String: Any] {
        var metadata: [String: Any] = [:]
        if let bundleIdentifier = Bundle.main.bundleIdentifier,
           !bundleIdentifier.isEmpty {
            metadata["appBundleIdentifier"] = bundleIdentifier
        }
        for (infoKey, resultKey) in [
            ("CFBundleShortVersionString", "appVersionName"),
            ("CFBundleVersion", "appVersionCode"),
            ("NVPNBuildGitSha", "appBuildGitSha"),
            ("NVPNBuildTimestampUTC", "appBuildTimestampUtc"),
        ] {
            if let value = Bundle.main.object(forInfoDictionaryKey: infoKey) as? String {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty && !trimmed.hasPrefix("$(") {
                    metadata[resultKey] = trimmed
                }
            }
        }
        return metadata
    }

    func writeDebugProbeResult(_ result: [String: Any], name: String) {
        let safeName = name
            .split(separator: "/")
            .last
            .map(String.init) ?? "debug-exit-probe.json"
        guard JSONSerialization.isValidJSONObject(result),
              let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
        else {
            return
        }
        if let supportDir {
            let url = supportDir.appendingPathComponent(safeName)
            try? data.write(to: url, options: .atomic)
            debugLog("debug probe wrote \(url.path)")
        }
        #if DEBUG
        if let debugResultsDir = Self.debugResultsDirectory() {
            try? FileManager.default.createDirectory(
                at: debugResultsDir,
                withIntermediateDirectories: true
            )
            try? data.write(
                to: debugResultsDir.appendingPathComponent(safeName),
                options: .atomic
            )
        }
        #endif
    }

    nonisolated static func debugResultsDirectory() -> URL? {
        FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first?.appendingPathComponent("Nostr VPN Debug Results", isDirectory: true)
    }

    nonisolated static func argumentValue(after name: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: name) else {
            return nil
        }
        let valueIndex = arguments.index(after: index)
        guard valueIndex < arguments.endIndex else {
            return nil
        }
        return arguments[valueIndex]
    }

    nonisolated static func clampedIntArgument(
        _ name: String,
        in arguments: [String],
        defaultValue: Int,
        minValue: Int,
        maxValue: Int
    ) -> Int {
        guard let parsed = argumentValue(after: name, in: arguments).flatMap(Int.init) else {
            return defaultValue
        }
        return min(max(parsed, minValue), maxValue)
    }

    nonisolated static func clampedDoubleArgument(
        _ name: String,
        in arguments: [String],
        defaultValue: Double,
        minValue: Double,
        maxValue: Double
    ) -> Double {
        guard let parsed = argumentValue(after: name, in: arguments).flatMap(Double.init),
              parsed.isFinite
        else {
            return defaultValue
        }
        return min(max(parsed, minValue), maxValue)
    }

    nonisolated static func wireGuardConfig(from arguments: [String], supportDir: URL?) -> String? {
        if let encoded = argumentValue(after: "--nvpn-debug-wireguard-config-base64", in: arguments),
           let data = Data(base64Encoded: encoded),
           let config = String(data: data, encoding: .utf8) {
            return config
        }
        guard let path = argumentValue(after: "--nvpn-debug-wireguard-config-file", in: arguments) else {
            return nil
        }
        let url: URL
        if path.hasPrefix("/") {
            url = URL(fileURLWithPath: path)
        } else if let supportDir {
            url = supportDir.appendingPathComponent(path)
        } else {
            return nil
        }
        return try? String(contentsOf: url)
    }

    nonisolated private static func resolveDebugHost(_ host: String) -> (addresses: [String], error: String?) {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0 else {
            let message = gai_strerror(status).map { String(cString: $0) } ?? "getaddrinfo failed"
            return ([], message)
        }
        defer { freeaddrinfo(result) }

        var addresses = Set<String>()
        var cursor = result
        while let current = cursor {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let info = current.pointee
            if getnameinfo(
                info.ai_addr,
                info.ai_addrlen,
                &buffer,
                socklen_t(buffer.count),
                nil,
                0,
                NI_NUMERICHOST
            ) == 0 {
                addresses.insert(String(cString: buffer))
            }
            cursor = info.ai_next
        }

        return (Array(addresses).sorted(), nil)
    }

}
