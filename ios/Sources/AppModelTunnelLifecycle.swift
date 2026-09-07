import Foundation

extension AppModel {
    func reconcilePacketTunnelAtStartup() {
        guard startupTunnelReconciliationTask == nil else {
            return
        }
        startupTunnelReconciliationGeneration &+= 1
        let generation = startupTunnelReconciliationGeneration
        startupTunnelReconciliationTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if startupTunnelReconciliationGeneration == generation {
                    startupTunnelReconciliationTask = nil
                }
            }
            await performStartupTunnelReconciliation(generation: generation)
        }
    }

    private func performStartupTunnelReconciliation(generation: UInt64) async {
        do {
            try requireStartupTunnelReconciliation(generation)
            if !state.vpnEnabled, !state.joinRequestQrCodeOrLink.isEmpty {
                await reconcilePendingJoinTunnelSidecarAtStartup()
                try requireStartupTunnelReconciliation(generation)
                if !state.vpnEnabled,
                   state.autoconnect,
                   !state.joinRequestQrCodeOrLink.isEmpty
                {
                    debugLog("startup preserving QR join tunnel until approval reconciliation")
                    ensureAutoconnectPacketTunnel(reason: "startup")
                    return
                }
            }

            actionInFlight = true
            if state.vpnEnabled {
                guard try await reconcileStartupTunnelRoutes(generation: generation) else {
                    actionInFlight = false
                    return
                }
            } else {
                statusMessage = "Restoring direct Internet"
                let status = try await vpnController.stopAndWaitForDisconnected()
                try requireStartupTunnelReconciliation(generation)
                debugLog("startup confirmed native VPN-off status=\(status)")
            }
            try requireStartupTunnelReconciliation(generation)
            actionInFlight = false
            statusMessage = state.error
            ensureAutoconnectPacketTunnel(reason: "startup")
        } catch is CancellationError {
            return
        } catch {
            actionInFlight = false
            statusMessage = error.localizedDescription
            debugLog("startup tunnel reconciliation failed: \(String(describing: error))")
        }
    }

    private func reconcileStartupTunnelRoutes(generation: UInt64) async throws -> Bool {
        guard packetTunnelStartAllowed(reason: "startup") else {
            return false
        }
        let status = await vpnController.statusRawValue()
        try requireStartupTunnelReconciliation(generation)
        let needsStart = Self.packetTunnelNeedsStart(statusRawValue: status)
        guard let core else {
            statusMessage = "Native core unavailable"
            return false
        }
        let providerOptionsConfigJson = core.mobileTunnelProviderOptionsConfigJson()
        let replacementRestartRequired = vpnController.replacementRestartRequired()
        if !needsStart, !replacementRestartRequired {
            guard let desired = PacketTunnelController.routeState(
                in: providerOptionsConfigJson
            ) else {
                statusMessage = "VPN route configuration is unavailable"
                debugLog("startup route reconciliation rejected invalid desired config")
                return false
            }
            let installed = await vpnController.installedRouteState()
            try requireStartupTunnelReconciliation(generation)
            if installed == desired {
                let providerResponsive = await vpnController.providerIsResponsive()
                try requireStartupTunnelReconciliation(generation)
                if providerResponsive {
                    return true
                }
                debugLog(
                    "startup replacing unresponsive PacketTunnel with matching saved routes"
                )
            }
        }

        statusMessage = needsStart ? "Restoring VPN" : "Updating VPN routes"
        // Relaunch must preserve the approval carrier just like a live config
        // update. The shared queue waits for pending receipts before replacing it.
        enqueuePacketTunnelOperation(.syncConfig(reason: "startup", force: true))
        return false
    }

    private func requireStartupTunnelReconciliation(_ generation: UInt64) throws {
        guard !Task.isCancelled,
              startupTunnelReconciliationGeneration == generation
        else {
            throw CancellationError()
        }
    }

    func enqueuePacketTunnelOperation(_ operation: PacketTunnelOperation) {
        tunnelConfigSyncTask?.cancel()
        tunnelConfigSyncTask = nil
        let startupPrevious = startupTunnelReconciliationTask
        startupTunnelReconciliationGeneration &+= 1
        startupPrevious?.cancel()
        startupTunnelReconciliationTask = nil

        let previous = packetTunnelTransitionTask
        previous?.cancel()
        packetTunnelTransitionGeneration &+= 1
        let generation = packetTunnelTransitionGeneration
        packetTunnelTransitionTask = Task { [weak self] in
            _ = await startupPrevious?.value
            _ = await previous?.value
            guard let self, packetTunnelTransitionIsCurrent(generation) else {
                return
            }
            defer {
                if packetTunnelTransitionGeneration == generation {
                    packetTunnelTransitionTask = nil
                    if case .setEnabled = operation {
                        pendingVpnTransitionEnabled = nil
                    }
                }
            }
            actionInFlight = false
            do {
                switch operation {
                case .setEnabled(true, let force):
                    try await performVpnStart(force: force, generation: generation)
                case .setEnabled(false, let force):
                    try await performVpnStop(force: force, generation: generation)
                case .syncConfig(let reason, let force):
                    try await syncPacketTunnelConfig(
                        reason: reason,
                        force: force,
                        generation: generation
                    )
                }
            } catch is CancellationError {
                return
            } catch {
                guard packetTunnelTransitionIsCurrent(generation) else {
                    return
                }
                actionInFlight = false
                switch operation {
                case .setEnabled(false, _):
                    // OFF is already durable; keep runtime state visible until teardown is confirmed.
                    break
                case .setEnabled(true, _), .syncConfig(_, _):
                    if let replacementError = error as? PacketTunnelReplacementError,
                       replacementError.disconnectConfirmed
                    {
                        dispatch(NativeActions.disconnectVpn(), status: "Turning VPN off")
                    }
                }
                statusMessage = error.localizedDescription
                debugLog("PacketTunnel operation failed: \(String(describing: error))")
            }
        }
    }

    private func performVpnStart(force: Bool, generation: UInt64) async throws {
        guard vpnStartIsDesired() else {
            debugLog("connect skipped: VPN off is desired")
            return
        }
        guard packetTunnelStartAllowed(reason: "VPN start") else {
            return
        }
        guard let core else {
            statusMessage = "Native core unavailable"
            return
        }
        guard force || !state.vpnEnabled else {
            debugLog("connect skipped: already enabled")
            return
        }
        if state.vpnEnabled {
            statusMessage = "Turning VPN on"
        } else {
            dispatch(NativeActions.connectVpn(), status: "Turning VPN on")
        }
        guard packetTunnelTransitionIsCurrent(generation),
              state.error.isEmpty,
              state.vpnEnabled
        else {
            debugLog("connect aborted after native enable error=\(state.error)")
            return
        }
        let tunnelConfigJson = core.mobileTunnelConfigJson()
        let providerOptionsConfigJson = core.mobileTunnelProviderOptionsConfigJson()
        debugLog("mobileTunnelConfigJson len=\(tunnelConfigJson.count)")
        try await vpnController.start(
            state: state,
            network: activeNetwork,
            tunnelConfigJson: tunnelConfigJson,
            providerOptionsConfigJson: providerOptionsConfigJson
        )
        try requirePacketTunnelTransition(generation)
        if statusMessage == "Turning VPN on" {
            statusMessage = state.error
        }
        debugLog("PacketTunnel start returned success")
    }

    private func performVpnStop(force: Bool, generation: UInt64) async throws {
        guard force || state.vpnEnabled else {
            debugLog("disconnect skipped: already disabled")
            return
        }
        actionInFlight = true
        statusMessage = "Turning VPN off"
        let status = try await vpnController.stopAndWaitForDisconnected()
        try requirePacketTunnelTransition(generation)
        actionInFlight = false
        dispatch(NativeActions.disconnectVpn(), status: "Turning VPN off")
        debugLog("PacketTunnel confirmed disconnected status=\(status)")
    }

    private func packetTunnelTransitionIsCurrent(_ generation: UInt64) -> Bool {
        !Task.isCancelled && packetTunnelTransitionGeneration == generation
    }

    func requirePacketTunnelTransition(_ generation: UInt64) throws {
        guard packetTunnelTransitionIsCurrent(generation) else {
            throw CancellationError()
        }
    }
}
