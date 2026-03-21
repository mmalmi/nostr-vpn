import Foundation
import NetworkExtension

private func packetTunnelProvider(for context: UInt) -> PacketTunnelProvider? {
    guard let pointer = UnsafeMutableRawPointer(bitPattern: Int(context)) else {
        return nil
    }
    return Unmanaged<PacketTunnelProvider>.fromOpaque(pointer).takeUnretainedValue()
}

private func packetTunnelSettingsCallback(_ json: UnsafePointer<CChar>?, _ context: UInt) {
    guard let provider = packetTunnelProvider(for: context),
          let json
    else {
        return
    }
    provider.applyDynamicSettings(jsonText: String(cString: json))
}

private func packetTunnelPacketCallback(
    _ packet: UnsafePointer<UInt8>?,
    _ length: UInt,
    _ context: UInt
) {
    guard let provider = packetTunnelProvider(for: context),
          let packet,
          length > 0
    else {
        return
    }
    let data = Data(bytes: packet, count: Int(length))
    provider.writePacket(data)
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var packetLoopRunning = false

    override func startTunnel(
        options: [String : NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            let request = try loadStartRequest(
                from: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            )
            try? storeStartRequest(request)
            NSLog("[nvpn-ios] packet tunnel provider startTunnel %@", request.sessionName)
            let initialSettings = PacketTunnelNetworkSettingsPayload(
                localAddresses: [request.localAddress],
                routes: [],
                dnsServers: request.dnsServers,
                searchDomains: request.searchDomains,
                mtu: request.mtu
            )

            applyNetworkSettings(initialSettings) { [weak self] error in
                guard let self else {
                    completionHandler(error)
                    return
                }
                if let error {
                    updateRecordedTunnelError(error.localizedDescription)
                    NSLog("[nvpn-ios] packet tunnel apply settings failed %@", error.localizedDescription)
                    completionHandler(error)
                    return
                }

                let context = UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque())
                let started = request.configJson.withCString { configJson in
                    nvpn_ios_extension_start(
                        configJson,
                        context,
                        packetTunnelSettingsCallback,
                        packetTunnelPacketCallback
                    )
                }

                guard started else {
                    let error = NSError(
                        domain: "to.iris.nvpn.packet-tunnel",
                        code: 1,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                recordedTunnelError() ?? "Rust packet tunnel failed to start."
                        ]
                    )
                    updateRecordedTunnelError(error.localizedDescription)
                    NSLog("[nvpn-ios] packet tunnel rust start failed %@", error.localizedDescription)
                    completionHandler(error)
                    return
                }

                updateRecordedTunnelError(nil)
                self.packetLoopRunning = true
                self.readPacketsLoop()
                NSLog("[nvpn-ios] packet tunnel provider started")
                completionHandler(nil)
            }
        } catch {
            updateRecordedTunnelError(error.localizedDescription)
            NSLog("[nvpn-ios] packet tunnel startTunnel threw %@", error.localizedDescription)
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        packetLoopRunning = false
        nvpn_ios_extension_stop()
        updateRecordedTunnelError(nil)
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        guard let command = String(data: messageData, encoding: .utf8), command == "status" else {
            completionHandler?(nil)
            return
        }

        guard let pointer = nvpn_ios_extension_status_json() else {
            completionHandler?(nil)
            return
        }

        let payload = Data(bytes: pointer, count: Int(strlen(pointer)))
        nvpn_ios_extension_free_string(pointer)
        completionHandler?(payload)
    }

    fileprivate func applyDynamicSettings(jsonText: String) {
        guard let data = jsonText.data(using: .utf8),
              let payload = try? JSONDecoder().decode(PacketTunnelNetworkSettingsPayload.self, from: data)
        else {
            return
        }

        applyNetworkSettings(payload) { error in
            if let error {
                updateRecordedTunnelError(error.localizedDescription)
            }
        }
    }

    fileprivate func writePacket(_ packet: Data) {
        packetFlow.writePackets([packet], withProtocols: [protocolNumber(for: packet)])
    }

    private func readPacketsLoop() {
        guard packetLoopRunning else {
            return
        }

        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else {
                return
            }

            for packet in packets {
                packet.withUnsafeBytes { rawBuffer in
                    guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                        return
                    }
                    nvpn_ios_extension_push_packet(baseAddress, UInt(packet.count))
                }
            }

            self.readPacketsLoop()
        }
    }

    private func applyNetworkSettings(
        _ payload: PacketTunnelNetworkSettingsPayload,
        completion: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.1")
        settings.mtu = NSNumber(value: payload.mtu)

        if let ipv4 = try? buildIPv4Settings(payload) {
            settings.ipv4Settings = ipv4
        }

        if !payload.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: payload.dnsServers)
            dns.searchDomains = payload.searchDomains.isEmpty ? nil : payload.searchDomains
            settings.dnsSettings = dns
        }

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    private func buildIPv4Settings(
        _ payload: PacketTunnelNetworkSettingsPayload
    ) throws -> NEIPv4Settings {
        let local = try payload.localAddresses.map(parseIPv4CIDR)
        let addresses = local.map(\.address)
        let masks = local.map(\.mask)

        let settings = NEIPv4Settings(addresses: addresses, subnetMasks: masks)
        settings.includedRoutes = try payload.routes.map { route in
            let parsed = try parseIPv4CIDR(route)
            return NEIPv4Route(destinationAddress: parsed.address, subnetMask: parsed.mask)
        }
        return settings
    }
}
