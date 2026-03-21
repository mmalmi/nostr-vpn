import Foundation
import NetworkExtension

let vpnAppGroupIdentifier = "group.to.iris.nvpn"
let vpnPacketTunnelBundleIdentifier = "to.iris.nvpn.PacketTunnel"
let vpnSharedStartRequestKey = "nvpn.startRequest"
let vpnLastErrorKey = "nvpn.lastError"

struct NvpnStartRequest: Codable {
    let sessionName: String
    let configJson: String
    let localAddress: String
    let dnsServers: [String]
    let searchDomains: [String]
    let mtu: UInt16
}

struct NvpnBridgeStatus: Codable {
    let prepared: Bool
    let active: Bool
    let error: String?
    let stateJson: String?
}

struct PacketTunnelBridgeStatus: Codable {
    let active: Bool
    let error: String?
    let stateJson: String?
}

struct PacketTunnelNetworkSettingsPayload: Codable {
    let localAddresses: [String]
    let routes: [String]
    let dnsServers: [String]
    let searchDomains: [String]
    let mtu: UInt16
}

enum VpnSharedError: LocalizedError {
    case invalidUtf8Request
    case missingStoredRequest
    case invalidStoredRequest
    case invalidCIDR(String)
    case managerUnavailable
    case operationTimedOut(String)

    var errorDescription: String? {
        switch self {
        case .invalidUtf8Request:
            return "The VPN request was not valid UTF-8."
        case .missingStoredRequest:
            return "No stored VPN configuration was available for the packet tunnel."
        case .invalidStoredRequest:
            return "Stored VPN configuration could not be decoded."
        case .invalidCIDR(let value):
            return "Invalid IPv4 CIDR value: \(value)"
        case .managerUnavailable:
            return "The packet tunnel manager is unavailable."
        case .operationTimedOut(let operation):
            return "Timed out while waiting for \(operation)."
        }
    }
}

func sharedDefaults() -> UserDefaults? {
    UserDefaults(suiteName: vpnAppGroupIdentifier)
}

func decodeStartRequest(_ pointer: UnsafePointer<CChar>?) throws -> NvpnStartRequest {
    guard let pointer else {
        throw VpnSharedError.invalidUtf8Request
    }
    let text = String(cString: pointer)
    guard let data = text.data(using: .utf8) else {
        throw VpnSharedError.invalidUtf8Request
    }
    return try JSONDecoder().decode(NvpnStartRequest.self, from: data)
}

func storeStartRequest(_ request: NvpnStartRequest) throws {
    let encoded = try JSONEncoder().encode(request)
    sharedDefaults()?.set(encoded, forKey: vpnSharedStartRequestKey)
}

func loadStoredStartRequest() throws -> NvpnStartRequest {
    guard let data = sharedDefaults()?.data(forKey: vpnSharedStartRequestKey) else {
        throw VpnSharedError.missingStoredRequest
    }
    return try JSONDecoder().decode(NvpnStartRequest.self, from: data)
}

func loadStartRequest(from providerConfiguration: [String: Any]?) throws -> NvpnStartRequest {
    guard let providerConfiguration else {
        return try loadStoredStartRequest()
    }

    guard let sessionName = providerConfiguration["sessionName"] as? String,
          let configJson = providerConfiguration["configJson"] as? String,
          let localAddress = providerConfiguration["localAddress"] as? String
    else {
        throw VpnSharedError.invalidStoredRequest
    }

    let dnsServers = providerConfiguration["dnsServers"] as? [String] ?? []
    let searchDomains = providerConfiguration["searchDomains"] as? [String] ?? []
    let mtuValue =
        (providerConfiguration["mtu"] as? NSNumber)?.uint16Value
        ?? UInt16(providerConfiguration["mtu"] as? Int ?? 0)

    guard mtuValue > 0 else {
        throw VpnSharedError.invalidStoredRequest
    }

    return NvpnStartRequest(
        sessionName: sessionName,
        configJson: configJson,
        localAddress: localAddress,
        dnsServers: dnsServers,
        searchDomains: searchDomains,
        mtu: mtuValue
    )
}

func updateRecordedTunnelError(_ error: String?) {
    if let error, !error.isEmpty {
        sharedDefaults()?.set(error, forKey: vpnLastErrorKey)
    } else {
        sharedDefaults()?.removeObject(forKey: vpnLastErrorKey)
    }
}

func recordedTunnelError() -> String? {
    sharedDefaults()?.string(forKey: vpnLastErrorKey)
}

func makeStatusCString(
    prepared: Bool,
    active: Bool,
    error: String?,
    stateJson: String?
) -> UnsafeMutablePointer<CChar>? {
    makeJsonCString(
        NvpnBridgeStatus(prepared: prepared, active: active, error: error, stateJson: stateJson)
    )
}

func makeJsonCString<T: Encodable>(_ value: T) -> UnsafeMutablePointer<CChar>? {
    let encoder = JSONEncoder()
    guard let data = try? encoder.encode(value),
          let text = String(data: data, encoding: .utf8)
    else {
        return nil
    }
    return strdup(text)
}

func parseIPv4CIDR(_ value: String) throws -> (address: String, mask: String) {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        throw VpnSharedError.invalidCIDR(value)
    }

    let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
    guard let address = parts.first.map(String.init), !address.isEmpty else {
        throw VpnSharedError.invalidCIDR(value)
    }

    let prefixLength: Int
    if parts.count == 2 {
        guard let parsedPrefix = Int(parts[1]), (0...32).contains(parsedPrefix) else {
            throw VpnSharedError.invalidCIDR(value)
        }
        prefixLength = parsedPrefix
    } else {
        prefixLength = 32
    }

    return (address, ipv4Mask(prefixLength: prefixLength))
}

func ipv4Mask(prefixLength: Int) -> String {
    guard prefixLength > 0 else {
        return "0.0.0.0"
    }

    let maskValue = prefixLength == 32 ? UInt32.max : UInt32.max << (32 - UInt32(prefixLength))
    let octets = [
        String((maskValue >> 24) & 0xff),
        String((maskValue >> 16) & 0xff),
        String((maskValue >> 8) & 0xff),
        String(maskValue & 0xff),
    ]
    return octets.joined(separator: ".")
}

func protocolNumber(for packet: Data) -> NSNumber {
    guard let firstByte = packet.first else {
        return NSNumber(value: Int32(AF_INET))
    }
    let version = firstByte >> 4
    if version == 6 {
        return NSNumber(value: Int32(AF_INET6))
    }
    return NSNumber(value: Int32(AF_INET))
}

func tunnelConnectionIsActive(_ status: NEVPNStatus) -> Bool {
    switch status {
    case .invalid, .disconnected:
        return false
    case .connecting, .connected, .reasserting, .disconnecting:
        return true
    @unknown default:
        return false
    }
}

func tunnelConnectionSupportsProviderMessages(_ status: NEVPNStatus) -> Bool {
    switch status {
    case .connected:
        return true
    case .invalid, .disconnected, .connecting, .reasserting, .disconnecting:
        return false
    @unknown default:
        return false
    }
}
