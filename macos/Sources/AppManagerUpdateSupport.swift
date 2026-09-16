import AppKit
import Darwin
import Foundation
import SwiftUI


struct ReleaseManifest: Decodable {
    let tag: String
    let assets: [ReleaseAsset]

    enum CodingKeys: String, CodingKey {
        case tag
        case tagName = "tag_name"
        case assets
    }

    init(tag: String, assets: [ReleaseAsset]) {
        self.tag = tag
        self.assets = assets
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let tag = try container.decodeIfPresent(String.self, forKey: .tag) {
            self.tag = tag
        } else if let tag = try container.decodeIfPresent(String.self, forKey: .tagName) {
            self.tag = tag
        } else {
            throw DecodingError.keyNotFound(
                CodingKeys.tag,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Missing release tag")
            )
        }
        self.assets = try container.decode([ReleaseAsset].self, forKey: .assets)
    }

    func preferredMacAsset() -> ReleaseAsset? {
        assets.first { $0.name.hasSuffix("-macos-arm64.app.tar.gz") }
            ?? assets.first { $0.name.hasSuffix("-macos-arm64.dmg") }
            ?? assets.first { $0.name.hasSuffix("-macos-arm64.zip") }
    }
}

struct ReleaseAsset: Decodable {
    let name: String
    let path: String

    enum CodingKeys: String, CodingKey {
        case name
        case path
        case browserDownloadUrl = "browser_download_url"
    }

    init(name: String, path: String) {
        self.name = name
        self.path = path
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        if let path = try container.decodeIfPresent(String.self, forKey: .path) {
            self.path = path
        } else if let path = try container.decodeIfPresent(String.self, forKey: .browserDownloadUrl) {
            self.path = path
        } else {
            throw DecodingError.keyNotFound(
                CodingKeys.path,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Missing release asset URL")
            )
        }
    }
}

struct UpdateCheck {
    let manifest: ReleaseManifest
    let asset: ReleaseAsset?
    let assetUrl: URL?
    let isNewer: Bool
    let usesCoreDownload: Bool
    let source: String
    let verified: Bool
}

struct CoreUpdateResult: Decodable {
    let available: Bool
    let tag: String
    let asset: String
    let source: String
    let verified: Bool
    let url: String?
    let path: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case available
        case tag
        case asset
        case source
        case verified
        case url
        case path
        case error
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.available = try container.decodeIfPresent(Bool.self, forKey: .available) ?? false
        self.tag = try container.decodeIfPresent(String.self, forKey: .tag) ?? ""
        self.asset = try container.decodeIfPresent(String.self, forKey: .asset) ?? ""
        self.source = try container.decodeIfPresent(String.self, forKey: .source) ?? ""
        self.verified = try container.decodeIfPresent(Bool.self, forKey: .verified) ?? false
        self.url = try container.decodeIfPresent(String.self, forKey: .url)
        self.path = try container.decodeIfPresent(String.self, forKey: .path)
        self.error = try container.decodeIfPresent(String.self, forKey: .error)
    }
}

enum CopyValue {
    case pubkey
    case meshId
    case joinRequest
    case peerNpub
    case paymentRequest
    case cashuToken
    case lightningPreimage
    case paymentEnvelope
}

enum LaunchAgentError: LocalizedError {
    case missingExecutable

    var errorDescription: String? {
        switch self {
        case .missingExecutable:
            return "App executable was not found."
        }
    }
}

enum UpdateError: LocalizedError {
    case missingAppBundle
    case coreUpdaterFailed(String)
    case coreUpdaterOutputInvalid
    case missingDownloadedPath
    case unverifiedSource(String)

    var errorDescription: String? {
        switch self {
        case .missingAppBundle:
            return "Downloaded update did not contain Nostr VPN.app."
        case .coreUpdaterFailed(let message):
            return message.isEmpty ? "Update check failed." : message
        case .coreUpdaterOutputInvalid:
            return "Updater returned invalid output."
        case .missingDownloadedPath:
            return "Updater did not return a downloaded file."
        case .unverifiedSource(let source):
            return "Refusing to install unverified update from \(source)."
        }
    }
}

enum UpdateFetchError: LocalizedError {
    case httpStatus(code: Int)
    case malformedManifest

    var errorDescription: String? {
        switch self {
        case .httpStatus(let code):
            if code == 404 {
                return "No release manifest published yet."
            }
            return "Update server returned HTTP \(code)."
        case .malformedManifest:
            return "Update manifest is not valid JSON."
        }
    }
}

enum UpdateE2EError: LocalizedError {
    case noAsset

    var errorDescription: String? {
        switch self {
        case .noAsset:
            return "No macOS update asset was selected."
        }
    }
}

func runUpdateE2ECommandIfRequested() {
    let arguments = Set(CommandLine.arguments)
    guard arguments.contains("--nvpn-e2e-update-check") else {
        return
    }

    let result = runUpdateE2ECommand(install: arguments.contains("--nvpn-e2e-install-update"))
    writeUpdateE2EResult(result)
    exit((result["ok"] as? Bool) == true ? EXIT_SUCCESS : EXIT_FAILURE)
}

func runUpdateE2ECommand(install: Bool) -> [String: Any] {
    do {
        let (manifestUrl, data) = try loadConfiguredUpdateManifestBlocking()
        let manifest = try JSONDecoder().decode(ReleaseManifest.self, from: data)
        let currentVersion = ProcessInfo.processInfo.environment["NVPN_UPDATE_E2E_CURRENT_VERSION"]
            ?? Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
            ?? ""
        let asset = manifest.preferredMacAsset()
        let assetUrl = asset.flatMap { URL(string: $0.path, relativeTo: manifestUrl)?.absoluteURL }
        let isNewer = versionIsNewer(manifest.tag, than: currentVersion)
        var downloadedPath: String?
        var preparedAppPath: String?

        if install {
            guard let assetUrl else {
                throw UpdateE2EError.noAsset
            }
            let savedUrl = try downloadUpdateAssetBlocking(from: assetUrl)
            downloadedPath = savedUrl.path
            preparedAppPath = try prepareDownloadedUpdateForE2E(savedUrl)?.path
        }

        return [
            "ok": true,
            "platform": "macos",
            "available": isNewer,
            "tag": manifest.tag,
            "assetName": asset?.name ?? NSNull(),
            "assetUrl": assetUrl?.absoluteString ?? NSNull(),
            "downloadedPath": downloadedPath ?? NSNull(),
            "preparedAppPath": preparedAppPath ?? NSNull()
        ]
    } catch {
        return [
            "ok": false,
            "platform": "macos",
            "error": error.localizedDescription
        ]
    }
}

func configuredUpdateManifestUrls() -> [URL] {
    if let overrideUrl = ProcessInfo.processInfo.environment["NVPN_UPDATE_MANIFEST_URL"]
        .flatMap(URL.init(string:)) {
        return [overrideUrl]
    }
    return [defaultUpdateManifestUrl, githubUpdateManifestUrl]
}

func loadConfiguredUpdateManifestBlocking() throws -> (URL, Data) {
    var lastError: Error?
    for manifestUrl in configuredUpdateManifestUrls() {
        do {
            return (manifestUrl, try loadUpdateDataBlocking(from: manifestUrl))
        } catch {
            lastError = error
        }
    }
    throw lastError ?? UpdateFetchError.malformedManifest
}

func loadUpdateDataBlocking(from url: URL) throws -> Data {
    if url.isFileURL {
        return try Data(contentsOf: url)
    }
    let request = updateURLRequest(for: url)
    let semaphore = DispatchSemaphore(value: 0)
    var resultData: Data?
    var resultResponse: URLResponse?
    var resultError: Error?
    let session = URLSession(configuration: updateURLSessionConfiguration())
    let task = session.dataTask(with: request) { data, response, error in
        resultData = data
        resultResponse = response
        resultError = error
        semaphore.signal()
    }
    task.resume()
    if semaphore.wait(timeout: .now() + updateRequestTimeout) == .timedOut {
        task.cancel()
        throw URLError(.timedOut)
    }
    if let resultError {
        throw resultError
    }
    if let http = resultResponse as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
        throw UpdateFetchError.httpStatus(code: http.statusCode)
    }
    return resultData ?? Data()
}

func downloadUpdateAssetBlocking(from assetUrl: URL) throws -> URL {
    let downloadedUrl = FileManager.default.temporaryDirectory
        .appendingPathComponent("nostr-vpn-update-download-\(UUID().uuidString)")
    if assetUrl.isFileURL {
        try FileManager.default.copyItem(at: assetUrl, to: downloadedUrl)
    } else {
        let data = try Data(contentsOf: assetUrl)
        try data.write(to: downloadedUrl)
    }
    return try moveDownloadedUpdate(downloadedUrl, from: assetUrl)
}

func prepareDownloadedUpdateForE2E(_ archiveUrl: URL) throws -> URL? {
    guard archiveUrl.lastPathComponent.hasSuffix(".app.tar.gz") else {
        return nil
    }
    let unpackDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("NostrVpnUpdateE2E-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: unpackDir, withIntermediateDirectories: true)
    try runProcess("/usr/bin/tar", arguments: ["-xzf", archiveUrl.path, "-C", unpackDir.path])
    guard let appBundle = findAppBundle(in: unpackDir) else {
        throw UpdateError.missingAppBundle
    }
    return appBundle
}

func writeUpdateE2EResult(_ result: [String: Any]) {
    let data = (try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]))
        ?? Data("{}".utf8)
    if let path = ProcessInfo.processInfo.environment["NVPN_UPDATE_E2E_RESULT_PATH"], !path.isEmpty {
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url)
    } else if let text = String(data: data, encoding: .utf8) {
        print(text)
    }
}

func queryValue(_ name: String, in url: URL) -> String? {
    URLComponents(url: url, resolvingAgainstBaseURL: false)?
        .queryItems?
        .first(where: { $0.name == name })?
        .value?
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

func launchAgentPlist(executable: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>fi.siriusbusiness.nvpn</string>
        <key>ProgramArguments</key>
        <array>
            <string>\(xmlEscaped(executable))</string>
            <string>--hidden</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
    </plist>
    """
}

func xmlEscaped(_ value: String) -> String {
    value
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
}

func runLaunchctl(_ arguments: [String]) -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = arguments
    do {
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    } catch {
        return false
    }
}

func moveDownloadedUpdate(_ downloadedUrl: URL, from assetUrl: URL) throws -> URL {
    let fileName = assetUrl.lastPathComponent.isEmpty ? "nostr-vpn-update" : assetUrl.lastPathComponent
    let destination = FileManager.default.temporaryDirectory
        .appendingPathComponent("NostrVpnDownloads", isDirectory: true)
        .appendingPathComponent(fileName)
    try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
    if FileManager.default.fileExists(atPath: destination.path) {
        try FileManager.default.removeItem(at: destination)
    }
    try FileManager.default.moveItem(at: downloadedUrl, to: destination)
    return destination
}

@_silgen_name("nostr_vpn_update_check_with_config_json")
func nostrVpnUpdateCheckWithConfigJson(
    _ currentVersion: UnsafePointer<CChar>?,
    _ mode: UnsafePointer<CChar>?,
    _ source: UnsafePointer<CChar>?,
    _ configPath: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("nostr_vpn_update_download_with_config_json")
func nostrVpnUpdateDownloadWithConfigJson(
    _ currentVersion: UnsafePointer<CChar>?,
    _ mode: UnsafePointer<CChar>?,
    _ source: UnsafePointer<CChar>?,
    _ downloadDir: UnsafePointer<CChar>?,
    _ configPath: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("nostr_vpn_string_free")
func nostrVpnStringFree(_ value: UnsafeMutablePointer<CChar>?)

func runCoreUpdateCheck(currentVersion: String, configPath: String) async throws -> CoreUpdateResult {
    try await Task.detached {
        try runCoreUpdateCheckBlocking(currentVersion: currentVersion, configPath: configPath)
    }.value
}

func runCoreUpdateDownload(currentVersion: String, downloadDir: URL, configPath: String) async throws -> CoreUpdateResult {
    try await Task.detached {
        try runCoreUpdateDownloadBlocking(
            currentVersion: currentVersion,
            downloadDir: downloadDir,
            configPath: configPath
        )
    }.value
}

func runCoreUpdateCheckBlocking(currentVersion: String, configPath: String) throws -> CoreUpdateResult {
    let json = try currentVersion.withCString { current in
        try "app".withCString { mode in
            try "auto".withCString { source in
                try configPath.withCString { config in
                    try takeRustString(nostrVpnUpdateCheckWithConfigJson(current, mode, source, config))
                }
            }
        }
    }
    return try decodeCoreUpdateResult(json)
}

func runCoreUpdateDownloadBlocking(currentVersion: String, downloadDir: URL, configPath: String) throws -> CoreUpdateResult {
    let json = try currentVersion.withCString { current in
        try "app".withCString { mode in
            try "auto".withCString { source in
                try downloadDir.path.withCString { dir in
                    try configPath.withCString { config in
                        try takeRustString(nostrVpnUpdateDownloadWithConfigJson(current, mode, source, dir, config))
                    }
                }
            }
        }
    }
    return try decodeCoreUpdateResult(json)
}

func takeRustString(_ pointer: UnsafeMutablePointer<CChar>?) throws -> String {
    guard let pointer else {
        throw UpdateError.coreUpdaterOutputInvalid
    }
    defer { nostrVpnStringFree(pointer) }
    return String(cString: pointer)
}

func decodeCoreUpdateResult(_ json: String) throws -> CoreUpdateResult {
    let data = Data(json.utf8)
    let result = try JSONDecoder().decode(CoreUpdateResult.self, from: data)
    if let error = result.error, !error.isEmpty {
        throw UpdateError.coreUpdaterFailed(error)
    }
    return result
}

func loadUpdateData(from url: URL) async throws -> Data {
    if url.isFileURL {
        return try Data(contentsOf: url)
    }
    let session = URLSession(configuration: updateURLSessionConfiguration())
    let (data, response) = try await session.data(for: updateURLRequest(for: url))
    if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
        throw UpdateFetchError.httpStatus(code: http.statusCode)
    }
    return data
}

func updateURLSessionConfiguration() -> URLSessionConfiguration {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = updateRequestTimeout
    configuration.timeoutIntervalForResource = updateRequestTimeout
    return configuration
}

func updateURLRequest(for url: URL) -> URLRequest {
    var request = URLRequest(url: url, timeoutInterval: updateRequestTimeout)
    request.httpMethod = "GET"
    if url.host == "api.github.com" {
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue(updateUserAgent, forHTTPHeaderField: "User-Agent")
    }
    return request
}

func versionIsNewer(_ candidate: String, than current: String) -> Bool {
    let left = versionParts(candidate)
    let right = versionParts(current)
    for index in 0..<max(left.count, right.count) {
        let leftValue = index < left.count ? left[index] : 0
        let rightValue = index < right.count ? right[index] : 0
        if leftValue != rightValue {
            return leftValue > rightValue
        }
    }
    return false
}

func versionParts(_ value: String) -> [Int] {
    value
        .trimmingCharacters(in: CharacterSet(charactersIn: "vV "))
        .split { !$0.isNumber }
        .map { Int($0) ?? 0 }
}

func runProcess(_ executable: String, arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    try process.run()
    process.waitUntilExit()
    if process.terminationStatus != 0 {
        throw CocoaError(.executableLoad)
    }
}

func findAppBundle(in directory: URL) -> URL? {
    guard let enumerator = FileManager.default.enumerator(
        at: directory,
        includingPropertiesForKeys: [.isDirectoryKey],
        options: [.skipsHiddenFiles]
    ) else {
        return nil
    }
    for case let url as URL in enumerator where url.pathExtension == "app" {
        if url.lastPathComponent == "Nostr VPN.app" || url.lastPathComponent == "NostrVpnMac.app" {
            return url
        }
    }
    return nil
}

func updateInstallScript() throws -> URL {
    let script = FileManager.default.temporaryDirectory
        .appendingPathComponent("nostr-vpn-install-update-\(UUID().uuidString).sh")
    let contents = """
    #!/bin/sh
    set -eu
    current_app="$1"
    new_app="$2"
    sleep 1
    rm -rf "$current_app"
    ditto "$new_app" "$current_app"
    open "$current_app"
    """
    try contents.write(to: script, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
    return script
}

func settingsPatch(
    nodeName: String? = nil,
    endpoint: String? = nil,
    tunnelIp: String? = nil,
    listenPort: UInt16? = nil,
    relays: [String]? = nil,
    disabledRelays: [String]? = nil,
    nostrPubsubMode: String? = nil,
    nostrPubsubFanout: UInt32? = nil,
    nostrPubsubMaxHops: UInt8? = nil,
    nostrPubsubMaxEventBytes: UInt32? = nil,
    internetSource: String? = nil,
    exitNode: String? = nil,
    exitNodeLeakProtection: Bool? = nil,
    exitDnsMode: String? = nil,
    exitDnsDohProvider: String? = nil,
    exitDnsCustomDohUrl: String? = nil,
    exitDnsCustomDohBootstrapIps: String? = nil,
    exitDnsThroughExitServers: String? = nil,
    advertiseExitNode: Bool? = nil,
    advertisedRoutes: String? = nil,
    wireguardExitEnabled: Bool? = nil,
    wireguardExitInterface: String? = nil,
    wireguardExitAddress: String? = nil,
    wireguardExitPrivateKey: String? = nil,
    wireguardExitPeerPublicKey: String? = nil,
    wireguardExitPeerPresharedKey: String? = nil,
    wireguardExitEndpoint: String? = nil,
    wireguardExitAllowedIps: String? = nil,
    wireguardExitDns: String? = nil,
    wireguardExitMtu: UInt16? = nil,
    wireguardExitPersistentKeepaliveSecs: UInt16? = nil,
    wireguardExitConfig: String? = nil,
    walletFiatEnabled: Bool? = nil,
    walletFiatCurrency: String? = nil,
    paidExitEnabled: Bool? = nil,
    paidExitUpstream: String? = nil,
    paidExitPriceMsatPerGb: UInt64? = nil,
    paidExitAcceptedMints: String? = nil,
    paidExitMaxChannelCapacitySat: UInt64? = nil,
    paidExitChannelExpirySecs: UInt64? = nil,
    paidExitFreeProbeUnits: UInt64? = nil,
    paidExitGraceUnits: UInt64? = nil,
    paidExitCountryCode: String? = nil,
    paidExitNetworkClass: String? = nil,
    paidExitAsn: String? = nil,
    paidExitRatingFile: String? = nil,
    paidExitRatingRelays: [String]? = nil,
    paidExitTrustedRatingAuthors: [String]? = nil,
    paidExitRatingScope: String? = nil,
    fipsHostTunnelEnabled: Bool? = nil,
    connectToNonRosterFipsPeers: Bool? = nil,
    fipsNostrDiscoveryEnabled: Bool? = nil,
    fipsWebrtcEnabled: Bool? = nil,
    fipsBootstrapEnabled: Bool? = nil,
    fipsBootstrapPeers: [String: [String]]? = nil,
    fipsHostInboundTcpPorts: String? = nil,
    autoconnect: Bool? = nil,
    launchOnStartup: Bool? = nil,
    closeToTrayOnClose: Bool? = nil
) -> SettingsPatch {
    SettingsPatch(
        nodeName: nodeName,
        endpoint: endpoint,
        tunnelIp: tunnelIp,
        listenPort: listenPort,
        relays: relays,
        disabledRelays: disabledRelays,
        nostrPubsubMode: nostrPubsubMode,
        nostrPubsubFanout: nostrPubsubFanout,
        nostrPubsubMaxHops: nostrPubsubMaxHops,
        nostrPubsubMaxEventBytes: nostrPubsubMaxEventBytes,
        internetSource: internetSource,
        exitNode: exitNode,
        exitNodeLeakProtection: exitNodeLeakProtection,
        exitDnsMode: exitDnsMode,
        exitDnsDohProvider: exitDnsDohProvider,
        exitDnsCustomDohUrl: exitDnsCustomDohUrl,
        exitDnsCustomDohBootstrapIps: exitDnsCustomDohBootstrapIps,
        exitDnsThroughExitServers: exitDnsThroughExitServers,
        advertiseExitNode: advertiseExitNode,
        advertisedRoutes: advertisedRoutes,
        wireguardExitEnabled: wireguardExitEnabled,
        wireguardExitInterface: wireguardExitInterface,
        wireguardExitAddress: wireguardExitAddress,
        wireguardExitPrivateKey: wireguardExitPrivateKey,
        wireguardExitPeerPublicKey: wireguardExitPeerPublicKey,
        wireguardExitPeerPresharedKey: wireguardExitPeerPresharedKey,
        wireguardExitEndpoint: wireguardExitEndpoint,
        wireguardExitAllowedIps: wireguardExitAllowedIps,
        wireguardExitDns: wireguardExitDns,
        wireguardExitMtu: wireguardExitMtu,
        wireguardExitPersistentKeepaliveSecs: wireguardExitPersistentKeepaliveSecs,
        wireguardExitConfig: wireguardExitConfig,
        walletFiatEnabled: walletFiatEnabled,
        walletFiatCurrency: walletFiatCurrency,
        paidExitEnabled: paidExitEnabled,
        paidExitUpstream: paidExitUpstream,
        paidExitPriceMsatPerGb: paidExitPriceMsatPerGb,
        paidExitAcceptedMints: paidExitAcceptedMints,
        paidExitMaxChannelCapacitySat: paidExitMaxChannelCapacitySat,
        paidExitChannelExpirySecs: paidExitChannelExpirySecs,
        paidExitFreeProbeUnits: paidExitFreeProbeUnits,
        paidExitGraceUnits: paidExitGraceUnits,
        paidExitCountryCode: paidExitCountryCode,
        paidExitNetworkClass: paidExitNetworkClass,
        paidExitAsn: paidExitAsn,
        paidExitIpv4: nil,
        paidExitIpv6: nil,
        paidExitRatingFile: paidExitRatingFile,
        paidExitRatingRelays: paidExitRatingRelays,
        paidExitTrustedRatingAuthors: paidExitTrustedRatingAuthors,
        paidExitRatingScope: paidExitRatingScope,
        fipsHostTunnelEnabled: fipsHostTunnelEnabled,
        connectToNonRosterFipsPeers: connectToNonRosterFipsPeers,
        fipsNostrDiscoveryEnabled: fipsNostrDiscoveryEnabled,
        fipsWebrtcEnabled: fipsWebrtcEnabled,
        fipsBootstrapEnabled: fipsBootstrapEnabled,
        fipsBootstrapPeers: fipsBootstrapPeers,
        fipsHostInboundTcpPorts: fipsHostInboundTcpPorts,
        autoconnect: autoconnect,
        launchOnStartup: launchOnStartup,
        closeToTrayOnClose: closeToTrayOnClose
    )
}

func appManagerNormalizeNetworkIdInput(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    let compactScalars = trimmed.unicodeScalars.filter {
        !$0.properties.isWhitespace && $0 != "-"
    }
    let compact = String(String.UnicodeScalarView(compactScalars))
    if compact.isEmpty && trimmed.unicodeScalars.allSatisfy({ $0.properties.isWhitespace || $0 == "-" }) {
        return ""
    }
    return !compact.isEmpty && appManagerIsHexString(compact) ? compact.lowercased() : trimmed
}

func appManagerIsHexString(_ value: String) -> Bool {
    !value.isEmpty && value.unicodeScalars.allSatisfy { scalar in
        (48...57).contains(Int(scalar.value))
            || (65...70).contains(Int(scalar.value))
            || (97...102).contains(Int(scalar.value))
    }
}
