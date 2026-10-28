import AppKit
import Darwin
import Foundation
import SwiftUI

extension AppManager {
    func copy(_ value: String, as copied: CopyValue? = nil, peerNpub: String? = nil) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
        copiedValue = copied
        copiedPeerNpub = peerNpub
        copyClearTask?.cancel()
        copyClearTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            await MainActor.run {
                guard !Task.isCancelled else {
                    return
                }
                self?.copiedValue = nil
                self?.copiedPeerNpub = nil
            }
        }
    }

    func share(_ value: String) {
        guard let contentView = NSApp.keyWindow?.contentView else {
            copy(value, as: .joinRequest)
            return
        }
        let item: Any = URL(string: value) ?? value
        let picker = NSSharingServicePicker(items: [item])
        picker.show(relativeTo: contentView.bounds, of: contentView, preferredEdge: .minY)
    }

    func handle(url: URL) {
        guard app != nil || fixtureMode else {
            // The core is still initializing; replay the link once it exists.
            pendingStartupUrls.append(url)
            return
        }
        let raw = url.absoluteString
        if url.scheme?.lowercased() == "nvpn", url.host?.lowercased() == "paid-exit" {
            paidExitChooserRequested = true
            guard openingPaidExitLink != raw else { return }
            pendingPaidExitLink = raw
            openPendingPaidExitLink()
            return
        }
        if raw.lowercased().hasPrefix("nvpn://join-request") {
            importJoinRequest(raw)
            return
        }

        #if DEBUG
        guard url.scheme == "nvpn", url.host == "debug" else {
            return
        }
        let action = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        switch action {
        case "tick":
            dispatch(.tick, status: "Refreshing")
        case "accept-join":
            let requestedNetwork = Self.debugQueryValue("networkId", aliases: ["network"], in: url)
            guard let network = state.networks.first(where: {
                requestedNetwork == nil || $0.id == requestedNetwork || $0.networkId == requestedNetwork
            }) else {
                return
            }
            let requester = Self.debugQueryValue(
                "requesterNpub",
                aliases: ["requester"],
                in: url
            ) ?? network.inboundJoinRequests.first?.requesterNpub
            guard let requester, !requester.isEmpty else {
                return
            }
            dispatch(
                .acceptJoinRequest(networkId: network.id, requesterNpub: requester),
                status: "Adding device",
                successStatus: "Device added"
            )
        default:
            break
        }
        #endif
    }

    func openPendingPaidExitLink() {
        guard !actionInFlight, let link = pendingPaidExitLink else { return }
        pendingPaidExitLink = nil
        openingPaidExitLink = link
        dispatch(.setManualPaidExitProvider(provider: link), status: "Opening provider") { [weak self] _ in
            self?.openingPaidExitLink = nil
        }
    }

    private static func debugQueryValue(_ name: String, aliases: [String], in url: URL) -> String? {
        let names = Set([name] + aliases)
        return URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { names.contains($0.name) })?
            .value?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func importJoinRequest(_ request: String) {
        let trimmed = request.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return
        }
        dispatch(
            .importJoinRequest(request: trimmed),
            status: "Adding device",
            successStatus: "Device added"
        )
    }

    func chooseWireGuardConfigFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText, .data, .item]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else {
                return
            }
            Task { @MainActor in
                self?.importWireGuardConfigFile(url)
            }
        }
    }

    func importWireGuardConfigFile(_ url: URL) {
        do {
            let didStartAccess = url.startAccessingSecurityScopedResource()
            defer {
                if didStartAccess {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            let config = try String(contentsOf: url, encoding: .utf8)
            guard !config.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                actionStatus = "Selected WireGuard config is empty."
                return
            }
            saveWireGuardExitConfig(config)
        } catch {
            actionStatus = error.localizedDescription
        }
    }

    func saveDeviceSettings(
        nodeName: String,
        endpoint: String,
        tunnelIp: String,
        listenPort: String
    ) {
        let parsedPort = UInt16(listenPort.trimmingCharacters(in: .whitespacesAndNewlines))
        dispatch(.updateSettings(patch: settingsPatch(
            nodeName: nodeName,
            endpoint: endpoint,
            tunnelIp: tunnelIp,
            listenPort: parsedPort
        )), status: "Saving device settings")
    }

    func saveFipsHostInboundTcpPorts(_ value: String) {
        dispatch(
            .updateSettings(patch: settingsPatch(fipsHostInboundTcpPorts: value)),
            status: "Saving FIPS option"
        )
    }

    func saveNostrPubsubSettings(
        mode: String,
        fanout: String,
        maxHops: String,
        maxEventBytes: String
    ) {
        let parsedFanout = UInt32(fanout.trimmingCharacters(in: .whitespacesAndNewlines))
        let parsedMaxHops = UInt8(maxHops.trimmingCharacters(in: .whitespacesAndNewlines))
        let parsedMaxEventBytes = UInt32(maxEventBytes.trimmingCharacters(in: .whitespacesAndNewlines))
        dispatch(
            .updateSettings(patch: settingsPatch(
                nostrPubsubMode: mode,
                nostrPubsubFanout: parsedFanout,
                nostrPubsubMaxHops: parsedMaxHops,
                nostrPubsubMaxEventBytes: parsedMaxEventBytes
            )),
            status: "Saving pubsub"
        )
    }

    @discardableResult
    func addRelay(_ value: String) -> Bool {
        guard let url = Self.normalizedRelayUrl(value) else {
            return false
        }
        var lists = relayLists()
        lists.disabled.removeAll { $0 == url }
        if !lists.enabled.contains(url) {
            lists.enabled.append(url)
        }
        saveRelayLists(lists)
        return true
    }

    func setRelay(_ url: String, enabled: Bool) {
        guard let url = Self.normalizedRelayUrl(url) else {
            return
        }
        var lists = relayLists()
        lists.enabled.removeAll { $0 == url }
        lists.disabled.removeAll { $0 == url }
        if enabled {
            lists.enabled.append(url)
        } else {
            lists.disabled.append(url)
        }
        saveRelayLists(lists)
    }

    func deleteRelay(_ url: String) {
        guard let url = Self.normalizedRelayUrl(url) else {
            return
        }
        var lists = relayLists()
        lists.enabled.removeAll { $0 == url }
        lists.disabled.removeAll { $0 == url }
        saveRelayLists(lists)
    }

    func relayLists() -> (enabled: [String], disabled: [String]) {
        let enabled = state.relays
            .filter(\.enabled)
            .compactMap { Self.normalizedRelayUrl($0.url) }
        let disabled = state.relays
            .filter { !$0.enabled }
            .compactMap { Self.normalizedRelayUrl($0.url) }
        return (
            enabled: Self.uniqueRelayList(enabled),
            disabled: Self.uniqueRelayList(disabled).filter { !enabled.contains($0) }
        )
    }

    func saveRelayLists(_ lists: (enabled: [String], disabled: [String])) {
        let enabled = Self.uniqueRelayList(lists.enabled)
        let disabled = Self.uniqueRelayList(lists.disabled).filter { !enabled.contains($0) }
        dispatch(
            .updateSettings(patch: settingsPatch(relays: enabled, disabledRelays: disabled)),
            status: "Saving relays"
        )
    }

    static func normalizedRelayUrl(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if trimmed.hasPrefix("ws://") || trimmed.hasPrefix("wss://") {
            return trimmed
        }
        return "wss://\(trimmed)"
    }

    static func uniqueRelayList(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
