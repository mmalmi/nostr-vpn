import AppKit
import Darwin
import Foundation
import SwiftUI

extension AppManager {
    func saveWireGuardExitConfig(_ config: String) {
        dispatch(.updateSettings(patch: settingsPatch(wireguardExitConfig: config)), status: "Saving WireGuard")
    }

    func saveExitDnsSettings(
        mode: String,
        provider: String,
        customUrl: String,
        bootstrapIps: String,
        throughExitServers: String
    ) {
        dispatch(.updateSettings(patch: settingsPatch(
            exitDnsMode: mode,
            exitDnsDohProvider: provider,
            exitDnsCustomDohUrl: customUrl,
            exitDnsCustomDohBootstrapIps: bootstrapIps,
            exitDnsThroughExitServers: throughExitServers
        )), status: "Saving Exit DNS")
    }

    func saveWireGuardExitSettings(
        interface: String,
        address: String,
        privateKey: String,
        peerPublicKey: String,
        peerPresharedKey: String,
        endpoint: String,
        allowedIps: String,
        dns: String,
        mtu: String,
        keepalive: String
    ) {
        dispatch(.updateSettings(patch: settingsPatch(
            wireguardExitInterface: interface,
            wireguardExitAddress: address,
            wireguardExitPrivateKey: privateKey,
            wireguardExitPeerPublicKey: peerPublicKey,
            wireguardExitPeerPresharedKey: peerPresharedKey,
            wireguardExitEndpoint: endpoint,
            wireguardExitAllowedIps: allowedIps,
            wireguardExitDns: dns,
            wireguardExitMtu: UInt16(mtu.trimmingCharacters(in: .whitespacesAndNewlines)),
            wireguardExitPersistentKeepaliveSecs: UInt16(keepalive.trimmingCharacters(in: .whitespacesAndNewlines))
        )), status: "Saving WireGuard")
    }

    func setAutoconnect(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(autoconnect: enabled)), status: "Saving VPN option")
    }

    func setFipsHostTunnel(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(fipsHostTunnelEnabled: enabled)), status: "Saving FIPS option")
    }

    func setConnectToNonRosterFipsPeers(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(connectToNonRosterFipsPeers: enabled)), status: "Saving FIPS option")
    }

    func setFipsNostrDiscoveryEnabled(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(fipsNostrDiscoveryEnabled: enabled)), status: "Saving FIPS option")
    }

    func setFipsWebrtcEnabled(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(fipsWebrtcEnabled: enabled)), status: "Saving FIPS option")
    }

    func setFipsBootstrapEnabled(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(fipsBootstrapEnabled: enabled)), status: "Saving FIPS option")
    }

    func setLaunchOnStartup(_ enabled: Bool) {
        do {
            try configureLaunchAgent(enabled: enabled, loadCurrentSession: true)
            dispatch(.updateSettings(patch: settingsPatch(launchOnStartup: enabled)), status: "Saving startup option")
        } catch {
            actionStatus = error.localizedDescription
        }
    }

    func setCloseToTray(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(closeToTrayOnClose: enabled)), status: "Saving menu bar option")
    }

    func setAdvertisedRoutes(_ routes: String) {
        dispatch(.updateSettings(patch: settingsPatch(advertisedRoutes: routes)), status: "Saving routes")
    }

    func selectDirectExit() {
        dispatch(
            .updateSettings(patch: settingsPatch(internetSource: "direct")),
            status: "Saving internet source"
        )
    }

    func selectWireGuardUpstreamExit() {
        dispatch(
            .updateSettings(patch: settingsPatch(internetSource: "wireguard")),
            status: "Saving internet source"
        )
    }

    func selectPeerExit(_ npub: String) {
        dispatch(
            .updateSettings(patch: settingsPatch(internetSource: "private_vpn", exitNode: npub)),
            status: "Saving internet source"
        )
    }

    func selectPaidAutomaticExit() {
        dispatch(
            .updateSettings(patch: settingsPatch(internetSource: "paid_automatic")),
            status: "Selecting paid internet"
        )
    }

    func selectPaidManualExit() {
        paidExitChooserRequested = true
    }

    func setWalletFiatEnabled(_ enabled: Bool) {
        dispatch(
            .updateSettings(patch: settingsPatch(walletFiatEnabled: enabled)),
            status: "Saving wallet display"
        )
    }

    func setWalletFiatCurrency(_ currency: String) {
        dispatch(
            .updateSettings(patch: settingsPatch(walletFiatCurrency: currency)),
            status: "Saving wallet currency"
        )
    }

    func setExitNodeLeakProtection(_ enabled: Bool) {
        dispatch(.updateSettings(patch: settingsPatch(exitNodeLeakProtection: enabled)), status: "Saving exit protection")
    }

    func addParticipant(
        networkId: String,
        npub: String,
        alias: String? = nil,
        completion: ((Bool) -> Void)? = nil
    ) {
        let trimmed = npub.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            let trimmedAlias = alias?.trimmingCharacters(in: .whitespacesAndNewlines)
            dispatch(
                .addParticipant(networkId: networkId, npub: trimmed, alias: trimmedAlias?.isEmpty == false ? trimmedAlias : nil),
                status: "Adding participant",
                completion: completion
            )
        } else {
            completion?(false)
        }
    }

    func manualAddNetwork(
        adminNpub: String,
        meshNetworkId: String,
        completion: ((Bool) -> Void)? = nil
    ) {
        dispatch(
            .manualAddNetwork(adminNpub: adminNpub, meshNetworkId: meshNetworkId),
            status: "Adding network",
            completion: completion
        )
    }

    func renameNetwork(networkId: String, name: String) {
        dispatch(.renameNetwork(networkId: networkId, name: name), status: "Renaming network")
    }

    func setNetworkMeshId(networkId: String, meshId: String) {
        dispatch(.setNetworkMeshId(networkId: networkId, meshId: meshId), status: "Saving mesh ID")
    }

    func setNetworkEnabled(networkId: String, enabled: Bool) {
        dispatch(.setNetworkEnabled(networkId: networkId, enabled: enabled), status: enabled ? "Activating network" : "Disabling network")
    }

    func setParticipantAlias(npub: String, alias: String) {
        dispatch(.setParticipantAlias(npub: npub, alias: alias), status: "Saving alias")
    }

    func setParticipantEndpointHints(npub: String, endpointHints: [String]) {
        dispatch(
            .setParticipantEndpointHints(npub: npub, endpointHints: endpointHints),
            status: "Saving address hints"
        )
    }

    func toggleAdmin(networkId: String, participant: NativeParticipantState) {
        if participant.isAdmin {
            dispatch(.removeAdmin(networkId: networkId, npub: participant.npub), status: "Removing admin")
        } else {
            dispatch(.addAdmin(networkId: networkId, npub: participant.npub), status: "Adding admin")
        }
    }

    func removeParticipant(networkId: String, npub: String) {
        dispatch(.removeParticipant(networkId: networkId, npub: npub), status: "Removing device")
    }

    func addNetwork(_ name: String, completion: ((Bool) -> Void)? = nil) {
        dispatch(
            .addNetwork(name: name.trimmingCharacters(in: .whitespacesAndNewlines)),
            status: "Adding network",
            completion: completion
        )
    }

    func removeNetwork(_ networkId: String) {
        dispatch(.removeNetwork(networkId: networkId), status: "Deleting network")
    }

    func installCli() {
        dispatch(.installCli, status: "Installing CLI")
    }

    func uninstallCli() {
        dispatch(.uninstallCli, status: "Uninstalling CLI")
    }

    func installService() {
        let installing = serviceUpdateRecommended ? "Updating service" : state.serviceInstalled ? "Reinstalling service" : "Installing service"
        let installed = serviceUpdateRecommended ? "Service updated" : state.serviceInstalled ? "Service reinstalled" : "Service installed"
        dispatch(.installSystemService, status: installing, successStatus: installed, settleService: true)
    }

    func enableService() {
        dispatch(.enableSystemService, status: "Enabling service", successStatus: "Service enabled", settleService: true)
    }

    func disableService() {
        dispatch(.disableSystemService, status: "Disabling service", successStatus: "Service disabled", settleService: true)
    }

    func uninstallService() {
        dispatch(.uninstallSystemService, status: "Uninstalling service", successStatus: "Service uninstalled", settleService: true)
    }

}
