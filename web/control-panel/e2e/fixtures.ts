import type { UiState } from '../src/lib/types';

export function state(vpnStatus: string, vpnEnabled = false): UiState {
  return {
    platform: 'linux', mobile: false, vpnControlSupported: true,
    cliInstallSupported: false, startupSettingsSupported: false, trayBehaviorSupported: false,
    runtimeStatusDetail: '', daemonRunning: true, vpnEnabled, vpnActive: vpnEnabled,
    cliInstalled: false, serviceSupported: true, serviceEnablementSupported: true,
    serviceInstalled: true, serviceDisabled: false, serviceRunning: true, serviceStatusDetail: '',
    vpnStatus, appVersion: 'test', daemonBinaryVersion: 'test', configPath: '',
    ownNpub: '', ownPubkeyHex: '', networkId: 'test', joinRequestQrCodeOrLink: '',
    nodeId: 'test', nodeName: 'Test device', selfMagicDnsName: 'test.nvpn',
    endpoint: '', tunnelIp: '', listenPort: 51820, relays: [], nostrPubsubMode: 'relay',
    nostrPubsubFanout: 4, nostrPubsubMaxHops: 2, nostrPubsubMaxEventBytes: 65536,
    exitNode: '', internetSource: 'direct', exitNodeLeakProtection: false,
    exitNodeActive: false, exitNodeBlocked: false, exitNodeStatusText: '',
    advertiseExitNode: false, advertisedRoutes: [], effectiveAdvertisedRoutes: [],
    wireguardExitEnabled: false, wireguardExitConfigured: false,
    wireguardExitEndpoint: '', wireguardExitConfig: '', fipsHostTunnelEnabled: false,
    connectToNonRosterFipsPeers: true, fipsNostrDiscoveryEnabled: true,
    fipsWebrtcEnabled: false, fipsBootstrapEnabled: false, fipsBootstrapPeers: {},
    fipsBootstrapPeerDefaults: {}, fipsHostInboundTcpPorts: '', magicDnsSuffix: 'nvpn',
    magicDnsStatus: '', autoconnect: false, launchOnStartup: false, closeToTrayOnClose: false,
    connectedPeerCount: 0, expectedPeerCount: 0, fipsConnectedPeerCount: 0,
    fipsRosterPeerCount: 0, nonFipsRosterPeerCount: 0, meshReady: false, health: [],
    network: {}, portMapping: { upnp: { state: '' }, natPmp: { state: '' }, pcp: { state: '' } },
    networks: [{
      id: 'test', name: 'Test network', enabled: true, networkId: 'test', localIsAdmin: true,
      adminNpubs: [], joinRequestsEnabled: false, joinRequestAdminNpub: '',
      inboundJoinRequests: [], onlineCount: 0, expectedCount: 0, participants: [],
    }],
  };
}
