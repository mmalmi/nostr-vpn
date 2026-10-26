export type HealthSeverity = 'info' | 'warning' | 'critical';

export type HealthIssue = {
  code: string;
  severity: HealthSeverity;
  summary: string;
  detail: string;
};

export type ProbeStatus = {
  state: string;
  detail?: string;
};

export type PortMappingStatus = {
  upnp: ProbeStatus;
  natPmp: ProbeStatus;
  pcp: ProbeStatus;
  activeProtocol?: string | null;
  externalEndpoint?: string | null;
  gateway?: string | null;
  goodUntil?: number | null;
};

export type NetworkSummary = {
  defaultInterface?: string | null;
  primaryIpv4?: string | null;
  primaryIpv6?: string | null;
  gatewayIpv4?: string | null;
  gatewayIpv6?: string | null;
  changedAt?: number | null;
  captivePortal?: boolean | null;
};

export type ParticipantView = {
  npub: string;
  pubkeyHex: string;
  alias: string;
  isAdmin: boolean;
  tunnelIp: string;
  magicDnsAlias: string;
  magicDnsName: string;
  txBytes: number;
  rxBytes: number;
  advertisedRoutes: string[];
  offersExitNode: boolean;
  reachable: boolean;
  fipsEndpointNpub: string;
  fipsEndpointHints: string[];
  fipsTransportAddr: string;
  fipsTransportType: string;
  fipsSrttMs?: number | null;
  fipsPacketsSent: number;
  fipsPacketsRecv: number;
  fipsBytesSent: number;
  fipsBytesRecv: number;
  state: string;
  meshState: string;
  statusText: string;
  lastSeenText: string;
};

export type OutboundJoinRequestView = {
  recipientNpub: string;
  recipientPubkeyHex: string;
  requestedAtText: string;
};

export type InboundJoinRequestView = {
  requesterNpub: string;
  requesterPubkeyHex: string;
  requesterNodeName: string;
  requestedAtText: string;
};

export type NetworkView = {
  id: string;
  name: string;
  enabled: boolean;
  networkId: string;
  localIsAdmin: boolean;
  adminNpubs: string[];
  joinRequestsEnabled: boolean;
  joinRequestAdminNpub: string;
  outboundJoinRequest?: OutboundJoinRequestView | null;
  inboundJoinRequests: InboundJoinRequestView[];
  onlineCount: number;
  expectedCount: number;
  participants: ParticipantView[];
};

export type UiState = {
  fileTransfers?: FileTransfer[];
  platform: string;
  mobile: boolean;
  vpnControlSupported: boolean;
  cliInstallSupported: boolean;
  startupSettingsSupported: boolean;
  trayBehaviorSupported: boolean;
  runtimeStatusDetail: string;
  daemonRunning: boolean;
  vpnEnabled: boolean;
  vpnActive: boolean;
  cliInstalled: boolean;
  serviceSupported: boolean;
  serviceEnablementSupported: boolean;
  serviceInstalled: boolean;
  serviceDisabled: boolean;
  serviceRunning: boolean;
  serviceStatusDetail: string;
  vpnStatus: string;
  appVersion: string;
  daemonBinaryVersion: string;
  configPath: string;
  ownNpub: string;
  ownPubkeyHex: string;
  networkId: string;
  joinRequestQrCodeOrLink: string;
  nodeId: string;
  nodeName: string;
  selfMagicDnsName: string;
  endpoint: string;
  tunnelIp: string;
  listenPort: number;
  relays: RelayView[];
  nostrPubsubMode: string;
  nostrPubsubFanout: number;
  nostrPubsubMaxHops: number;
  nostrPubsubMaxEventBytes: number;
  exitNode: string;
  internetSource: string;
  exitNodeLeakProtection: boolean;
  exitNodeActive: boolean;
  exitNodeBlocked: boolean;
  exitNodeStatusText: string;
  advertiseExitNode: boolean;
  advertisedRoutes: string[];
  effectiveAdvertisedRoutes: string[];
  wireguardExitEnabled: boolean;
  wireguardExitConfigured: boolean;
  wireguardExitEndpoint: string;
  wireguardExitConfig: string;
  fipsHostTunnelEnabled: boolean;
  connectToNonRosterFipsPeers: boolean;
  fipsNostrDiscoveryEnabled: boolean;
  fipsWebrtcEnabled: boolean;
  fipsBootstrapEnabled: boolean;
  fipsBootstrapPeers: Record<string, string[]>;
  fipsBootstrapPeerDefaults: Record<string, string[]>;
  fipsHostInboundTcpPorts: string;
  magicDnsSuffix: string;
  magicDnsStatus: string;
  autoconnect: boolean;
  launchOnStartup: boolean;
  closeToTrayOnClose: boolean;
  connectedPeerCount: number;
  expectedPeerCount: number;
  fipsConnectedPeerCount: number;
  fipsRosterPeerCount: number;
  nonFipsRosterPeerCount: number;
  meshReady: boolean;
  health: HealthIssue[];
  network: NetworkSummary;
  portMapping: PortMappingStatus;
  networks: NetworkView[];
};

export type FileTransfer = {
  id: string;
  peerNpub: string;
  peerName: string;
  isSender: boolean;
  files: { name: string; sizeBytes: number; localPath?: string | null }[];
  status: string;
  transferredBytes: number;
  totalBytes: number;
  error?: string | null;
};

export type RelayView = {
  url: string;
  status: string;
};

export type QrMatrix = {
  width: number;
  cells: boolean[];
};
