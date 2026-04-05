export type RelayState = 'up' | 'down' | 'checking' | 'unknown'
export type PeerState = 'local' | 'online' | 'pending' | 'offline' | 'checking' | 'unknown'
export type PresenceState = 'local' | 'present' | 'absent' | 'unknown'
export type HealthSeverity = 'info' | 'warning' | 'critical'
export type ProbeState = 'available' | 'unavailable' | 'unsupported' | 'error' | 'unknown'

export interface RelaySummary {
  up: number
  down: number
  checking: number
  unknown: number
}

export interface RelayView {
  url: string
  state: RelayState
  statusText: string
}

export interface ParticipantView {
  npub: string
  pubkeyHex: string
  isAdmin: boolean
  tunnelIp: string
  magicDnsAlias: string
  magicDnsName: string
  relayPathActive: boolean
  runtimeEndpoint: string
  txBytes: number
  rxBytes: number
  advertisedRoutes: string[]
  offersExitNode: boolean
  state: PeerState
  presenceState: PresenceState
  statusText: string
  lastSignalText: string
}

export interface RelayOperatorSessionView {
  requestId: string
  networkId: string
  requesterNpub: string
  requesterPubkeyHex: string
  targetNpub: string
  targetPubkeyHex: string
  requesterIngressEndpoint: string
  targetIngressEndpoint: string
  startedText: string
  expiresText: string
  bytesFromRequester: number
  bytesFromTarget: number
  totalForwardedBytes: number
}

export interface RelayOperatorView {
  relayNpub: string
  relayPubkeyHex: string
  advertisedEndpoint: string
  totalSessionsServed: number
  totalForwardedBytes: number
  currentForwardBps: number
  uniquePeerCount: number
  activeSessionCount: number
  updatedText: string
  activeSessions: RelayOperatorSessionView[]
}

export interface OutboundJoinRequestView {
  recipientNpub: string
  recipientPubkeyHex: string
  requestedAtText: string
}

export interface InboundJoinRequestView {
  requesterNpub: string
  requesterPubkeyHex: string
  requesterNodeName: string
  requestedAtText: string
}

export interface NetworkView {
  id: string
  name: string
  enabled: boolean
  networkId: string
  localIsAdmin: boolean
  adminNpubs: string[]
  joinRequestsEnabled: boolean
  inviteInviterNpub: string
  outboundJoinRequest: OutboundJoinRequestView | null
  inboundJoinRequests: InboundJoinRequestView[]
  onlineCount: number
  expectedCount: number
  participants: ParticipantView[]
}

export interface LanPeerView {
  npub: string
  nodeName: string
  endpoint: string
  networkName: string
  networkId: string
  invite: string
  lastSeenText: string
}

export interface HealthIssue {
  code: string
  severity: HealthSeverity
  summary: string
  detail: string
}

export interface NetworkSummary {
  defaultInterface?: string
  primaryIpv4?: string
  primaryIpv6?: string
  gatewayIpv4?: string
  gatewayIpv6?: string
  changedAt?: number
  captivePortal?: boolean
}

export interface ProbeStatus {
  state: ProbeState
  detail: string
}

export interface PortMappingStatus {
  upnp: ProbeStatus
  natPmp: ProbeStatus
  pcp: ProbeStatus
  activeProtocol?: string
  externalEndpoint?: string
  gateway?: string
  goodUntil?: number
}

export interface UiState {
  platform: string
  mobile: boolean
  vpnSessionControlSupported: boolean
  cliInstallSupported: boolean
  startupSettingsSupported: boolean
  trayBehaviorSupported: boolean
  runtimeStatusDetail: string
  daemonRunning: boolean
  sessionActive: boolean
  relayConnected: boolean
  cliInstalled: boolean
  serviceSupported: boolean
  serviceEnablementSupported: boolean
  serviceInstalled: boolean
  serviceDisabled: boolean
  serviceRunning: boolean
  serviceStatusDetail: string
  sessionStatus: string
  appVersion: string
  daemonBinaryVersion: string
  serviceBinaryVersion: string
  configPath: string
  ownNpub: string
  ownPubkeyHex: string
  networkId: string
  activeNetworkInvite: string
  nodeId: string
  nodeName: string
  selfMagicDnsName: string
  endpoint: string
  tunnelIp: string
  listenPort: number
  exitNode: string
  advertiseExitNode: boolean
  advertisedRoutes: string[]
  effectiveAdvertisedRoutes: string[]
  usePublicRelayFallback: boolean
  relayForOthers: boolean
  provideNatAssist: boolean
  relayOperatorRunning: boolean
  relayOperatorStatus: string
  natAssistRunning: boolean
  natAssistStatus: string
  magicDnsSuffix: string
  magicDnsStatus: string
  autoconnect: boolean
  lanPairingActive: boolean
  lanPairingRemainingSecs: number
  launchOnStartup: boolean
  closeToTrayOnClose: boolean
  connectedPeerCount: number
  expectedPeerCount: number
  meshReady: boolean
  health: HealthIssue[]
  network: NetworkSummary
  portMapping: PortMappingStatus
  networks: NetworkView[]
  relays: RelayView[]
  relaySummary: RelaySummary
  relayOperator: RelayOperatorView | null
  lanPeers: LanPeerView[]
}

export interface SettingsPatch {
  nodeName?: string
  endpoint?: string
  tunnelIp?: string
  listenPort?: number
  exitNode?: string
  advertiseExitNode?: boolean
  advertisedRoutes?: string
  usePublicRelayFallback?: boolean
  relayForOthers?: boolean
  provideNatAssist?: boolean
  magicDnsSuffix?: string
  autoconnect?: boolean
  launchOnStartup?: boolean
  closeToTrayOnClose?: boolean
}
