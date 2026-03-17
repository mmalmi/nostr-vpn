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
  tunnelIp: string
  magicDnsAlias: string
  magicDnsName: string
  advertisedRoutes: string[]
  offersExitNode: boolean
  state: PeerState
  presenceState: PresenceState
  statusText: string
  lastSignalText: string
}

export interface NetworkView {
  id: string
  name: string
  enabled: boolean
  onlineCount: number
  expectedCount: number
  participants: ParticipantView[]
}

export interface LanPeerView {
  npub: string
  nodeName: string
  endpoint: string
  lastSeenText: string
  configured: boolean
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
  configPath: string
  ownNpub: string
  ownPubkeyHex: string
  networkId: string
  nodeId: string
  nodeName: string
  endpoint: string
  tunnelIp: string
  listenPort: number
  exitNode: string
  advertiseExitNode: boolean
  advertisedRoutes: string[]
  effectiveAdvertisedRoutes: string[]
  magicDnsSuffix: string
  magicDnsStatus: string
  autoDisconnectRelaysWhenMeshReady: boolean
  autoconnect: boolean
  lanDiscoveryEnabled: boolean
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
  magicDnsSuffix?: string
  autoDisconnectRelaysWhenMeshReady?: boolean
  autoconnect?: boolean
  lanDiscoveryEnabled?: boolean
  launchOnStartup?: boolean
  closeToTrayOnClose?: boolean
}
