export type RelayState = 'up' | 'down' | 'checking' | 'unknown'
export type PeerState = 'local' | 'online' | 'offline' | 'checking' | 'unknown'

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
  state: PeerState
  statusText: string
  lastSignalText: string
}

export interface LanPeerView {
  npub: string
  nodeName: string
  endpoint: string
  lastSeenText: string
  configured: boolean
}

export interface UiState {
  sessionActive: boolean
  relayConnected: boolean
  sessionStatus: string
  configPath: string
  ownNpub: string
  ownPubkeyHex: string
  nodeId: string
  nodeName: string
  endpoint: string
  tunnelIp: string
  listenPort: number
  networkId: string
  effectiveNetworkId: string
  magicDnsSuffix: string
  magicDnsStatus: string
  autoDisconnectRelaysWhenMeshReady: boolean
  lanDiscoveryEnabled: boolean
  launchOnStartup: boolean
  closeToTrayOnClose: boolean
  connectedPeerCount: number
  expectedPeerCount: number
  meshReady: boolean
  participants: ParticipantView[]
  relays: RelayView[]
  relaySummary: RelaySummary
  lanPeers: LanPeerView[]
}

export interface SettingsPatch {
  nodeName?: string
  endpoint?: string
  tunnelIp?: string
  listenPort?: number
  networkId?: string
  magicDnsSuffix?: string
  autoDisconnectRelaysWhenMeshReady?: boolean
  lanDiscoveryEnabled?: boolean
  launchOnStartup?: boolean
  closeToTrayOnClose?: boolean
}
