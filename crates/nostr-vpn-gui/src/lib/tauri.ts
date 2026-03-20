import { invoke } from '@tauri-apps/api/core'
import type { NetworkView, SettingsPatch, UiState } from './types'

declare const __APP_VERSION__: string

const isTauriRuntime = () =>
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

const composeMagicDnsName = (alias: string, suffix: string) =>
  suffix.trim().length > 0 ? `${alias}.${suffix}` : alias

const normalizeAlias = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')

const NETWORK_INVITE_PREFIX = 'nvpn://invite/'
const APP_VERSION = __APP_VERSION__

type MockNetworkInvite = {
  v: number
  networkName: string
  networkId: string
  inviterNpub: string
  relays: string[]
}

const pseudoHexFromNpub = (npub: string) => {
  const seed = npub
    .replace(/^npub1/i, '')
    .replace(/[^a-z0-9]/gi, '')
    .toLowerCase()
  return (seed + 'a'.repeat(64)).slice(0, 64)
}

const encodeInvitePayload = (payload: MockNetworkInvite) => {
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return `${NETWORK_INVITE_PREFIX}${btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')}`
}

const decodeInvitePayload = (invite: string): MockNetworkInvite => {
  const trimmed = invite.trim()
  if (!trimmed) {
    throw new Error('Invite code is empty')
  }

  const payload = trimmed.startsWith('{')
    ? trimmed
    : trimmed.startsWith(NETWORK_INVITE_PREFIX)
      ? trimmed.slice(NETWORK_INVITE_PREFIX.length)
      : trimmed

  if (payload.startsWith('{')) {
    return JSON.parse(payload) as MockNetworkInvite
  }

  const padded = payload + '='.repeat((4 - (payload.length % 4 || 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as MockNetworkInvite
}

const countExpectedPeers = (network: NetworkView) =>
  network.enabled
    ? network.participants.filter((participant) => participant.state !== 'local').length
    : 0

const countOnlinePeers = (network: NetworkView) =>
  network.enabled
    ? network.participants.filter((participant) => participant.state === 'online').length
    : 0

const countExpectedDevices = (network: NetworkView) =>
  network.enabled ? countExpectedPeers(network) + 1 : 0

const countOnlineDevices = (network: NetworkView, sessionActive: boolean) =>
  network.enabled ? countOnlinePeers(network) + Number(sessionActive) : 0

const computeMockEffectiveAdvertisedRoutes = () => {
  const effective = [...mockState.advertisedRoutes]
  if (mockState.advertiseExitNode) {
    for (const route of ['0.0.0.0/0', '::/0']) {
      if (!effective.includes(route)) {
        effective.push(route)
      }
    }
  }
  return effective
}

const mockState: UiState = {
  daemonRunning: false,
  sessionActive: false,
  relayConnected: false,
  cliInstalled: false,
  serviceSupported: true,
  serviceEnablementSupported: true,
  serviceInstalled: false,
  serviceDisabled: false,
  serviceRunning: false,
  serviceStatusDetail: 'Background service is not installed',
  sessionStatus: 'Install background service to turn VPN on from the app',
  appVersion: APP_VERSION,
  configPath: '~/.config/nvpn/config.toml',
  ownNpub: 'npub1akgu9lxldpt32lnjf97k005a4kgasewmvsrmkpzqeff39ssev0ssd6t3u',
  ownPubkeyHex: 'f'.repeat(64),
  networkId: 'nostr-vpn:mockmesh',
  activeNetworkInvite: '',
  nodeId: 'mock-node',
  nodeName: 'nostr-vpn-node',
  endpoint: '192.168.1.4:51820',
  tunnelIp: '10.44.0.1/32',
  listenPort: 51820,
  exitNode: '',
  advertiseExitNode: false,
  advertisedRoutes: [],
  effectiveAdvertisedRoutes: [],
  magicDnsSuffix: 'nvpn',
  magicDnsStatus: 'System DNS active for .nvpn via 127.0.0.1:1053',
  autoDisconnectRelaysWhenMeshReady: true,
  autoconnect: true,
  lanDiscoveryEnabled: true,
  launchOnStartup: true,
  closeToTrayOnClose: true,
  connectedPeerCount: 0,
  expectedPeerCount: 0,
  meshReady: false,
  health: [],
  network: {
    defaultInterface: 'en0',
    primaryIpv4: '192.168.1.4',
    primaryIpv6: 'fd00::4',
    gatewayIpv4: '192.168.1.1',
    gatewayIpv6: 'fd00::1',
    captivePortal: false,
  },
  portMapping: {
    upnp: { state: 'unknown', detail: 'not checked' },
    natPmp: { state: 'unknown', detail: 'not checked' },
    pcp: { state: 'unknown', detail: 'not checked' },
  },
  networks: [
    {
      id: 'network-1',
      name: 'Network 1',
      enabled: true,
      networkId: 'nostr-vpn:mockmesh',
      onlineCount: 0,
      expectedCount: 0,
      participants: [],
    },
  ],
  relays: [
    { url: 'wss://temp.iris.to', state: 'unknown', statusText: 'not checked' },
    { url: 'wss://relay.damus.io', state: 'unknown', statusText: 'not checked' },
    { url: 'wss://nos.lol', state: 'unknown', statusText: 'not checked' },
  ],
  relaySummary: { up: 0, down: 0, checking: 0, unknown: 3 },
  lanPeers: [
    {
      npub: 'npub1x8teht3pj2zhq6e4l6s5zh2fcn0vzrp3d8zjls74g7zq5qemk3dq3wlp5m',
      nodeName: 'home-server',
      endpoint: '192.168.1.20:51820',
      lastSeenText: '2s ago',
      configured: false,
    },
  ],
}

const cloneMockState = () => structuredClone(mockState)

const mockActiveNetwork = () =>
  mockState.networks.find((network) => network.enabled) ?? mockState.networks[0]

const buildMockActiveNetworkInvite = () => {
  const activeNetwork = mockActiveNetwork()
  if (!activeNetwork) {
    return ''
  }

  return encodeInvitePayload({
    v: 1,
    networkName: activeNetwork.name,
    networkId: activeNetwork.networkId,
    inviterNpub: mockState.ownNpub,
    relays: mockState.relays.map((relay) => relay.url),
  })
}

const activateMockNetwork = (networkId: string) => {
  mockState.networks = mockState.networks.map((network) => ({
    ...network,
    enabled: network.id === networkId,
  }))
}

const mockRequiresServiceSetup = () =>
  mockState.serviceSupported && !mockState.serviceInstalled && !mockState.daemonRunning

const updateMockRelaySummary = () => {
  mockState.relaySummary = {
    up: mockState.relays.filter((relay) => relay.state === 'up').length,
    down: mockState.relays.filter((relay) => relay.state === 'down').length,
    checking: mockState.relays.filter((relay) => relay.state === 'checking').length,
    unknown: mockState.relays.filter((relay) => relay.state === 'unknown').length,
  }
}

const recomputeMockConnectivity = () => {
  mockState.networks = mockState.networks.map((network) => ({
    ...network,
    onlineCount: countOnlineDevices(network, mockState.sessionActive),
    expectedCount: countExpectedDevices(network),
  }))

  const activeNetwork = mockActiveNetwork()
  mockState.networkId = activeNetwork?.networkId || mockState.networkId
  mockState.activeNetworkInvite = buildMockActiveNetworkInvite()
  mockState.connectedPeerCount = activeNetwork ? countOnlinePeers(activeNetwork) : 0
  mockState.expectedPeerCount = activeNetwork ? countExpectedPeers(activeNetwork) : 0
  mockState.meshReady =
    mockState.expectedPeerCount > 0 &&
    mockState.connectedPeerCount >= mockState.expectedPeerCount
}

const refreshMockLanConfigured = () => {
  const configured = new Set(
    mockState.networks.flatMap((network) =>
      network.participants.map((participant) => participant.npub),
    ),
  )

  mockState.lanPeers = mockState.lanPeers.map((peer) => ({
    ...peer,
    configured: configured.has(peer.npub),
  }))
}

const asResult = async () => {
  recomputeMockConnectivity()
  refreshMockLanConfigured()
  mockState.effectiveAdvertisedRoutes = computeMockEffectiveAdvertisedRoutes()
  return cloneMockState()
}

export const tick = () =>
  isTauriRuntime() ? invoke<UiState>('tick') : asResult()

export const connectSession = () =>
  isTauriRuntime()
    ? invoke<UiState>('connect_session')
    : (() => {
        if (mockRequiresServiceSetup()) {
          throw new Error('Install background service to turn VPN on from the app')
        }
        mockState.sessionActive = true
        mockState.daemonRunning = true
        mockState.serviceDisabled = false
        mockState.serviceRunning = mockState.serviceInstalled
        mockState.relayConnected = true
        mockState.sessionStatus = 'Daemon running'
        mockState.relays = mockState.relays.map((relay) => ({
          ...relay,
          state: 'up',
          statusText: 'connected (mock)',
        }))
        mockState.networks = mockState.networks.map((network) => ({
          ...network,
          participants: network.participants.map((participant) => ({
            ...participant,
            state: participant.state === 'local' ? 'local' : 'online',
            presenceState: participant.state === 'local' ? 'local' : 'present',
            statusText:
              participant.state === 'local'
                ? 'local'
                : 'online (handshake 0s ago)',
            lastSignalText:
              participant.state === 'local' ? 'self' : 'nostr seen 0s ago',
          })),
        }))
        updateMockRelaySummary()
        return asResult()
      })()

export const disconnectSession = () =>
  isTauriRuntime()
    ? invoke<UiState>('disconnect_session')
    : (() => {
        mockState.sessionActive = false
        mockState.daemonRunning = true
        mockState.serviceDisabled = false
        mockState.serviceRunning = mockState.serviceInstalled
        mockState.relayConnected = false
        mockState.sessionStatus = 'Paused'
        mockState.relays = mockState.relays.map((relay) => ({
          ...relay,
          state: 'unknown',
          statusText: 'not checked',
        }))
        mockState.networks = mockState.networks.map((network) => ({
          ...network,
          participants: network.participants.map((participant) => ({
            ...participant,
            state: participant.state === 'local' ? 'local' : 'unknown',
            presenceState: participant.state === 'local' ? 'local' : 'unknown',
            statusText: participant.state === 'local' ? 'local' : 'unknown',
            lastSignalText: participant.state === 'local' ? 'self' : 'nostr unseen',
          })),
        }))
        updateMockRelaySummary()
        return asResult()
      })()

export const installCli = () =>
  isTauriRuntime()
    ? invoke<UiState>('install_cli')
    : asResult()

export const uninstallCli = () =>
  isTauriRuntime()
    ? invoke<UiState>('uninstall_cli')
    : asResult()

export const installSystemService = () =>
  isTauriRuntime()
    ? invoke<UiState>('install_system_service')
    : (() => {
        mockState.serviceInstalled = true
        mockState.serviceDisabled = false
        mockState.serviceRunning = true
        mockState.daemonRunning = true
        mockState.serviceStatusDetail = 'Background service running (mock)'
        mockState.sessionStatus = 'Daemon running'
        return asResult()
      })()

export const enableSystemService = () =>
  isTauriRuntime()
    ? invoke<UiState>('enable_system_service')
    : (() => {
        mockState.serviceInstalled = true
        mockState.serviceDisabled = false
        mockState.serviceRunning = true
        mockState.daemonRunning = true
        mockState.serviceStatusDetail = 'Background service running (mock)'
        mockState.sessionStatus = 'Daemon running'
        return asResult()
      })()

export const disableSystemService = () =>
  isTauriRuntime()
    ? invoke<UiState>('disable_system_service')
    : (() => {
        mockState.serviceInstalled = true
        mockState.serviceDisabled = true
        mockState.serviceRunning = false
        mockState.sessionActive = false
        mockState.daemonRunning = false
        mockState.relayConnected = false
        mockState.serviceStatusDetail = 'Background service is installed but disabled in launchd'
        mockState.sessionStatus = 'Background service is disabled in launchd'
        return asResult()
      })()

export const uninstallSystemService = () =>
  isTauriRuntime()
    ? invoke<UiState>('uninstall_system_service')
    : (() => {
        mockState.serviceInstalled = false
        mockState.serviceDisabled = false
        mockState.serviceRunning = false
        mockState.sessionActive = false
        mockState.daemonRunning = false
        mockState.relayConnected = false
        mockState.serviceStatusDetail = 'Background service is not installed'
        mockState.sessionStatus = 'Install background service to turn VPN on from the app'
        return asResult()
      })()

export const addNetwork = (name: string) =>
  isTauriRuntime()
    ? invoke<UiState>('add_network', { name })
    : (() => {
        const index = mockState.networks.length + 1
        const normalized = name.trim() || `Network ${index}`
        let id = `network-${index}`
        let suffix = 2
        while (mockState.networks.some((network) => network.id === id)) {
          id = `network-${index}-${suffix}`
          suffix += 1
        }
        mockState.networks.push({
          id,
          name: normalized,
          enabled: false,
          networkId: `nostr-vpn:${id}`,
          onlineCount: 0,
          expectedCount: 0,
          participants: [],
        })
        return asResult()
      })()

export const renameNetwork = (networkId: string, name: string) =>
  isTauriRuntime()
    ? invoke<UiState>('rename_network', { networkId, name })
    : (() => {
        mockState.networks = mockState.networks.map((network) =>
          network.id === networkId
            ? { ...network, name: name.trim() || network.name }
            : network,
        )
        return asResult()
      })()

export const setNetworkMeshId = (networkId: string, meshId: string) =>
  isTauriRuntime()
    ? invoke<UiState>('set_network_mesh_id', { networkId, meshId })
    : (() => {
        mockState.networks = mockState.networks.map((network) =>
          network.id === networkId
            ? { ...network, networkId: meshId.trim() || network.networkId }
            : network,
        )
        return asResult()
      })()

export const removeNetwork = (networkId: string) =>
  isTauriRuntime()
    ? invoke<UiState>('remove_network', { networkId })
    : (() => {
        if (mockState.networks.length <= 1) {
          return asResult()
        }
        mockState.networks = mockState.networks.filter(
          (network) => network.id !== networkId,
        )
        if (!mockState.networks.some((network) => network.enabled) && mockState.networks[0]) {
          activateMockNetwork(mockState.networks[0].id)
        }
        return asResult()
      })()

export const setNetworkEnabled = (networkId: string, enabled: boolean) =>
  isTauriRuntime()
    ? invoke<UiState>('set_network_enabled', { networkId, enabled })
    : (() => {
        if (enabled) {
          activateMockNetwork(networkId)
        }
        return asResult()
      })()

const upsertMockParticipant = (networkId: string, npub: string, alias = '') => {
  const target = mockState.networks.find((network) => network.id === networkId)
  if (!target || target.participants.some((participant) => participant.npub === npub)) {
    return
  }

  const pubkeyHex = pseudoHexFromNpub(npub)
  const aliasCandidate = normalizeAlias(alias)
  const magicDnsAlias =
    aliasCandidate.length > 0 ? aliasCandidate : `peer-${pubkeyHex.slice(0, 10)}`

  target.participants.push({
    npub,
    pubkeyHex,
    tunnelIp: '10.44.0.2/32',
    magicDnsAlias,
    magicDnsName: composeMagicDnsName(magicDnsAlias, mockState.magicDnsSuffix),
    advertisedRoutes: [],
    offersExitNode: false,
    state: 'unknown',
    presenceState: 'absent',
    statusText: 'no signal yet',
    lastSignalText: 'nostr unseen',
  })
}

export const addParticipant = (networkId: string, npub: string, alias = '') =>
  isTauriRuntime()
    ? invoke<UiState>('add_participant', { networkId, npub, alias: alias.trim() || null })
    : (() => {
        upsertMockParticipant(networkId, npub, alias)
        return asResult()
      })()

export const importNetworkInvite = (invite: string) =>
  isTauriRuntime()
    ? invoke<UiState>('import_network_invite', { invite })
    : (() => {
        const parsed = decodeInvitePayload(invite)
        const activeNetwork = mockActiveNetwork()
        if (!activeNetwork) {
          return asResult()
        }

        if (
          parsed.networkName.trim() &&
          (activeNetwork.participants.length === 0 || /^Network \d+/.test(activeNetwork.name))
        ) {
          activeNetwork.name = parsed.networkName.trim()
        }
        if (parsed.networkId.trim()) {
          activeNetwork.networkId = parsed.networkId.trim()
        }
        upsertMockParticipant(activeNetwork.id, parsed.inviterNpub)
        for (const relay of parsed.relays) {
          const normalizedRelay = relay.trim()
          if (
            normalizedRelay &&
            !mockState.relays.some((entry) => entry.url === normalizedRelay)
          ) {
            mockState.relays.push({
              url: normalizedRelay,
              state: 'unknown',
              statusText: 'not checked',
            })
          }
        }
        updateMockRelaySummary()
        mockState.sessionStatus = `Invite imported for ${parsed.networkName.trim() || activeNetwork.name}`
        return asResult()
      })()

export const removeParticipant = (networkId: string, npub: string) =>
  isTauriRuntime()
    ? invoke<UiState>('remove_participant', { networkId, npub })
    : (() => {
        mockState.networks = mockState.networks.map((network) => {
          if (network.id !== networkId) {
            return network
          }
          return {
            ...network,
            participants: network.participants.filter(
              (participant) => participant.npub !== npub,
            ),
          }
        })

        return asResult()
      })()

export const setParticipantAlias = (npub: string, alias: string) =>
  isTauriRuntime()
    ? invoke<UiState>('set_participant_alias', { npub, alias })
    : (() => {
        const normalized = normalizeAlias(alias)
        mockState.networks = mockState.networks.map((network) => ({
          ...network,
          participants: network.participants.map((participant) => {
            if (participant.npub !== npub) {
              return participant
            }

            const magicDnsAlias = normalized || participant.magicDnsAlias
            return {
              ...participant,
              magicDnsAlias,
              magicDnsName: composeMagicDnsName(magicDnsAlias, mockState.magicDnsSuffix),
            }
          }),
        }))
        return asResult()
      })()

export const addRelay = (relay: string) =>
  isTauriRuntime()
    ? invoke<UiState>('add_relay', { relay })
    : (() => {
        if (!mockState.relays.some((entry) => entry.url === relay)) {
          mockState.relays.push({ url: relay, state: 'unknown', statusText: 'not checked' })
          updateMockRelaySummary()
        }
        return asResult()
      })()

export const removeRelay = (relay: string) =>
  isTauriRuntime()
    ? invoke<UiState>('remove_relay', { relay })
    : (() => {
        if (mockState.relays.length > 1) {
          mockState.relays = mockState.relays.filter((entry) => entry.url !== relay)
          updateMockRelaySummary()
        }
        return asResult()
      })()

export const updateSettings = (patch: SettingsPatch) =>
  isTauriRuntime()
    ? invoke<UiState>('update_settings', { patch })
    : (() => {
        if (patch.nodeName !== undefined) {
          mockState.nodeName = patch.nodeName
        }
        if (patch.endpoint !== undefined) {
          mockState.endpoint = patch.endpoint
        }
        if (patch.tunnelIp !== undefined) {
          mockState.tunnelIp = patch.tunnelIp
        }
        if (patch.magicDnsSuffix !== undefined) {
          mockState.magicDnsSuffix = patch.magicDnsSuffix
          mockState.magicDnsStatus =
            patch.magicDnsSuffix.trim().length > 0
              ? `System DNS active for .${patch.magicDnsSuffix} via 127.0.0.1:1053`
              : 'Local DNS only on 127.0.0.1:1053 (set suffix for system split-dns)'
          mockState.networks = mockState.networks.map((network) => ({
            ...network,
            participants: network.participants.map((participant) => ({
              ...participant,
              magicDnsName: composeMagicDnsName(
                participant.magicDnsAlias,
                mockState.magicDnsSuffix,
              ),
            })),
          }))
        }
        if (patch.listenPort !== undefined) {
          mockState.listenPort = patch.listenPort
        }
        if (patch.exitNode !== undefined) {
          mockState.exitNode = patch.exitNode.trim()
        }
        if (patch.advertiseExitNode !== undefined) {
          mockState.advertiseExitNode = patch.advertiseExitNode
        }
        if (patch.advertisedRoutes !== undefined) {
          mockState.advertisedRoutes = patch.advertisedRoutes
            .split(',')
            .map((value) => value.trim())
            .filter((value) => value.length > 0)
        }
        mockState.effectiveAdvertisedRoutes = computeMockEffectiveAdvertisedRoutes()
        if (patch.autoDisconnectRelaysWhenMeshReady !== undefined) {
          mockState.autoDisconnectRelaysWhenMeshReady =
            patch.autoDisconnectRelaysWhenMeshReady
        }
        if (patch.autoconnect !== undefined) {
          mockState.autoconnect = patch.autoconnect
        }
        if (patch.lanDiscoveryEnabled !== undefined) {
          mockState.lanDiscoveryEnabled = patch.lanDiscoveryEnabled
        }
        if (patch.launchOnStartup !== undefined) {
          mockState.launchOnStartup = patch.launchOnStartup
        }
        if (patch.closeToTrayOnClose !== undefined) {
          mockState.closeToTrayOnClose = patch.closeToTrayOnClose
        }
        return asResult()
      })()

let mockAutostartEnabled = true

export const isAutostartEnabled = async () => {
  if (!isTauriRuntime()) {
    return mockAutostartEnabled
  }

  try {
    const { isEnabled } = await import('@tauri-apps/plugin-autostart')
    return await isEnabled()
  } catch {
    return false
  }
}

export const setAutostartEnabled = async (enabled: boolean) => {
  if (!isTauriRuntime()) {
    mockAutostartEnabled = enabled
    return true
  }

  try {
    if (enabled) {
      const { enable } = await import('@tauri-apps/plugin-autostart')
      await enable()
    } else {
      const { disable } = await import('@tauri-apps/plugin-autostart')
      await disable()
    }
    return true
  } catch {
    return false
  }
}
