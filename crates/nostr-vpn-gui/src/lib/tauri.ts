import { invoke } from '@tauri-apps/api/core'
import type { NetworkView, SettingsPatch, UiState } from './types'

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

const pseudoHexFromNpub = (npub: string) => {
  const seed = npub
    .replace(/^npub1/i, '')
    .replace(/[^a-z0-9]/gi, '')
    .toLowerCase()
  return (seed + 'a'.repeat(64)).slice(0, 64)
}

const countExpected = (network: NetworkView) =>
  network.enabled
    ? network.participants.filter((participant) => participant.state !== 'local').length
    : 0

const countOnline = (network: NetworkView) =>
  network.enabled
    ? network.participants.filter((participant) => participant.state === 'online').length
    : 0

const mockState: UiState = {
  sessionActive: false,
  relayConnected: false,
  sessionStatus: 'Disconnected',
  configPath: '~/.config/nvpn/config.toml',
  ownNpub: 'npub1akgu9lxldpt32lnjf97k005a4kgasewmvsrmkpzqeff39ssev0ssd6t3u',
  ownPubkeyHex: 'f'.repeat(64),
  nodeId: 'mock-node',
  nodeName: 'nostr-vpn-node',
  endpoint: '192.168.1.4:51820',
  tunnelIp: '10.44.0.1/32',
  listenPort: 51820,
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
  networks: [
    {
      id: 'network-1',
      name: 'Network 1',
      enabled: true,
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
    onlineCount: countOnline(network),
    expectedCount: countExpected(network),
  }))

  mockState.connectedPeerCount = mockState.networks.reduce(
    (sum, network) => sum + network.onlineCount,
    0,
  )
  mockState.expectedPeerCount = mockState.networks.reduce(
    (sum, network) => sum + network.expectedCount,
    0,
  )
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
  return cloneMockState()
}

export const tick = () =>
  isTauriRuntime() ? invoke<UiState>('tick') : asResult()

export const connectSession = () =>
  isTauriRuntime()
    ? invoke<UiState>('connect_session')
    : (() => {
        mockState.sessionActive = true
        mockState.relayConnected = true
        mockState.sessionStatus = 'Connected'
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
            statusText:
              participant.state === 'local'
                ? 'local'
                : 'online (handshake 0s ago)',
            lastSignalText:
              participant.state === 'local' ? 'self' : 'presence 0s ago',
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
        mockState.relayConnected = false
        mockState.sessionStatus = 'Disconnected'
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
            statusText: participant.state === 'local' ? 'local' : 'unknown',
            lastSignalText:
              participant.state === 'local' ? 'self' : 'no presence yet',
          })),
        }))
        updateMockRelaySummary()
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
          enabled: true,
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
        return asResult()
      })()

export const setNetworkEnabled = (networkId: string, enabled: boolean) =>
  isTauriRuntime()
    ? invoke<UiState>('set_network_enabled', { networkId, enabled })
    : (() => {
        mockState.networks = mockState.networks.map((network) =>
          network.id === networkId ? { ...network, enabled } : network,
        )
        return asResult()
      })()

export const addParticipant = (networkId: string, npub: string, alias = '') =>
  isTauriRuntime()
    ? invoke<UiState>('add_participant', { networkId, npub, alias: alias.trim() || null })
    : (() => {
        const target = mockState.networks.find((network) => network.id === networkId)
        if (!target) {
          return asResult()
        }

        if (target.participants.some((participant) => participant.npub === npub)) {
          return asResult()
        }

        const pubkeyHex = pseudoHexFromNpub(npub)
        const aliasCandidate = normalizeAlias(alias)
        const magicDnsAlias = aliasCandidate.length > 0 ? aliasCandidate : `peer-${pubkeyHex.slice(0, 10)}`

        target.participants.push({
          npub,
          pubkeyHex,
          tunnelIp: '10.44.0.2/32',
          magicDnsAlias,
          magicDnsName: composeMagicDnsName(magicDnsAlias, mockState.magicDnsSuffix),
          state: 'unknown',
          statusText: 'no signal yet',
          lastSignalText: 'no presence yet',
        })

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
