import { invoke } from '@tauri-apps/api/core'
import type { SettingsPatch, UiState } from './types'

const isTauriRuntime = () =>
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

const composeMagicDnsName = (alias: string, suffix: string) =>
  suffix.trim().length > 0 ? `${alias}.${suffix}` : alias

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
  networkId: 'nostr-vpn',
  effectiveNetworkId: 'nostr-vpn',
  magicDnsSuffix: 'nvpn',
  magicDnsStatus: 'System DNS active for .nvpn via 127.0.0.1:1053',
  autoDisconnectRelaysWhenMeshReady: true,
  lanDiscoveryEnabled: true,
  launchOnStartup: true,
  closeToTrayOnClose: true,
  connectedPeerCount: 0,
  expectedPeerCount: 0,
  meshReady: false,
  participants: [],
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

const asResult = async () => cloneMockState()

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
          statusText: 'up (mock)',
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
        return asResult()
      })()

export const addParticipant = (npub: string) =>
  isTauriRuntime()
    ? invoke<UiState>('add_participant', { npub })
    : (() => {
        if (!mockState.participants.some((participant) => participant.npub === npub)) {
          mockState.participants.push({
            npub,
            pubkeyHex: 'a'.repeat(64),
            tunnelIp: '10.44.0.2/32',
            magicDnsAlias: `peer-${'a'.repeat(12)}`,
            magicDnsName: composeMagicDnsName(
              `peer-${'a'.repeat(12)}`,
              mockState.magicDnsSuffix,
            ),
            state: 'unknown',
            statusText: 'not checked',
            lastSignalText: 'no signal yet',
          })
          mockState.expectedPeerCount = mockState.participants.length
        }
        return asResult()
      })()

export const removeParticipant = (npub: string) =>
  isTauriRuntime()
    ? invoke<UiState>('remove_participant', { npub })
    : (() => {
        mockState.participants = mockState.participants.filter(
          (participant) => participant.npub !== npub,
        )
        mockState.expectedPeerCount = mockState.participants.length
        return asResult()
      })()

export const setParticipantAlias = (npub: string, alias: string) =>
  isTauriRuntime()
    ? invoke<UiState>('set_participant_alias', { npub, alias })
    : (() => {
        mockState.participants = mockState.participants.map((participant) => {
          if (participant.npub !== npub) {
            return participant
          }

          const normalized = alias.trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || participant.magicDnsAlias
          return {
            ...participant,
            magicDnsAlias: normalized,
            magicDnsName: composeMagicDnsName(normalized, mockState.magicDnsSuffix),
          }
        })
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
        if (patch.networkId !== undefined) {
          mockState.networkId = patch.networkId
          mockState.effectiveNetworkId = patch.networkId
        }
        if (patch.magicDnsSuffix !== undefined) {
          mockState.magicDnsSuffix = patch.magicDnsSuffix
          mockState.magicDnsStatus =
            patch.magicDnsSuffix.trim().length > 0
              ? `System DNS active for .${patch.magicDnsSuffix} via 127.0.0.1:1053`
              : 'Local DNS only on 127.0.0.1:1053 (set suffix for system split-dns)'
          mockState.participants = mockState.participants.map((participant) => ({
            ...participant,
            magicDnsName: composeMagicDnsName(
              participant.magicDnsAlias,
              mockState.magicDnsSuffix,
            ),
          }))
        }
        if (patch.listenPort !== undefined) {
          mockState.listenPort = patch.listenPort
        }
        if (patch.autoDisconnectRelaysWhenMeshReady !== undefined) {
          mockState.autoDisconnectRelaysWhenMeshReady =
            patch.autoDisconnectRelaysWhenMeshReady
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
