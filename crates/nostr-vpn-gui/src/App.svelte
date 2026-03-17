<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { Check, Copy, Trash2 } from 'lucide-svelte'

  import {
    addNetwork,
    addParticipant,
    addRelay,
    connectSession,
    disableSystemService,
    disconnectSession,
    enableSystemService,
    installCli,
    installSystemService,
    isAutostartEnabled,
    removeNetwork,
    removeParticipant,
    removeRelay,
    renameNetwork,
    setNetworkEnabled,
    setParticipantAlias,
    setAutostartEnabled,
    tick,
    uninstallCli,
    uninstallSystemService,
    updateSettings,
  } from './lib/tauri'
  import type {
    HealthIssue,
    NetworkView,
    ParticipantView,
    PeerState,
    PresenceState,
    SettingsPatch,
    UiState,
  } from './lib/types'

  let state: UiState | null = null
  let relayInput = ''
  let error = ''
  let cliActionStatus = ''
  let serviceActionStatus = ''
  let copiedPubkey = false

  let newNetworkName = ''
  let nodeNameDraft = ''
  let endpointDraft = ''
  let tunnelIpDraft = ''
  let listenPortDraft = ''
  let exitNodeDraft = ''
  let advertisedRoutesDraft = ''
  let magicDnsSuffixDraft = ''
  let exitNodeSearch = ''
  let draftsInitialized = false
  let showAdvancedRoutes = false

  let networkNameDrafts: Record<string, string> = {}
  let participantInputDrafts: Record<string, string> = {}
  let participantAddAliasDrafts: Record<string, string> = {}
  let participantAliasDrafts: Record<string, string> = {}

  let autostartReady = false
  let autostartUpdating = false

  const debouncers = new Map<string, number>()
  let pollHandle: number | null = null
  let copiedHandle: number | null = null
  let refreshInFlight = false
  let actionInFlight = false
  let serviceInstallRecommended = false
  let serviceEnableRecommended = false
  let serviceSetupRequired = false

  $: serviceInstallRecommended = !!state?.serviceSupported && !state.serviceInstalled
  $: serviceEnableRecommended =
    !!state?.serviceEnablementSupported && !!state?.serviceInstalled && !!state?.serviceDisabled
  $: serviceSetupRequired = serviceInstallRecommended && !state?.daemonRunning

  const serviceMetaText = (state: UiState) => {
    if (!state.serviceInstalled) {
      return 'Not installed'
    }
    if (state.serviceDisabled) {
      return 'Installed but disabled'
    }
    if (state.serviceRunning) {
      return 'Installed and running'
    }
    return 'Installed'
  }

  const serviceLifecycleBadgeText = (state: UiState) => {
    if (state.serviceDisabled) {
      return 'Disabled'
    }
    return state.serviceRunning ? 'Running' : 'Not running'
  }

  const serviceLifecycleBadgeClass = (state: UiState) => {
    if (state.serviceDisabled) {
      return 'warn'
    }
    return state.serviceRunning ? 'ok' : 'muted'
  }

  const participantBadgeClass = (state: PeerState | PresenceState) => {
    if (state === 'online' || state === 'present') {
      return 'ok'
    }
    if (state === 'pending') {
      return 'warn'
    }
    if (state === 'offline' || state === 'absent') {
      return 'bad'
    }
    return 'muted'
  }

  const peerStatePriority = (state: PeerState) => {
    switch (state) {
      case 'online':
        return 0
      case 'pending':
        return 1
      case 'offline':
        return 2
      case 'checking':
        return 3
      case 'unknown':
        return 4
      case 'local':
      default:
        return 5
    }
  }

  const healthBadgeClass = (severity: HealthIssue['severity']) => {
    switch (severity) {
      case 'critical':
        return 'bad'
      case 'warning':
        return 'warn'
      case 'info':
      default:
        return 'muted'
    }
  }

  const healthSummaryText = (state: UiState) => {
    if (state.health.length === 0) {
      return 'No active warnings'
    }
    const critical = state.health.filter((issue) => issue.severity === 'critical').length
    const warning = state.health.filter((issue) => issue.severity === 'warning').length
    if (critical > 0) {
      return `${critical} critical`
    }
    if (warning > 0) {
      return `${warning} warning${warning === 1 ? '' : 's'}`
    }
    return `${state.health.length} info`
  }

  const participantTransportBadgeText = (participant: ParticipantView) => {
    switch (participant.state) {
      case 'local':
        return 'WireGuard self'
      case 'online':
        return 'WireGuard online'
      case 'pending':
        return 'WireGuard waiting'
      case 'offline':
        return 'WireGuard offline'
      default:
        return 'WireGuard unknown'
    }
  }

  const participantPresenceBadgeText = (participant: ParticipantView) => {
    switch (participant.presenceState) {
      case 'local':
        return 'Nostr self'
      case 'present':
        return 'Nostr present'
      case 'absent':
        return 'Nostr absent'
      default:
        return 'Nostr unknown'
    }
  }

  const short = (value: string, head = 12, tail = 10) => {
    if (value.length <= head + tail + 3) {
      return value
    }

    return `${value.slice(0, head)}...${value.slice(-tail)}`
  }

  const activeNetwork = (state: UiState) =>
    state.networks.find((network) => network.enabled) ?? state.networks[0]

  const heroStateBadgeClass = (state: UiState) => {
    if (state.meshReady) {
      return 'ok'
    }
    if (state.sessionActive || serviceInstallRecommended || serviceEnableRecommended) {
      return 'warn'
    }
    return 'muted'
  }

  const heroStateText = (state: UiState) => {
    if ((serviceInstallRecommended || serviceEnableRecommended) && !state.sessionActive) {
      return 'Service required'
    }
    if (state.meshReady) {
      return 'Connected'
    }
    if (state.sessionActive) {
      return 'Connecting'
    }
    return 'Disconnected'
  }

  const heroSubtext = (state: UiState) => {
    const network = activeNetwork(state)
    if ((serviceInstallRecommended || serviceEnableRecommended) && !state.sessionActive) {
      return 'Install the background service for reliable startup, reconnects, and admin-free VPN switching.'
    }
    if (!state.sessionActive) {
      return `Ready to connect ${network.name}.`
    }
    if (state.expectedPeerCount === 0) {
      return `${network.name} is active, but no remote devices are configured yet.`
    }
    if (state.meshReady) {
      return `${network.name} is fully connected across ${state.connectedPeerCount}/${state.expectedPeerCount} peers.`
    }

    const remaining = Math.max(state.expectedPeerCount - state.connectedPeerCount, 0)
    return `${network.name} is waiting on ${remaining} more peer${remaining === 1 ? '' : 's'}.`
  }

  const networkPeerSummary = (network: NetworkView) => {
    const saved = `${network.participants.length} device${network.participants.length === 1 ? '' : 's'} saved`
    if (network.enabled) {
      return `${saved} • ${network.onlineCount}/${network.expectedCount} peers online`
    }
    return saved
  }

  const networkHasParticipant = (network: NetworkView, npub: string) =>
    network.participants.some((participant) => participant.npub === npub)

  const exitNodeCandidates = (state: UiState) => {
    const seen = new Set<string>()
    const participants: ParticipantView[] = []

    for (const network of state.networks) {
      for (const participant of network.participants) {
        if (participant.state === 'local' || seen.has(participant.npub)) {
          continue
        }
        seen.add(participant.npub)
        participants.push(participant)
      }
    }

    return participants.sort((left, right) => {
      const exitScore = Number(right.offersExitNode) - Number(left.offersExitNode)
      if (exitScore !== 0) {
        return exitScore
      }
      const stateScore = peerStatePriority(left.state) - peerStatePriority(right.state)
      if (stateScore !== 0) {
        return stateScore
      }
      return exitNodeOptionLabel(left).localeCompare(exitNodeOptionLabel(right))
    })
  }

  const exitNodeOptionLabel = (participant: ParticipantView) => {
    const base = participant.magicDnsName || short(participant.npub, 18, 12)
    return participant.offersExitNode
      ? `${base} (offers exit node)`
      : `${base} (not offering exit node)`
  }

  const filteredExitNodeCandidates = (state: UiState, query: string) => {
    const normalized = query.trim().toLowerCase()
    return exitNodeCandidates(state).filter((participant) => {
      if (!normalized) {
        return true
      }
      return (
        participant.magicDnsName.toLowerCase().includes(normalized) ||
        participant.magicDnsAlias.toLowerCase().includes(normalized) ||
        participant.npub.toLowerCase().includes(normalized) ||
        participant.tunnelIp.toLowerCase().includes(normalized)
      )
    })
  }

  const exitNodeAvailabilityClass = (participant: ParticipantView) => {
    if (!participant.offersExitNode) {
      return 'muted'
    }
    switch (participant.state) {
      case 'online':
        return 'ok'
      case 'pending':
        return 'warn'
      case 'offline':
        return 'bad'
      default:
        return 'muted'
    }
  }

  const exitNodeAvailabilityText = (participant: ParticipantView) => {
    if (!participant.offersExitNode) {
      return 'Not offered'
    }
    switch (participant.state) {
      case 'online':
        return 'Ready'
      case 'pending':
        return 'Waiting'
      case 'offline':
        return 'Offline'
      default:
        return 'Unknown'
    }
  }

  const offerExitNodeStatusText = (state: UiState) => {
    const defaultRoutes = state.effectiveAdvertisedRoutes.filter(
      (route) => route === '0.0.0.0/0' || route === '::/0',
    )
    const advertised = defaultRoutes.length > 0 ? defaultRoutes.join(', ') : '0.0.0.0/0, ::/0'

    if (state.advertiseExitNode) {
      return `Will advertise default routes: ${advertised}`
    }

    return 'Turn this on to offer this device as an exit node.'
  }

  const additionalRoutesStatusText = (state: UiState) => {
    if (state.advertisedRoutes.length === 0) {
      return 'Optional extra LAN or subnet routes. Not needed for exit-node traffic.'
    }

    return `Currently advertising extra routes: ${state.advertisedRoutes.join(', ')}`
  }

  const selectedExitNodeStatusText = (state: UiState) => {
    if (!state.exitNode) {
      return 'Internet-bound traffic stays local; only mesh routes are used.'
    }

    const selected = exitNodeCandidates(state).find((participant) => participant.npub === state.exitNode)
    if (!selected) {
      return 'Selected exit node is not present in the current network view.'
    }

    const label = selected.magicDnsName || short(selected.npub, 18, 12)
    if (!selected.offersExitNode) {
      return `${label} is selected, but it is not offering exit-node traffic right now.`
    }

    switch (selected.state) {
      case 'online':
        return `${label} is selected and ready to carry internet-bound traffic.`
      case 'pending':
        return `${label} is selected, but WireGuard is still waiting for a handshake.`
      case 'offline':
        return `${label} is selected, but it is currently offline.`
      default:
        return `${label} is selected; availability is still being checked.`
    }
  }

  async function refresh() {
    if (refreshInFlight || actionInFlight) {
      return
    }
    refreshInFlight = true
    try {
      state = await tick()
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
    } finally {
      refreshInFlight = false
    }
  }

  function initializeDraftsOnce() {
    if (!state || draftsInitialized) {
      return
    }

    nodeNameDraft = state.nodeName
    endpointDraft = state.endpoint
    tunnelIpDraft = state.tunnelIp
    listenPortDraft = String(state.listenPort)
    exitNodeDraft = state.exitNode
    advertisedRoutesDraft = state.advertisedRoutes.join(', ')
    magicDnsSuffixDraft = state.magicDnsSuffix
    draftsInitialized = true
    syncDraftsFromState()
  }

  function syncDraftsFromState() {
    if (!state) {
      networkNameDrafts = {}
      participantAliasDrafts = {}
      return
    }

    const nextNetworkNames: Record<string, string> = {}
    const nextParticipantInput: Record<string, string> = {}
    const nextParticipantAddAlias: Record<string, string> = {}
    const nextParticipantAliases: Record<string, string> = {}

    for (const network of state.networks) {
      const nameDebounceKey = `network-name-${network.id}`
      nextNetworkNames[network.id] = debouncers.has(nameDebounceKey)
        ? (networkNameDrafts[network.id] ?? network.name)
        : network.name

      nextParticipantInput[network.id] = participantInputDrafts[network.id] ?? ''
      nextParticipantAddAlias[network.id] = participantAddAliasDrafts[network.id] ?? ''

      for (const participant of network.participants) {
        const aliasDebounceKey = `alias-${participant.pubkeyHex}`
        nextParticipantAliases[participant.pubkeyHex] = debouncers.has(aliasDebounceKey)
          ? (participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias)
          : participant.magicDnsAlias
      }
    }

    networkNameDrafts = nextNetworkNames
    participantInputDrafts = nextParticipantInput
    participantAddAliasDrafts = nextParticipantAddAlias
    participantAliasDrafts = nextParticipantAliases

    if (!debouncers.has('magicDnsSuffix')) {
      magicDnsSuffixDraft = state.magicDnsSuffix
    }
    exitNodeDraft = state.exitNode
    if (state.advertisedRoutes.length > 0) {
      showAdvancedRoutes = true
    }
    if (!debouncers.has('advertisedRoutes')) {
      advertisedRoutesDraft = state.advertisedRoutes.join(', ')
    }
  }

  function debounce(key: string, fn: () => Promise<void>, delay = 450) {
    const existing = debouncers.get(key)
    if (existing) {
      window.clearTimeout(existing)
    }

    const timer = window.setTimeout(async () => {
      debouncers.delete(key)
      await fn()
    }, delay)

    debouncers.set(key, timer)
  }

  async function runAction(action: () => Promise<UiState>) {
    if (actionInFlight) {
      return
    }
    actionInFlight = true
    try {
      state = await action()
      error = ''
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
      cliActionStatus = ''
      serviceActionStatus = ''
      try {
        state = await tick()
        initializeDraftsOnce()
        syncDraftsFromState()
      } catch {
        // Keep the original action error if state refresh also fails.
      }
    } finally {
      actionInFlight = false
    }
  }

  async function onToggleSession() {
    if (!state) {
      return
    }

    if (serviceSetupRequired && !state.sessionActive) {
      await onInstallSystemService(true)
      return
    }

    if (serviceEnableRecommended && !state.sessionActive) {
      await onEnableSystemService(true)
      return
    }

    await runAction(state.sessionActive ? disconnectSession : connectSession)
  }

  async function onInstallCli() {
    await runAction(installCli)
    if (!error) {
      cliActionStatus = 'CLI installed in PATH (/usr/local/bin/nvpn)'
    }
  }

  async function onUninstallCli() {
    await runAction(uninstallCli)
    if (!error) {
      cliActionStatus = 'CLI removed from PATH (/usr/local/bin/nvpn)'
    }
  }

  async function onInstallSystemService(connectAfter = false) {
    const wasInstalled = !!state?.serviceInstalled
    await runAction(installSystemService)
    if (!error) {
      serviceActionStatus = 'System service installed and started'
    } else if (!wasInstalled && state?.serviceInstalled) {
      error = ''
      serviceActionStatus = state.serviceRunning
        ? 'System service installed and started'
        : 'System service installed'
    }
    if (connectAfter && !error && state && !state.sessionActive) {
      await runAction(connectSession)
    }
  }

  async function onEnableSystemService(connectAfter = false) {
    const wasDisabled = !!state?.serviceDisabled
    await runAction(enableSystemService)
    if (!error) {
      serviceActionStatus = 'System service enabled and started'
    } else if (wasDisabled && state && !state.serviceDisabled) {
      error = ''
      serviceActionStatus = state.serviceRunning
        ? 'System service enabled and started'
        : 'System service enabled'
    }
    if (connectAfter && !error && state && !state.sessionActive) {
      await runAction(connectSession)
    }
  }

  async function onDisableSystemService() {
    const wasEnabled = !!state?.serviceInstalled && !state?.serviceDisabled
    await runAction(disableSystemService)
    if (!error) {
      serviceActionStatus = 'System service disabled'
    } else if (wasEnabled && state?.serviceDisabled) {
      error = ''
      serviceActionStatus = 'System service disabled'
    }
  }

  async function onUninstallSystemService() {
    const wasInstalled = !!state?.serviceInstalled
    await runAction(uninstallSystemService)
    if (!error) {
      serviceActionStatus = 'System service removed'
    } else if (wasInstalled && state && !state.serviceInstalled) {
      error = ''
      serviceActionStatus = 'System service removed'
    }
  }

  async function onAddNetwork() {
    const name = newNetworkName.trim()
    await runAction(() => addNetwork(name))
    newNetworkName = ''
  }

  function onNetworkNameInput(networkId: string, value: string) {
    networkNameDrafts = {
      ...networkNameDrafts,
      [networkId]: value,
    }

    debounce(`network-name-${networkId}`, async () => {
      await runAction(() => renameNetwork(networkId, value))
    }, 500)
  }

  async function onAddParticipant(networkId: string) {
    const npub = participantInputDrafts[networkId]?.trim() || ''
    const alias = participantAddAliasDrafts[networkId]?.trim() || ''
    if (!npub) {
      return
    }

    await runAction(() => addParticipant(networkId, npub, alias))
    participantInputDrafts = {
      ...participantInputDrafts,
      [networkId]: '',
    }
    participantAddAliasDrafts = {
      ...participantAddAliasDrafts,
      [networkId]: '',
    }
  }

  async function onAddLanPeer(networkId: string, npub: string) {
    await runAction(() => addParticipant(networkId, npub, ''))
  }

  async function onAddRelay() {
    const relay = relayInput.trim()
    if (!relay) {
      return
    }

    await runAction(() => addRelay(relay))
    relayInput = ''
  }

  async function onUpdateSettings(patch: SettingsPatch) {
    await runAction(() => updateSettings(patch))
  }

  async function onSelectExitNode(npub: string) {
    exitNodeDraft = npub
    await onUpdateSettings({ exitNode: npub })
  }

  function onParticipantAliasInput(
    participantNpub: string,
    participantHex: string,
    value: string,
  ) {
    participantAliasDrafts = {
      ...participantAliasDrafts,
      [participantHex]: value,
    }

    debounce(
      `alias-${participantHex}`,
      async () => {
        await runAction(() => setParticipantAlias(participantNpub, value))
      },
      500,
    )
  }

  async function refreshAutostart() {
    if (!state) {
      autostartReady = true
      return
    }

    const runtimeEnabled = await isAutostartEnabled()
    if (runtimeEnabled !== state.launchOnStartup) {
      const ok = await setAutostartEnabled(state.launchOnStartup)
      // Startup sync can run in environments where autostart cannot be managed
      // (for example the Linux Tauri-driver container), so avoid surfacing a
      // boot-time banner unless the user explicitly changed the setting.
      if (!ok) {
        autostartReady = true
        return
      }
    }

    autostartReady = true
  }

  async function onToggleAutostart(enabled: boolean) {
    if (!state) {
      return
    }

    const previous = state.launchOnStartup
    autostartUpdating = true
    await onUpdateSettings({ launchOnStartup: enabled })
    const ok = await setAutostartEnabled(enabled)

    if (!ok) {
      error = 'Failed to update autostart setting'
      await onUpdateSettings({ launchOnStartup: previous })
    } else {
      await refreshAutostart()
    }

    autostartUpdating = false
  }

  async function copyPubkey() {
    if (!state) {
      return
    }

    try {
      await navigator.clipboard.writeText(state.ownNpub)
      copiedPubkey = true
      if (copiedHandle) {
        window.clearTimeout(copiedHandle)
      }
      copiedHandle = window.setTimeout(() => {
        copiedPubkey = false
        copiedHandle = null
      }, 2000)
    } catch {
      error = 'Clipboard copy failed'
    }
  }

  onMount(async () => {
    await refresh()
    await refreshAutostart()
    pollHandle = window.setInterval(refresh, 1500)
  })

  onDestroy(() => {
    if (pollHandle) {
      window.clearInterval(pollHandle)
    }
    if (copiedHandle) {
      window.clearTimeout(copiedHandle)
    }
    for (const timer of debouncers.values()) {
      window.clearTimeout(timer)
    }
  })
</script>

<main class="app-shell">
  <div class="drag-padding drag-padding-top" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-left" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-right" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-bottom" data-tauri-drag-region aria-hidden="true"></div>

  <header class="window-chrome" data-tauri-drag-region>
    <div class="window-title" data-testid="window-title">Nostr VPN</div>
  </header>

  <section class="identity-card panel hero-card">
    {#if state}
      {@const activeNetworkView = activeNetwork(state)}
      <div class="row hero-row">
        <div class="hero-copy">
          <div class="panel-kicker">Active network</div>
          <div class="row hero-title-row">
            <h1 data-testid="active-network-title">{activeNetworkView.name}</h1>
            <span class={`badge ${heroStateBadgeClass(state)}`}>{heroStateText(state)}</span>
          </div>
          <div class="hero-subtitle">{heroSubtext(state)}</div>
        </div>
        {#if !serviceSetupRequired}
          <button
            class={`session-switch ${state.sessionActive ? 'on' : 'off'}`}
            role="switch"
            aria-checked={state.sessionActive}
            aria-label="Toggle VPN session"
            data-testid="session-toggle"
            on:click={onToggleSession}
          >
            <span class="session-switch-track" aria-hidden="true">
              <span class="session-switch-thumb"></span>
            </span>
            <span class="session-switch-label">VPN {state.sessionActive ? 'On' : 'Off'}</span>
          </button>
        {/if}
      </div>

      <div class="hero-stats-grid">
        <div class="hero-stat-card" data-testid="hero-identity-card">
          <div class="panel-kicker">Identity</div>
          <button
            class="btn copy-btn copy-npub-btn hero-copy-btn"
            data-testid="copy-pubkey"
            on:click={copyPubkey}
          >
            <span class="copy-icon" aria-hidden="true">
              {#if copiedPubkey}
                <Check size={16} strokeWidth={2.3} />
              {:else}
                <Copy size={16} strokeWidth={2.2} />
              {/if}
            </span>
            <span class="copy-value" data-testid="pubkey">
              {short(state.ownNpub, 18, 14)}
            </span>
          </button>
        </div>

        <div class="hero-stat-card" data-testid="hero-mesh-card">
          <div class="panel-kicker">Mesh ID</div>
          <div class="hero-stat-value hero-stat-mono" data-testid="mesh-id">{state.networkId}</div>
          <div class="config-path">Share this mesh ID only with devices in {activeNetworkView.name}.</div>
        </div>

        <div class="hero-stat-card">
          <div class="panel-kicker">This device</div>
          <div class="hero-stat-value">{state.nodeName}</div>
          <div class="config-path">{state.tunnelIp} • {state.endpoint}</div>
        </div>
      </div>

      <div class="row status-row">
        <span class={`badge ${state.daemonRunning ? 'ok' : 'bad'}`}>
          Daemon {state.daemonRunning ? 'Running' : 'Stopped'}
        </span>
        <span class={`badge ${state.sessionActive ? 'ok' : 'bad'}`}>
          VPN {state.sessionActive ? 'On' : 'Off'}
        </span>
        <span class={`badge ${state.relayConnected ? 'ok' : 'muted'}`}>
          Relays {state.relayConnected ? 'Connected' : 'Disconnected'}
        </span>
        <span class="badge muted" data-testid="mesh-badge">
          Mesh {state.connectedPeerCount}/{state.expectedPeerCount}
        </span>
      </div>
      <div class="identity-status" data-testid="session-status-text">{state.sessionStatus}</div>
    {:else}
      <div class="panel-kicker">Loading</div>
      <div class="row hero-title-row">
        <h1>Starting Nostr VPN</h1>
      </div>
      <div class="hero-subtitle">Loading config, daemon state, and local mesh status.</div>
    {/if}
  </section>

  {#if error}
    <section class="panel error">{error}</section>
  {/if}

  {#if state}
    {@const activeNetworkView = activeNetwork(state)}

    {#if serviceInstallRecommended || serviceEnableRecommended}
      <section
        class={`panel service-panel ${serviceSetupRequired ? 'service-panel-required' : ''}`}
        data-testid="service-panel"
      >
        <div class="section-title-row">
          <div>
            <div class="panel-kicker">Action needed</div>
            <h2>Background Service</h2>
          </div>
          <div class="section-meta">{serviceMetaText(state)}</div>
        </div>

        <div class="row status-row">
          <span class={`badge ${state.serviceInstalled ? 'ok' : 'warn'}`}>
            {state.serviceInstalled ? 'Installed' : 'Setup required'}
          </span>
          <span class={`badge ${serviceLifecycleBadgeClass(state)}`}>
            {serviceLifecycleBadgeText(state)}
          </span>
          <span class="badge muted">Daemon {state.daemonRunning ? 'reachable' : 'idle'}</span>
        </div>

        <div class="service-panel-copy">
          <div class="service-panel-title">
            {serviceSetupRequired
              ? 'Install once for reliable background VPN'
              : 'Enable the service to keep VPN control out of the GUI process'}
          </div>
          <div class="service-panel-text">
            Required for background startup, resilient reconnects, and avoiding repeated admin prompts.
          </div>
          {#if state.serviceStatusDetail}
            <div class="service-panel-detail" data-testid="service-status-detail">
              {state.serviceStatusDetail}
            </div>
          {/if}
          {#if serviceActionStatus}
            <div class="service-panel-detail service-panel-detail-ok">{serviceActionStatus}</div>
          {/if}
        </div>

        <div class="row service-actions-row">
          <button
            class={`btn ${serviceSetupRequired ? 'service-primary-btn' : ''}`}
            data-testid="install-service-btn"
            on:click={() =>
              serviceEnableRecommended
                ? onEnableSystemService()
                : onInstallSystemService(serviceSetupRequired)}
          >
            {serviceEnableRecommended
              ? 'Enable service'
              : state.serviceInstalled
                ? 'Reinstall service'
                : 'Install service'}
          </button>
          {#if state.serviceEnablementSupported && state.serviceInstalled && !state.serviceDisabled}
            <button
              class="btn ghost"
              data-testid="disable-service-btn"
              on:click={onDisableSystemService}
            >
              Disable service
            </button>
          {/if}
          <button
            class="btn ghost"
            data-testid="uninstall-service-btn"
            on:click={onUninstallSystemService}
            disabled={!state.serviceInstalled}
          >
            Uninstall
          </button>
        </div>
      </section>
    {/if}

    <section class="panel spotlight-panel">
      <div class="section-title-row">
        <div>
          <div class="panel-kicker">Live mesh</div>
          <h2>Devices</h2>
        </div>
        <div class="section-meta">{activeNetworkView.onlineCount}/{activeNetworkView.expectedCount} online</div>
      </div>

      <div class="spotlight-meta-grid">
        <div class="spotlight-meta-card">
          <div class="panel-kicker">Network</div>
          <div class="spotlight-meta-value">{activeNetworkView.name}</div>
          <div class="config-path">{networkPeerSummary(activeNetworkView)}</div>
        </div>
        <div class="spotlight-meta-card">
          <div class="panel-kicker">Mesh ID</div>
          <div class="spotlight-meta-value hero-stat-mono">{activeNetworkView.networkId}</div>
          <div class="config-path">
            Peers on {activeNetworkView.name} must share this Mesh ID and list each other as participants.
          </div>
        </div>
      </div>

      <label class="toggle-row lan-discovery-toggle">
        <input
          type="checkbox"
          checked={state.lanDiscoveryEnabled}
          data-testid="lan-discovery-toggle"
          on:change={(event) =>
            onUpdateSettings({
              lanDiscoveryEnabled: (event.currentTarget as HTMLInputElement).checked,
            })}
        />
        LAN discovery (multicast)
      </label>

      <div class="participant-add-panel">
        <div class="participant-add-label">Add device to {activeNetworkView.name}</div>
        <div class="participant-add-fields">
          <input
            class="text-input participant-add-npub"
            placeholder="Participant npub"
            data-testid="participant-input"
            value={participantInputDrafts[activeNetworkView.id] ?? ''}
            on:input={(event) =>
              (participantInputDrafts = {
                ...participantInputDrafts,
                [activeNetworkView.id]: (event.currentTarget as HTMLInputElement).value,
              })}
            on:keydown={(event) => event.key === 'Enter' && onAddParticipant(activeNetworkView.id)}
          />
          <input
            class="text-input participant-add-alias"
            placeholder="Alias (optional)"
            data-testid="participant-add-alias-input"
            value={participantAddAliasDrafts[activeNetworkView.id] ?? ''}
            on:input={(event) =>
              (participantAddAliasDrafts = {
                ...participantAddAliasDrafts,
                [activeNetworkView.id]: (event.currentTarget as HTMLInputElement).value,
              })}
            on:keydown={(event) => event.key === 'Enter' && onAddParticipant(activeNetworkView.id)}
          />
          <button
            class="btn participant-add-btn"
            data-testid="participant-add"
            on:click={() => onAddParticipant(activeNetworkView.id)}
          >
            Add
          </button>
        </div>
      </div>

      {#if activeNetworkView.participants.length === 0}
        <div class="item-row network-empty-state">
          <div class="item-main">
            <div class="item-title">No devices yet</div>
            <div class="item-sub">Add participant npubs to start building the active mesh.</div>
          </div>
        </div>
      {:else}
        <div class="stack rows">
          {#each activeNetworkView.participants as participant}
            <div class="item-row" data-testid="participant-row">
              <div class="item-main">
                <div class="item-title">{short(participant.npub, 22, 12)}</div>
                <div class="row alias-row">
                  <input
                    class="text-input alias-input"
                    value={participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias}
                    data-testid="participant-alias-input"
                    on:input={(event) =>
                      onParticipantAliasInput(
                        participant.npub,
                        participant.pubkeyHex,
                        (event.currentTarget as HTMLInputElement).value,
                      )}
                  />
                  {#if state.magicDnsSuffix}
                    <span class="alias-suffix">.{state.magicDnsSuffix}</span>
                  {/if}
                </div>
                <div class="item-sub" data-testid="participant-status-text">
                  {participant.magicDnsName} | {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
                  {#if participant.advertisedRoutes.length > 0}
                    | routes {participant.advertisedRoutes.join(', ')}
                  {/if}
                </div>
              </div>
              <div class="participant-badges">
                <span
                  class={`badge participant-badge ${participantBadgeClass(participant.state)}`}
                  data-testid="participant-state"
                >
                  {participantTransportBadgeText(participant)}
                </span>
                <span
                  class={`badge participant-badge ${participantBadgeClass(participant.presenceState)}`}
                  data-testid="participant-presence-state"
                >
                  {participantPresenceBadgeText(participant)}
                </span>
                {#if participant.offersExitNode}
                  <span class="badge participant-badge warn">Exit node</span>
                {/if}
                {#if state.exitNode === participant.npub}
                  <span class="badge participant-badge ok">Selected exit</span>
                {/if}
              </div>
              <button
                class="btn ghost icon-btn"
                data-testid="participant-remove"
                title="Delete participant"
                aria-label="Delete participant"
                on:click={() => runAction(() => removeParticipant(activeNetworkView.id, participant.npub))}
              >
                <Trash2 size={16} strokeWidth={2.2} />
              </button>
            </div>
          {/each}
        </div>
      {/if}

      {#if state.lanDiscoveryEnabled}
        {@const unconfiguredLan = state.lanPeers.filter((peer) => !networkHasParticipant(activeNetworkView, peer.npub))}
        {#if unconfiguredLan.length > 0}
          <div class="lan-title">LAN peers</div>
          <div class="stack rows">
            {#each unconfiguredLan as peer}
              <div class="item-row" data-testid="lan-peer-row">
                <div class="item-main">
                  <div class="item-title">{short(peer.npub, 22, 12)}</div>
                  <div class="item-sub">{peer.nodeName} | {peer.endpoint} | seen {peer.lastSeenText}</div>
                </div>
                <button class="btn" on:click={() => onAddLanPeer(activeNetworkView.id, peer.npub)}>
                  Add
                </button>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </section>

    <section class="panel exit-node-panel">
      <div class="section-title-row">
        <div>
          <div class="panel-kicker">Routing</div>
          <h2>Exit Node</h2>
        </div>
        <div class="section-meta">{state.exitNode ? 'Selected' : 'Direct mesh'}</div>
      </div>

      <div class="config-path">{selectedExitNodeStatusText(state)}</div>
      <div class="field-span field-panel exit-node-panel-body">
        <input
          class="text-input"
          placeholder="Search peers by alias, npub, or tunnel IP"
          data-testid="exit-node-search"
          bind:value={exitNodeSearch}
        />
        <div class="exit-node-list" data-testid="exit-node-select">
          <button
            class={`exit-node-card ${!state.exitNode ? 'selected' : ''}`}
            type="button"
            on:click={() => onSelectExitNode('')}
          >
            <div class="row spread">
              <div class="item-title">No exit node</div>
              <span class="badge muted">Direct mesh</span>
            </div>
            <div class="item-sub">Keep default-route traffic off peer relays and use mesh routing only.</div>
          </button>

          {#each filteredExitNodeCandidates(state, exitNodeSearch) as participant}
            <button
              class={`exit-node-card ${
                state.exitNode === participant.npub ? 'selected' : ''
              } ${!participant.offersExitNode ? 'disabled' : ''}`}
              type="button"
              on:click={() => onSelectExitNode(participant.npub)}
              disabled={!participant.offersExitNode}
            >
              <div class="row spread">
                <div class="item-title">{participant.magicDnsName || short(participant.npub, 18, 12)}</div>
                <span class={`badge ${exitNodeAvailabilityClass(participant)}`}>
                  {exitNodeAvailabilityText(participant)}
                </span>
              </div>
              <div class="item-sub">
                {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
              </div>
            </button>
          {/each}

          {#if filteredExitNodeCandidates(state, exitNodeSearch).length === 0}
            <div class="config-path">No peers match that search.</div>
          {/if}
        </div>
      </div>
    </section>

    <section class="panel network-directory-panel">
      <div class="section-title-row">
        <div>
          <div class="panel-kicker">Profiles</div>
          <h2 data-testid="saved-networks-title">Networks</h2>
        </div>
        <div class="section-meta">{state.networks.length} total</div>
      </div>

      <div class="config-path">
        Only one network is active at a time. Activate a saved network to switch the live mesh.
      </div>

      <div class="row form-row network-create-row">
        <input
          class="text-input"
          placeholder="Add network name (optional)"
          data-testid="network-add-input"
          bind:value={newNetworkName}
          on:keydown={(event) => event.key === 'Enter' && onAddNetwork()}
        />
        <button class="btn" data-testid="network-add" on:click={onAddNetwork}>
          Add network
        </button>
      </div>

      <div class="stack rows network-stack">
        {#each [activeNetworkView, ...state.networks.filter((network) => network.id !== activeNetworkView.id)] as network}
          <section class={`network-card ${network.enabled ? 'network-card-active' : 'network-disabled'}`} data-testid="network-card">
            <div class="row spread network-header">
              <div class="network-directory-main">
                <div class="row network-directory-title-row">
                  <input
                  class="text-input network-name-input"
                  value={networkNameDrafts[network.id] ?? network.name}
                  data-testid="network-name-input"
                  on:input={(event) =>
                    onNetworkNameInput(network.id, (event.currentTarget as HTMLInputElement).value)}
                  />
                  {#if network.enabled}
                    <span class="badge ok" data-testid="network-active-badge">
                      Active
                    </span>
                  {:else}
                    <span class="badge muted">Saved</span>
                  {/if}
                </div>
                <div class="config-path" data-testid="network-mesh-id">Mesh ID: {network.networkId}</div>
                <div class="config-path">{networkPeerSummary(network)}</div>
              </div>

              <div class="row network-actions">
                {#if network.enabled}
                  <button class="btn ghost" data-testid="network-enabled-toggle" disabled>
                    Active
                  </button>
                {:else}
                  <button
                    class="btn ghost"
                    data-testid="network-enabled-toggle"
                    on:click={() => runAction(() => setNetworkEnabled(network.id, true))}
                  >
                    Activate
                  </button>
                {/if}
                <button
                  class="btn ghost icon-btn"
                  data-testid="network-remove"
                  title="Delete network"
                  aria-label="Delete network"
                  disabled={state.networks.length <= 1}
                  on:click={() => runAction(() => removeNetwork(network.id))}
                >
                  <Trash2 size={16} strokeWidth={2.2} />
                </button>
              </div>
            </div>

            {#if network.enabled}
              <div class="config-path saved-network-note">
                This is the active network. Devices, presence, and tunnel state are shown in the live mesh panel above.
              </div>
            {:else}
              <details class="network-editor">
                <summary class="network-editor-summary">Edit saved devices</summary>
                <div class="config-path saved-network-note">
                  Activate this saved network when you want to switch the live mesh to it.
                </div>

                <div class="participant-add-panel">
                  <div class="participant-add-label">Add device to {network.name}</div>
                  <div class="participant-add-fields">
                    <input
                      class="text-input participant-add-npub"
                      placeholder="Participant npub"
                      data-testid="participant-input"
                      value={participantInputDrafts[network.id] ?? ''}
                      on:input={(event) =>
                        (participantInputDrafts = {
                          ...participantInputDrafts,
                          [network.id]: (event.currentTarget as HTMLInputElement).value,
                        })}
                      on:keydown={(event) => event.key === 'Enter' && onAddParticipant(network.id)}
                    />
                    <input
                      class="text-input participant-add-alias"
                      placeholder="Alias (optional)"
                      data-testid="participant-add-alias-input"
                      value={participantAddAliasDrafts[network.id] ?? ''}
                      on:input={(event) =>
                        (participantAddAliasDrafts = {
                          ...participantAddAliasDrafts,
                          [network.id]: (event.currentTarget as HTMLInputElement).value,
                        })}
                      on:keydown={(event) => event.key === 'Enter' && onAddParticipant(network.id)}
                    />
                    <button
                      class="btn participant-add-btn"
                      data-testid="participant-add"
                      on:click={() => onAddParticipant(network.id)}
                    >
                      Add
                    </button>
                  </div>
                </div>

                {#if network.participants.length === 0}
                  <div class="item-row network-empty-state">
                    <div class="item-main">
                      <div class="item-title">No saved devices yet</div>
                      <div class="item-sub">Add npubs now and activate this network later when you want it live.</div>
                    </div>
                  </div>
                {:else}
                  <div class="stack rows">
                    {#each network.participants as participant}
                      <div class="item-row saved-participant-row">
                        <div class="item-main">
                          <div class="item-title">{short(participant.npub, 22, 12)}</div>
                          <div class="row alias-row">
                            <input
                              class="text-input alias-input"
                              value={participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias}
                              on:input={(event) =>
                                onParticipantAliasInput(
                                  participant.npub,
                                  participant.pubkeyHex,
                                  (event.currentTarget as HTMLInputElement).value,
                                )}
                            />
                            {#if state.magicDnsSuffix}
                              <span class="alias-suffix">.{state.magicDnsSuffix}</span>
                            {/if}
                          </div>
                          <div class="item-sub">
                            {participant.magicDnsName || participant.magicDnsAlias || short(participant.npub, 16, 10)} | {participant.tunnelIp}
                            {#if participant.offersExitNode}
                              | exit routes advertised
                            {/if}
                          </div>
                        </div>
                        <button
                          class="btn ghost icon-btn"
                          title="Delete participant"
                          aria-label="Delete participant"
                          on:click={() => runAction(() => removeParticipant(network.id, participant.npub))}
                        >
                          <Trash2 size={16} strokeWidth={2.2} />
                        </button>
                      </div>
                    {/each}
                  </div>
                {/if}

                {#if state.lanDiscoveryEnabled}
                  {@const unconfiguredLan = state.lanPeers.filter((peer) => !networkHasParticipant(network, peer.npub))}
                  {#if unconfiguredLan.length > 0}
                    <div class="lan-title">LAN peers</div>
                    <div class="stack rows">
                      {#each unconfiguredLan as peer}
                        <div class="item-row" data-testid="lan-peer-row">
                          <div class="item-main">
                            <div class="item-title">{short(peer.npub, 22, 12)}</div>
                            <div class="item-sub">{peer.nodeName} | {peer.endpoint} | seen {peer.lastSeenText}</div>
                          </div>
                          <button class="btn" on:click={() => onAddLanPeer(network.id, peer.npub)}>
                            Add
                          </button>
                        </div>
                      {/each}
                    </div>
                  {/if}
                {/if}
              </details>
            {/if}
          </section>
        {/each}
      </div>
    </section>

    <details class="panel collapsible-panel" open={state.health.length > 0}>
      <summary class="collapsible-summary">
        <div>
          <div class="panel-kicker">Advanced</div>
          <h2>Diagnostics</h2>
        </div>
        <div class="section-meta">{healthSummaryText(state)}</div>
      </summary>

      <div class="collapsible-body diagnostics-panel">
        <div class="row status-row diagnostics-badges">
          <span class="badge muted">
            IF {state.network.defaultInterface || 'unknown'}
          </span>
          <span
            class={`badge ${
              state.network.captivePortal === true
                ? 'bad'
                : state.network.captivePortal === false
                  ? 'ok'
                  : 'muted'
            }`}
          >
            {state.network.captivePortal === true
              ? 'Captive portal'
              : state.network.captivePortal === false
                ? 'Open internet'
                : 'Portal unknown'}
          </span>
          <span class={`badge ${state.portMapping.activeProtocol ? 'ok' : 'muted'}`}>
            Mapping {state.portMapping.activeProtocol || 'none'}
          </span>
        </div>

        <div class="diagnostics-copy">
          <div class="config-path">
            Local addresses:
            {state.network.primaryIpv4 || 'no IPv4'}
            {#if state.network.primaryIpv6}
              | {state.network.primaryIpv6}
            {/if}
          </div>
          <div class="config-path">
            Gateway:
            {state.network.gatewayIpv4 || state.network.gatewayIpv6 || 'unknown'}
          </div>
          <div class="config-path">
            External endpoint:
            {state.portMapping.externalEndpoint || 'stun / direct only'}
          </div>
        </div>

        {#if state.health.length === 0}
          <div class="config-path" data-testid="health-empty">Daemon reports no active health warnings.</div>
        {:else}
          <div class="stack rows">
            {#each state.health as issue}
              <div class="health-card" data-testid="health-issue">
                <div class="row spread health-card-header">
                  <div class="item-title">{issue.summary}</div>
                  <span class={`badge ${healthBadgeClass(issue.severity)}`}>{issue.severity}</span>
                </div>
                <div class="item-sub">{issue.detail}</div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </details>

    {#if state.serviceSupported && !serviceInstallRecommended && !serviceEnableRecommended}
      <details class="panel collapsible-panel service-panel" data-testid="service-panel">
        <summary class="collapsible-summary">
          <div>
            <div class="panel-kicker">Advanced</div>
            <h2>Background Service</h2>
          </div>
          <div class="section-meta">{serviceMetaText(state)}</div>
        </summary>

        <div class="collapsible-body">
          <div class="row status-row">
            <span class="badge ok">Installed</span>
            <span class={`badge ${serviceLifecycleBadgeClass(state)}`}>
              {serviceLifecycleBadgeText(state)}
            </span>
            <span class={`badge ${state.daemonRunning ? 'ok' : 'muted'}`}>
              Daemon {state.daemonRunning ? 'reachable' : 'idle'}
            </span>
          </div>

          <div class="service-panel-copy">
            <div class="service-panel-title">
              Background service manages privileged VPN runtime operations.
            </div>
            {#if state.serviceStatusDetail}
              <div class="service-panel-detail" data-testid="service-status-detail">
                {state.serviceStatusDetail}
              </div>
            {/if}
            {#if serviceActionStatus}
              <div class="service-panel-detail service-panel-detail-ok">{serviceActionStatus}</div>
            {/if}
          </div>

          <div class="row service-actions-row">
            <button
              class="btn"
              data-testid="install-service-btn"
              on:click={() =>
                serviceEnableRecommended ? onEnableSystemService() : onInstallSystemService()}
            >
              {serviceEnableRecommended ? 'Enable service' : 'Reinstall service'}
            </button>
            {#if state.serviceEnablementSupported && state.serviceInstalled && !state.serviceDisabled}
              <button
                class="btn ghost"
                data-testid="disable-service-btn"
                on:click={onDisableSystemService}
              >
                Disable service
              </button>
            {/if}
            <button
              class="btn ghost"
              data-testid="uninstall-service-btn"
              on:click={onUninstallSystemService}
            >
              Uninstall
            </button>
          </div>
        </div>
      </details>
    {/if}

    <details class="panel collapsible-panel">
      <summary class="collapsible-summary">
        <div>
          <div class="panel-kicker">Advanced</div>
          <h2>Relays</h2>
        </div>
        <div class="section-meta relay-health">
          <span class="ok-text">{state.relaySummary.up}/{state.relays.length} connected</span>
        </div>
      </summary>

      <div class="collapsible-body">
        <div class="row form-row">
          <input
            class="text-input"
            placeholder="Add relay URL"
            data-testid="relay-input"
            bind:value={relayInput}
            on:keydown={(event) => event.key === 'Enter' && onAddRelay()}
          />
          <button class="btn" data-testid="relay-add" on:click={onAddRelay}>Add</button>
        </div>

        <div class="stack rows">
          {#each state.relays as relay}
            <div class="item-row" data-testid="relay-row">
              <div class="item-main">
                <div class="item-title relay-url">{relay.url}</div>
                {#if relay.state !== 'unknown' && relay.statusText}
                  <div class="item-sub">{relay.statusText}</div>
                {/if}
              </div>
              <span class={`badge ${relay.state === 'up' ? 'ok' : relay.state === 'down' ? 'bad' : relay.state === 'checking' ? 'warn' : 'muted'}`}>
                {relay.state}
              </span>
              <button
                class="btn ghost icon-btn"
                data-testid="relay-remove"
                title="Delete relay"
                aria-label="Delete relay"
                on:click={() => runAction(() => removeRelay(relay.url))}
              >
                <Trash2 size={16} strokeWidth={2.2} />
              </button>
            </div>
          {/each}
        </div>
      </div>
    </details>

    <details class="panel collapsible-panel">
      <summary class="collapsible-summary">
        <div>
          <div class="panel-kicker">Advanced</div>
          <h2>Settings</h2>
        </div>
        <div class="section-meta">Node & app</div>
      </summary>

      <div class="collapsible-body">
        <div class="row settings-action-row">
          <div class="config-path">Config: {state.configPath}</div>
        </div>
        <div class="row spread settings-action-row">
          <div class="config-path">Terminal CLI</div>
          <div class="row cli-actions-row">
            <button class="btn" data-testid="install-cli-btn" on:click={onInstallCli}>
              {state.cliInstalled ? 'Reinstall CLI' : 'Install CLI'}
            </button>
            <button
              class="btn ghost"
              data-testid="uninstall-cli-btn"
              on:click={onUninstallCli}
              disabled={!state.cliInstalled}
            >
              Uninstall CLI
            </button>
          </div>
        </div>
        {#if cliActionStatus}
          <div class="config-path">{cliActionStatus}</div>
        {/if}
        <div class="config-path" data-testid="magic-dns-status">DNS: {state.magicDnsStatus}</div>

        <label class="toggle-row">
          <input
            type="checkbox"
            checked={state.autoDisconnectRelaysWhenMeshReady}
            on:change={(event) =>
              onUpdateSettings({
                autoDisconnectRelaysWhenMeshReady: (event.target as HTMLInputElement).checked,
              })}
          />
          <span>Auto-disconnect relays when mesh is ready</span>
        </label>

        <label class="toggle-row">
          <input
            type="checkbox"
            checked={state.autoconnect}
            on:change={(event) =>
              onUpdateSettings({
                autoconnect: (event.currentTarget as HTMLInputElement).checked,
              })}
          />
          <span>Auto-connect session on app start</span>
        </label>

        <label class="toggle-row">
          <input
            type="checkbox"
            checked={state.advertiseExitNode}
            on:change={(event) =>
              onUpdateSettings({
                advertiseExitNode: (event.currentTarget as HTMLInputElement).checked,
              })}
          />
          <span>Advertise exit node (default routes)</span>
        </label>

        <label class="toggle-row">
          <input
            type="checkbox"
            data-testid="autostart-toggle"
            checked={state.launchOnStartup}
            disabled={!autostartReady || autostartUpdating}
            on:change={(event) =>
              onToggleAutostart((event.currentTarget as HTMLInputElement).checked)}
          />
          <span>Launch on system startup</span>
        </label>

        <label class="toggle-row">
          <input
            type="checkbox"
            checked={state.closeToTrayOnClose}
            on:change={(event) =>
              onUpdateSettings({
                closeToTrayOnClose: (event.currentTarget as HTMLInputElement).checked,
              })}
          />
          <span>Keep running in menu bar when window is closed</span>
        </label>

        <div class="field-grid">
          <label>
            <span>Advertised Routes</span>
            <input
              class="text-input"
              placeholder="10.0.0.0/24, 192.168.0.0/24"
              bind:value={advertisedRoutesDraft}
              on:input={() =>
                debounce('advertisedRoutes', () =>
                  onUpdateSettings({ advertisedRoutes: advertisedRoutesDraft }))}
            />
          </label>

          <label>
            <span>MagicDNS Suffix (Optional)</span>
            <input
              class="text-input"
              data-testid="magic-dns-suffix-input"
              bind:value={magicDnsSuffixDraft}
              on:input={() =>
                debounce('magicDnsSuffix', () =>
                  onUpdateSettings({ magicDnsSuffix: magicDnsSuffixDraft }))}
            />
          </label>

          <label>
            <span>Node Name</span>
            <input
              class="text-input"
              data-testid="node-name-input"
              bind:value={nodeNameDraft}
              on:input={() => debounce('nodeName', () => onUpdateSettings({ nodeName: nodeNameDraft }))}
            />
          </label>

          <label>
            <span>Endpoint</span>
            <input
              class="text-input"
              bind:value={endpointDraft}
              on:input={() => debounce('endpoint', () => onUpdateSettings({ endpoint: endpointDraft }))}
            />
          </label>

          <label>
            <span>Tunnel IP</span>
            <input
              class="text-input"
              bind:value={tunnelIpDraft}
              on:input={() => debounce('tunnelIp', () => onUpdateSettings({ tunnelIp: tunnelIpDraft }))}
            />
          </label>

          <label>
            <span>Listen Port</span>
            <input
              class="text-input"
              bind:value={listenPortDraft}
              on:input={() =>
                debounce('listenPort', async () => {
                  const parsed = Number.parseInt(listenPortDraft, 10)
                  if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
                    await onUpdateSettings({ listenPort: parsed })
                  }
                })}
            />
          </label>
        </div>
      </div>
    </details>
  {/if}
</main>
