<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { Check, Copy, Trash2 } from 'lucide-svelte'

  import {
    addNetwork,
    addParticipant,
    addRelay,
    connectSession,
    disconnectSession,
    isAutostartEnabled,
    removeNetwork,
    removeParticipant,
    removeRelay,
    renameNetwork,
    setNetworkEnabled,
    setParticipantAlias,
    setAutostartEnabled,
    tick,
    updateSettings,
  } from './lib/tauri'
  import type { NetworkView, SettingsPatch, UiState } from './lib/types'

  let state: UiState | null = null
  let relayInput = ''
  let error = ''
  let copiedPubkey = false

  let newNetworkName = ''
  let nodeNameDraft = ''
  let endpointDraft = ''
  let tunnelIpDraft = ''
  let listenPortDraft = ''
  let magicDnsSuffixDraft = ''
  let draftsInitialized = false

  let networkNameDrafts: Record<string, string> = {}
  let participantInputDrafts: Record<string, string> = {}
  let participantAddAliasDrafts: Record<string, string> = {}
  let participantAliasDrafts: Record<string, string> = {}

  let autostartReady = false
  let autostartUpdating = false

  const debouncers = new Map<string, number>()
  let pollHandle: number | null = null
  let copiedHandle: number | null = null

  const short = (value: string, head = 12, tail = 10) => {
    if (value.length <= head + tail + 3) {
      return value
    }

    return `${value.slice(0, head)}...${value.slice(-tail)}`
  }

  const networkHasParticipant = (network: NetworkView, npub: string) =>
    network.participants.some((participant) => participant.npub === npub)

  async function refresh() {
    try {
      state = await tick()
      error = ''
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
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
    try {
      state = await action()
      error = ''
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
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
      if (!ok) {
        error = 'Failed to apply startup launch setting'
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
    pollHandle = window.setInterval(refresh, 1000)
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

  <section class="identity-card panel">
    <div class="row identity-row">
      <button class="btn copy-btn copy-npub-btn" data-testid="copy-pubkey" on:click={copyPubkey} disabled={!state}>
        <span class="copy-icon" aria-hidden="true">
          {#if copiedPubkey}
            <Check size={16} strokeWidth={2.3} />
          {:else}
            <Copy size={16} strokeWidth={2.2} />
          {/if}
        </span>
        <span class="copy-value" data-testid="pubkey">
          {state ? short(state.ownNpub, 18, 14) : 'Loading...'}
        </span>
      </button>
    </div>

    {#if state}
      <div class="row status-row">
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
    {/if}
  </section>

  {#if error}
    <section class="panel error">{error}</section>
  {/if}

  {#if state}
    <section class="panel">
      <div class="section-title-row">
        <h2>Networks</h2>
        <div class="section-meta">
          Enabled: {state.networks.filter((network) => network.enabled).length}/{state.networks.length}
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
        {#each state.networks as network}
          <section class={`network-card ${network.enabled ? '' : 'network-disabled'}`} data-testid="network-card">
            <div class="row spread network-header">
              <div class="row network-title-group">
                <input
                  class="text-input network-name-input"
                  value={networkNameDrafts[network.id] ?? network.name}
                  data-testid="network-name-input"
                  on:input={(event) =>
                    onNetworkNameInput(network.id, (event.currentTarget as HTMLInputElement).value)}
                />
                <span class="badge muted" data-testid="network-mesh-badge">
                  {network.onlineCount}/{network.expectedCount}
                </span>
              </div>
              <div class="row network-actions">
                <label class="toggle-row compact">
                  <input
                    type="checkbox"
                    checked={network.enabled}
                    data-testid="network-enabled-toggle"
                    on:change={(event) =>
                      runAction(() =>
                        setNetworkEnabled(network.id, (event.currentTarget as HTMLInputElement).checked),
                      )}
                  />
                  <span>{network.enabled ? 'On' : 'Off'}</span>
                </label>
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

            <div class="row form-row participant-add-row">
              <input
                class="text-input"
                placeholder="Add participant (npub)"
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
              <button class="btn" data-testid="participant-add" on:click={() => onAddParticipant(network.id)}>
                Add
              </button>
            </div>

            <div class="stack rows">
              {#each network.participants as participant}
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
                    </div>
                  </div>
                  <span class={`badge ${participant.state === 'online' ? 'ok' : participant.state === 'offline' ? 'bad' : participant.state === 'local' ? 'muted' : 'warn'}`}>
                    <span data-testid="participant-state">{participant.state}</span>
                  </span>
                  <button
                    class="btn ghost icon-btn"
                    data-testid="participant-remove"
                    title="Delete participant"
                    aria-label="Delete participant"
                    on:click={() => runAction(() => removeParticipant(network.id, participant.npub))}
                  >
                    <Trash2 size={16} strokeWidth={2.2} />
                  </button>
                </div>
              {/each}
            </div>

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
                      <button class="btn" on:click={() => onAddLanPeer(network.id, peer.npub)}>Add</button>
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
          </section>
        {/each}
      </div>
    </section>

    <section class="panel">
      <div class="section-title-row">
        <h2>Relays</h2>
        <div class="section-meta relay-health">
          <span class="ok-text">{state.relaySummary.up}/{state.relays.length} connected</span>
        </div>
      </div>

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
    </section>

    <section class="panel">
      <div class="section-title-row">
        <h2>Session & Node</h2>
      </div>

      <div class="row spread settings-action-row">
        <div class="config-path">Config: {state.configPath}</div>
        {#if state.sessionActive}
          <button
            class="btn bad"
            data-testid="disconnect-session"
            on:click={() => runAction(disconnectSession)}
          >
            Disconnect
          </button>
        {:else}
          <button class="btn" data-testid="connect-session" on:click={() => runAction(connectSession)}>
            Connect
          </button>
        {/if}
      </div>
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
    </section>
  {/if}
</main>
