<script lang="ts">
  import { Check, Copy } from 'lucide-svelte'

  import {
    activeNetwork,
    heroBadgeText,
    heroDetailText,
    heroStateBadgeClass,
    heroSubtext,
    platformLabel,
    selectedExitNodeBadgeClass,
    selectedExitNodeBadgeText,
  } from './lib/app-view'
  import { nodeNameDnsPreview } from './lib/node-name.js'
  import type { SettingsPatch, UiState } from './lib/types'

  export let state: UiState | null = null
  export let nodeNameDraft = ''
  export let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  export let vpnControlSupported = false
  export let serviceSetupRequired = false
  export let sessionToggleDisabled = false
  export let onToggleSession: () => Promise<void>
  export let copyPubkey: () => Promise<void>
  export let onUpdateSettings: (patch: SettingsPatch) => Promise<void>
  export let debounce: (key: string, fn: () => Promise<void>, delay?: number) => void

  const nodeNamePreviewText = (nodeName: string, currentState: UiState) => {
    if (nodeName.trim() === currentState.nodeName.trim()) {
      return currentState.selfMagicDnsName
        ? `Shared as ${currentState.selfMagicDnsName}`
        : 'Shared name has no DNS-safe .nvpn label yet.'
    }

    const preview = nodeNameDnsPreview(nodeName, currentState.magicDnsSuffix)
    return preview ? `Will share as ${preview}` : 'Shared name has no DNS-safe .nvpn label yet.'
  }
</script>

<section class="identity-card panel hero-card">
  {#if state}
    {@const activeNetworkView = activeNetwork(state)}
    <div class="row hero-row">
      <div class="hero-copy">
        <div class="panel-kicker">Status</div>
        <div class="row hero-title-row">
          <h1 data-testid="active-network-title">{activeNetworkView.name}</h1>
          {#if activeNetworkView.localIsAdmin}
            <span class="badge ok" data-testid="active-network-admin-badge">Admin</span>
          {/if}
          <span class={`badge ${heroStateBadgeClass(state)}`}>
            {heroBadgeText(state)}
          </span>
        </div>
        <div class="hero-subtitle">{heroSubtext(state)}</div>
      </div>
      {#if vpnControlSupported && !serviceSetupRequired}
        <button
          class={`session-switch ${state.sessionActive ? 'on' : 'off'}`}
          role="switch"
          aria-checked={state.sessionActive}
          aria-label="Toggle VPN session"
          data-testid="session-toggle"
          on:click={() => onToggleSession()}
          disabled={sessionToggleDisabled}
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
        <div class="hero-identity-row">
          <div class="copy-value hero-copy-value" data-testid="pubkey">
            {state.ownNpub}
          </div>
          <button
            class="btn icon-btn hero-copy-icon-btn"
            type="button"
            aria-label="Copy npub"
            title="Copy npub"
            data-testid="copy-pubkey"
            on:click={() => copyPubkey()}
          >
            <span class="copy-icon" aria-hidden="true">
              {#if copiedValue === 'pubkey'}
                <Check size={16} strokeWidth={2.3} />
              {:else}
                <Copy size={16} strokeWidth={2.2} />
              {/if}
            </span>
          </button>
        </div>
      </div>

      <div class="hero-stat-card hero-device-card">
        <div class="panel-kicker">This device</div>
        <input
          class="text-input hero-device-name-input"
          data-testid="node-name-input"
          bind:value={nodeNameDraft}
          on:input={() => debounce('nodeName', () => onUpdateSettings({ nodeName: nodeNameDraft }))}
        />
        <div class="config-path hero-device-preview">{nodeNamePreviewText(nodeNameDraft, state)}</div>
        <div class="config-path">{state.tunnelIp} • {state.endpoint}</div>
      </div>
    </div>

    <div class="row status-row">
      {#if vpnControlSupported}
        <span class={`badge ${state.daemonRunning ? 'ok' : 'bad'}`}>
          Daemon {state.daemonRunning ? 'Running' : 'Stopped'}
        </span>
        <span class={`badge ${state.sessionActive ? 'ok' : 'bad'}`}>
          VPN {state.sessionActive ? 'On' : 'Off'}
        </span>
        <span class={`badge ${state.relayConnected ? 'ok' : 'muted'}`}>
          Relays {state.relayConnected ? 'Connected' : 'Disconnected'}
        </span>
        {#if state.exitNode}
          <span
            class={`badge ${selectedExitNodeBadgeClass(state)}`}
            data-testid="exit-node-badge"
          >
            {selectedExitNodeBadgeText(state)}
          </span>
        {/if}
      {:else}
        <span class="badge muted">Platform {platformLabel(state.platform)}</span>
        <span class="badge muted">Config editing enabled</span>
        <span class="badge muted">Tunnel control unavailable</span>
      {/if}
    </div>
    {#if heroDetailText(state)}
      <div class="identity-status" data-testid="session-status-text">
        {heroDetailText(state)}
      </div>
    {/if}
  {:else}
    <div class="panel-kicker">Loading</div>
    <div class="row hero-title-row">
      <h1>Starting Nostr VPN</h1>
    </div>
    <div class="hero-subtitle">Loading config, daemon state, and local mesh status.</div>
  {/if}
</section>
