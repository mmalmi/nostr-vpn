<script lang="ts">
  import { Check, Copy, Trash2 } from 'lucide-svelte'

  import InviteShareSection from './InviteShareSection.svelte'
  import {
    formatMeshIdDraftForDisplay,
  } from './lib/mesh-id.js'
  import {
    lanPairingHelpText,
    networkAdminSummary,
    networkPeerSummary,
    onlineDeviceSummary,
    participantBadgeClass,
    participantPresenceBadgeText,
    participantTrafficText,
    participantTransportBadgeText,
  } from './lib/app-view'
  import type { NetworkView, UiState } from './lib/types'

  export let state: UiState
  export let activeNetworkView: NetworkView
  export let networkNameDrafts: Record<string, string>
  export let networkIdDrafts: Record<string, string>
  export let participantInputDrafts: Record<string, string>
  export let participantAddAliasDrafts: Record<string, string>
  export let participantAliasDrafts: Record<string, string>
  export let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  export let copiedPeerNpub: string | null = null
  export let lanPairingDisplayRemainingSecs = 0
  export let formatCountdown: (seconds: number) => string
  export let copyMeshId: () => Promise<void>
  export let copyInvite: () => Promise<void>
  export let copyPeerNpub: (npub: string) => Promise<void>
  export let onNetworkNameInput: (networkId: string, value: string) => void
  export let onNetworkMeshIdInput: (networkId: string, value: string) => void
  export let commitNetworkMeshId: (networkId: string, value: string) => Promise<void>
  export let meshIdDraftError: (networkId: string) => string
  export let meshIdHelperText: (networkId: string, currentMeshId: string) => string
  export let onToggleJoinRequests: (networkId: string, enabled: boolean) => Promise<void>
  export let onAcceptJoinRequest: (networkId: string, requesterNpub: string) => Promise<void>
  export let onStartLanPairing: () => Promise<void>
  export let onStopLanPairing: () => Promise<void>
  export let onJoinLanPeer: (invite: string) => Promise<void>
  export let onRequestNetworkJoin: (networkId: string) => Promise<void>
  export let onAddParticipant: (networkId: string) => Promise<void>
  export let onParticipantAliasInput: (participantNpub: string, participantHex: string, value: string) => void
  export let onToggleAdmin: (networkId: string, participant: NetworkView['participants'][number]) => Promise<void>
  export let onRemoveParticipant: (networkId: string, npub: string) => Promise<void>
  export let onImportInviteCode: (invite: string, options?: { autoConnectOnSuccess?: boolean }) => Promise<boolean>
</script>

<section class="panel spotlight-panel">
  <div class="section-title-row">
    <div>
      <div class="panel-kicker">Active network</div>
      <h2>{activeNetworkView.name}</h2>
    </div>
    <div class="section-meta">
      {onlineDeviceSummary(activeNetworkView.onlineCount, activeNetworkView.expectedCount)}
    </div>
  </div>

  <div class="spotlight-meta-grid">
    <div class="spotlight-meta-card spotlight-profile-card">
      <div class="panel-kicker">Profile</div>
      <div class="spotlight-profile-fields">
        <label class="field-label" for={`active-network-name-${activeNetworkView.id}`}>Name</label>
        <input
          id={`active-network-name-${activeNetworkView.id}`}
          class="text-input active-network-name-input"
          data-testid="network-name-input"
          value={networkNameDrafts[activeNetworkView.id] ?? activeNetworkView.name}
          disabled={!activeNetworkView.localIsAdmin}
          on:input={(event) =>
            onNetworkNameInput(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
        />
        <label class="field-label" for={`active-network-mesh-${activeNetworkView.id}`}>Mesh ID</label>
        <div class="inline-copy-field">
          <input
            id={`active-network-mesh-${activeNetworkView.id}`}
            class={`text-input network-mesh-id-input ${meshIdDraftError(activeNetworkView.id) ? 'text-input-invalid' : ''}`}
            data-testid="active-network-mesh-id-input"
            value={formatMeshIdDraftForDisplay(
              networkIdDrafts[activeNetworkView.id] ?? '',
              activeNetworkView.networkId,
            )}
            disabled={!activeNetworkView.localIsAdmin}
            on:input={(event) =>
              onNetworkMeshIdInput(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
            on:blur={(event) =>
              commitNetworkMeshId(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
            on:keydown={(event) =>
              event.key === 'Enter' &&
              commitNetworkMeshId(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
          />
          <button class="btn copy-btn" data-testid="copy-mesh-id" on:click={() => copyMeshId()}>
            <span class="copy-icon" aria-hidden="true">
              {#if copiedValue === 'meshId'}
                <Check size={16} strokeWidth={2.3} />
              {:else}
                <Copy size={16} strokeWidth={2.2} />
              {/if}
            </span>
            <span>{copiedValue === 'meshId' ? 'Copied' : 'Copy Mesh ID'}</span>
          </button>
        </div>
        <div class={`config-path ${meshIdDraftError(activeNetworkView.id) ? 'mesh-id-note-error' : ''}`}>
          {meshIdHelperText(activeNetworkView.id, activeNetworkView.networkId)}
        </div>
        {#if !activeNetworkView.localIsAdmin}
          <div class="config-path">
            Only admins can rename this network, change its Mesh ID, or rename participants.
          </div>
        {/if}
      </div>
      <div class="config-path">{networkPeerSummary(activeNetworkView)}</div>
      <div class="config-path">
        Stable identifier used for tunnel addressing and matching the right mesh.
      </div>
    </div>
    <div class="spotlight-meta-card spotlight-share-card">
      <div class="panel-kicker">Join & share</div>
      <div class="spotlight-meta-value">Copy, scan, or pair</div>
      <div class="config-path">
        Includes the Mesh ID, your npub, and the relay list for {activeNetworkView.name}.
      </div>
      <div class="config-path" data-testid="network-admin-summary">
        {networkAdminSummary(activeNetworkView)}
      </div>
      <label class="toggle-row">
        <input
          type="checkbox"
          checked={activeNetworkView.joinRequestsEnabled}
          disabled={!activeNetworkView.localIsAdmin}
          on:change={(event) =>
            onToggleJoinRequests(
              activeNetworkView.id,
              (event.currentTarget as HTMLInputElement).checked,
            )}
        />
        <div>Listen for join requests</div>
      </label>
      <div class="config-path">
        Join requests from invite holders will appear here.
      </div>
      {#if activeNetworkView.inboundJoinRequests.length > 0}
        <div class="lan-title">Pending join requests</div>
        <div class="stack rows">
          {#each activeNetworkView.inboundJoinRequests as request}
            <div class="item-row" data-testid="join-request-row">
              <div class="item-main">
                <div class="item-title">
                  {request.requesterNodeName || 'Pending device'}
                </div>
                <div class="peer-npub-row">
                  <div class="peer-npub-text">{request.requesterNpub}</div>
                  <button
                    class="btn ghost icon-btn peer-npub-copy-btn"
                    type="button"
                    aria-label="Copy peer npub"
                    title="Copy peer npub"
                    data-testid="copy-peer-npub"
                    on:click={() => copyPeerNpub(request.requesterNpub)}
                  >
                    <span class="copy-icon" aria-hidden="true">
                      {#if copiedValue === 'peerNpub' && copiedPeerNpub === request.requesterNpub}
                        <Check size={16} strokeWidth={2.3} />
                      {:else}
                        <Copy size={16} strokeWidth={2.2} />
                      {/if}
                    </span>
                  </button>
                </div>
                <div class="item-sub">
                  requested {request.requestedAtText}
                </div>
              </div>
              <button
                class="btn"
                data-testid="accept-join-request"
                disabled={!activeNetworkView.localIsAdmin}
                on:click={() => onAcceptJoinRequest(activeNetworkView.id, request.requesterNpub)}
              >
                Accept
              </button>
            </div>
          {/each}
        </div>
      {/if}
      <InviteShareSection
        {state}
        {activeNetworkView}
        {participantInputDrafts}
        {participantAddAliasDrafts}
        {copiedValue}
        {copiedPeerNpub}
        {lanPairingDisplayRemainingSecs}
        {formatCountdown}
        {copyInvite}
        {copyPeerNpub}
        {onStartLanPairing}
        {onStopLanPairing}
        {onJoinLanPeer}
        {onRequestNetworkJoin}
        {onAddParticipant}
        {lanPairingHelpText}
        onImportInviteCode={onImportInviteCode}
      />
    </div>
  </div>

  {#if activeNetworkView.participants.length === 0}
    <div class="item-row network-empty-state">
      <div class="item-main">
        <div class="item-title">No devices yet</div>
        <div class="item-sub">Import an invite, start LAN pairing, or add a participant npub to start building the active mesh.</div>
      </div>
    </div>
  {:else}
    <div class="stack rows">
      {#each activeNetworkView.participants as participant}
        <div class="item-row" data-testid="participant-row">
          <div class="item-main">
            <div class="peer-npub-row">
              <div class="peer-npub-text" data-testid="participant-npub">{participant.npub}</div>
              <button
                class="btn ghost icon-btn peer-npub-copy-btn"
                type="button"
                aria-label="Copy peer npub"
                title="Copy peer npub"
                data-testid="copy-peer-npub"
                on:click={() => copyPeerNpub(participant.npub)}
              >
                <span class="copy-icon" aria-hidden="true">
                  {#if copiedValue === 'peerNpub' && copiedPeerNpub === participant.npub}
                    <Check size={16} strokeWidth={2.3} />
                  {:else}
                    <Copy size={16} strokeWidth={2.2} />
                  {/if}
                </span>
              </button>
            </div>
            <div class="row alias-row">
              <input
                class="text-input alias-input"
                value={participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias}
                data-testid="participant-alias-input"
                disabled={!activeNetworkView.localIsAdmin}
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
              {participant.magicDnsName || participant.magicDnsAlias || 'No alias'} | {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
              | {participantTrafficText(participant)}
              {#if participant.relayPathActive && participant.runtimeEndpoint}
                | relay {participant.runtimeEndpoint}
              {/if}
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
            {#if participant.isAdmin}
              <span class="badge participant-badge ok" data-testid="participant-admin-badge">
                Admin
              </span>
            {/if}
            {#if participant.relayPathActive}
              <span class="badge participant-badge warn">Relay fallback</span>
            {/if}
            {#if participant.offersExitNode}
              <span class="badge participant-badge warn">Private exit</span>
            {/if}
            {#if state.exitNode === participant.npub}
              <span class="badge participant-badge ok">Selected exit</span>
            {/if}
          </div>
          {#if activeNetworkView.localIsAdmin}
            <button
              class="btn ghost"
              data-testid="participant-toggle-admin"
              on:click={() => onToggleAdmin(activeNetworkView.id, participant)}
            >
              {participant.isAdmin ? 'Remove admin' : 'Make admin'}
            </button>
          {/if}
          <button
            class="btn ghost icon-btn"
            data-testid="participant-remove"
            title="Delete participant"
            aria-label="Delete participant"
            disabled={!activeNetworkView.localIsAdmin}
            on:click={() => onRemoveParticipant(activeNetworkView.id, participant.npub)}
          >
            <Trash2 size={16} strokeWidth={2.2} />
          </button>
        </div>
      {/each}
    </div>
  {/if}
</section>
