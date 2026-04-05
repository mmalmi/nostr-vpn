<script lang="ts">
  import { Check, Copy, Trash2 } from 'lucide-svelte'

  import SavedNetworkParticipantRow from './SavedNetworkParticipantRow.svelte'
  import type { NetworkView, UiState } from './lib/types'

  export let state: UiState
  export let network: NetworkView
  export let networkNameDrafts: Record<string, string>
  export let networkIdDrafts: Record<string, string>
  export let participantInputDrafts: Record<string, string>
  export let participantAddAliasDrafts: Record<string, string>
  export let participantAliasDrafts: Record<string, string>
  export let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  export let copiedPeerNpub: string | null = null
  export let formatMeshIdForDisplay: (value: string) => string
  export let formatMeshIdDraftForDisplay: (value: string, current: string) => string
  export let networkPeerSummary: (network: NetworkView) => string
  export let networkAdminSummary: (network: NetworkView) => string
  export let meshIdDraftError: (networkId: string) => string
  export let meshIdHelperText: (networkId: string, currentMeshId: string) => string
  export let onNetworkNameInput: (networkId: string, value: string) => void
  export let onNetworkMeshIdInput: (networkId: string, value: string) => void
  export let commitNetworkMeshId: (networkId: string, value: string) => Promise<void>
  export let onToggleJoinRequests: (networkId: string, enabled: boolean) => Promise<void>
  export let copyPeerNpub: (npub: string) => Promise<void>
  export let onAcceptJoinRequest: (networkId: string, requesterNpub: string) => Promise<void>
  export let onAddParticipant: (networkId: string) => Promise<void>
  export let onRequestNetworkJoin: (networkId: string) => Promise<void>
  export let onRemoveParticipant: (networkId: string, npub: string) => Promise<void>
  export let onParticipantAliasInput: (
    participantNpub: string,
    participantHex: string,
    value: string,
  ) => void
  export let runAction: (action: () => Promise<void>) => Promise<void>
  export let removeNetwork: (networkId: string) => Promise<void>
  export let setNetworkEnabled: (networkId: string, enabled: boolean) => Promise<void>
</script>

<section class="network-card" data-testid="network-card">
  <div class="row spread network-header">
    <div class="network-directory-main">
      <div class="row network-directory-title-row">
        <div class="item-title">{network.name}</div>
        <span class="badge muted">Saved</span>
        {#if network.localIsAdmin}
          <span class="badge ok" data-testid="saved-network-admin-badge">Admin</span>
        {/if}
        {#if network.inboundJoinRequests.length > 0}
          <span class="badge warn">
            {network.inboundJoinRequests.length} request{network.inboundJoinRequests.length === 1 ? '' : 's'}
          </span>
        {/if}
      </div>
      <div class="config-path" data-testid="network-mesh-id">
        Mesh ID: {formatMeshIdForDisplay(network.networkId)}
      </div>
      <div class="config-path">{networkPeerSummary(network)}</div>
    </div>

    <div class="row network-actions">
      <button
        class="btn ghost"
        data-testid="network-enabled-toggle"
        on:click={() => setNetworkEnabled(network.id, true)}
      >
        Activate
      </button>
      <button
        class="btn ghost icon-btn"
        data-testid="network-remove"
        title="Delete network"
        aria-label="Delete network"
        disabled={state.networks.filter((candidate) => !candidate.enabled).length <= 1}
        on:click={() => runAction(() => removeNetwork(network.id))}
      >
        <Trash2 size={16} strokeWidth={2.2} />
      </button>
    </div>
  </div>

  <details class="network-editor">
    <summary class="network-editor-summary">Edit saved network</summary>
    <div class="participant-add-panel network-profile-editor">
      <div class="participant-add-label">Profile</div>
      <div class="spotlight-profile-fields">
        <label class="field-label" for={`saved-network-name-${network.id}`}>Name</label>
        <input
          id={`saved-network-name-${network.id}`}
          class="text-input active-network-name-input"
          data-testid="network-name-input"
          value={networkNameDrafts[network.id] ?? network.name}
          on:input={(event) =>
            onNetworkNameInput(network.id, (event.currentTarget as HTMLInputElement).value)}
        />
        <label class="field-label" for={`saved-network-mesh-${network.id}`}>Mesh ID</label>
        <input
          id={`saved-network-mesh-${network.id}`}
          class={`text-input network-mesh-id-input ${meshIdDraftError(network.id) ? 'text-input-invalid' : ''}`}
          data-testid="saved-network-mesh-id-input"
          value={formatMeshIdDraftForDisplay(networkIdDrafts[network.id] ?? '', network.networkId)}
          on:input={(event) =>
            onNetworkMeshIdInput(network.id, (event.currentTarget as HTMLInputElement).value)}
          on:blur={(event) =>
            commitNetworkMeshId(network.id, (event.currentTarget as HTMLInputElement).value)}
          on:keydown={(event) =>
            event.key === 'Enter' &&
            commitNetworkMeshId(network.id, (event.currentTarget as HTMLInputElement).value)}
        />
      </div>
      <div class={`config-path ${meshIdDraftError(network.id) ? 'mesh-id-note-error' : ''}`}>
        {meshIdHelperText(network.id, network.networkId)}
      </div>
      <div class="config-path saved-network-note">
        Activate this saved network when you want to switch the current mesh to it.
      </div>
      <div class="config-path" data-testid="network-admin-summary">
        {networkAdminSummary(network)}
      </div>
    </div>

    <div class="participant-add-panel">
      <div class="participant-add-label">Join requests</div>
      <label class="toggle-row">
        <input
          type="checkbox"
          checked={network.joinRequestsEnabled}
          disabled={!network.localIsAdmin}
          on:change={(event) =>
            onToggleJoinRequests(network.id, (event.currentTarget as HTMLInputElement).checked)}
        />
        <div>Listen for join requests</div>
      </label>
      <div class="config-path">
        Join requests from invite holders will appear here, even when this mesh is not active.
      </div>
      {#if network.inboundJoinRequests.length > 0}
        <div class="stack rows">
          {#each network.inboundJoinRequests as request}
            <div class="item-row">
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
                disabled={!network.localIsAdmin}
                on:click={() => onAcceptJoinRequest(network.id, request.requesterNpub)}
              >
                Accept
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="participant-add-panel network-onboarding-panel">
      <div class="participant-add-label">Add devices</div>
      <div class="invite-help">
        Fastest: paste an invite from another device. LAN pairing can also broadcast yours nearby for 15 minutes.
      </div>
      {#if !network.localIsAdmin}
        <div class="config-path">Only admins can change the participant list for this network.</div>
      {/if}
      {#if network.inviteInviterNpub}
        <div class="mesh-share-actions">
          <button
            class="btn"
            data-testid="request-network-join"
            on:click={() => onRequestNetworkJoin(network.id)}
          >
            Request Join
          </button>
        </div>
        <div class="config-path">Imported from {network.inviteInviterNpub}.</div>
      {/if}
      <div class="participant-add-separator">or add one manually</div>
      <div class="participant-add-fields">
        <input
          class="text-input participant-add-npub"
          placeholder="Participant npub"
          data-testid="participant-input"
          disabled={!network.localIsAdmin}
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
          disabled={!network.localIsAdmin}
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
          disabled={!network.localIsAdmin}
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
          <SavedNetworkParticipantRow
            magicDnsSuffix={state.magicDnsSuffix}
            networkLocalIsAdmin={network.localIsAdmin}
            networkId={network.id}
            {participant}
            {participantAliasDrafts}
            {copiedValue}
            {copiedPeerNpub}
            {copyPeerNpub}
            {onParticipantAliasInput}
            {onRemoveParticipant}
          />
        {/each}
      </div>
    {/if}
  </details>
</section>
