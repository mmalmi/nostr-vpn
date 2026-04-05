<script lang="ts">
  import SavedNetworkCard from './SavedNetworkCard.svelte'
  import type { NetworkView, UiState } from './lib/types'

  export let state: UiState
  export let inactiveNetworks: NetworkView[] = []
  export let newNetworkName = ''
  export let networkNameDrafts: Record<string, string> = {}
  export let networkIdDrafts: Record<string, string> = {}
  export let participantInputDrafts: Record<string, string> = {}
  export let participantAddAliasDrafts: Record<string, string> = {}
  export let participantAliasDrafts: Record<string, string> = {}
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
  export let onAddNetwork: () => Promise<void>
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

<details class="panel collapsible-panel network-directory-panel">
  <summary class="collapsible-summary">
    <div>
      <div class="panel-kicker">Saved networks</div>
      <h2 data-testid="saved-networks-title">Other networks</h2>
    </div>
    <div class="section-meta">{inactiveNetworks.length} saved</div>
  </summary>

  <div class="collapsible-body">
    <div class="config-path">
      Keep alternate network profiles here. Activate one when you want to switch the current mesh.
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

    {#if inactiveNetworks.length === 0}
      <div class="item-row network-empty-state">
        <div class="item-main">
          <div class="item-title">No saved networks yet</div>
          <div class="item-sub">Add another network if you want a separate mesh profile.</div>
        </div>
      </div>
    {:else}
      <div class="stack rows network-stack">
        {#each inactiveNetworks as network}
          <SavedNetworkCard
            {state}
            {network}
            {networkNameDrafts}
            {networkIdDrafts}
            {participantInputDrafts}
            {participantAddAliasDrafts}
            {participantAliasDrafts}
            {copiedValue}
            {copiedPeerNpub}
            {formatMeshIdForDisplay}
            {formatMeshIdDraftForDisplay}
            {networkPeerSummary}
            {networkAdminSummary}
            {meshIdDraftError}
            {meshIdHelperText}
            {onNetworkNameInput}
            {onNetworkMeshIdInput}
            {commitNetworkMeshId}
            {onToggleJoinRequests}
            {copyPeerNpub}
            {onAcceptJoinRequest}
            {onAddParticipant}
            {onRequestNetworkJoin}
            {onRemoveParticipant}
            {onParticipantAliasInput}
            {runAction}
            {removeNetwork}
            {setNetworkEnabled}
          />
        {/each}
      </div>
    {/if}
  </div>
</details>
