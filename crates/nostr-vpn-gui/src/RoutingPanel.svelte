<script lang="ts">
  import {
    additionalRoutesStatusText,
    exitNodeAvailabilityClass,
    exitNodeAvailabilityText,
    filteredExitNodeCandidates,
    offerExitNodeStatusText,
    routingModeStatusText,
    routingSectionMetaText,
    selectedExitNodeStatusText,
  } from './lib/app-view'
  import type { SettingsPatch, UiState } from './lib/types'

  export let state: UiState
  export let advertisedRoutesDraft = ''
  export let exitNodeSearch = ''
  export let onAdvertisedRoutesInput: (value: string) => void
  export let onUpdateSettings: (patch: SettingsPatch) => Promise<void>
  export let onSelectExitNode: (npub: string) => Promise<void>

  $: exitNodeCandidates = filteredExitNodeCandidates(state, exitNodeSearch)
</script>

<section class="panel exit-node-panel">
  <div class="section-title-row">
    <div>
      <div class="panel-kicker">Routing</div>
      <h2>Routing & Sharing</h2>
    </div>
    <div class="section-meta">{routingSectionMetaText(state)}</div>
  </div>

  <div class="field-grid">
    <div class="field-panel">
      <div class="field-label">Current Mode</div>
      <div class="config-path">{routingModeStatusText(state)}</div>
    </div>

    <div class="field-panel">
      <label class="toggle-row">
        <input
          type="checkbox"
          checked={state.advertiseExitNode}
          on:change={(event) =>
            onUpdateSettings({
              advertiseExitNode: (event.currentTarget as HTMLInputElement).checked,
            })}
        />
        <div>Advertise this device as a private exit node</div>
      </label>
      <div class="config-path settings-note">{offerExitNodeStatusText(state)}</div>
    </div>

    <label class="field-span">
      <span>Advertised Routes</span>
      <input
        class="text-input"
        placeholder="10.0.0.0/24, 192.168.0.0/24"
        value={advertisedRoutesDraft}
        on:input={(event) =>
          onAdvertisedRoutesInput((event.currentTarget as HTMLInputElement).value)}
      />
      <div class="config-path">{additionalRoutesStatusText(state)}</div>
    </label>

    <div class="field-span field-panel exit-node-panel-body">
      <div class="field-label">Use A Peer Exit Node</div>
      <div class="config-path">{selectedExitNodeStatusText(state)}</div>
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

        {#each exitNodeCandidates as participant}
          <button
            class={`exit-node-card ${state.exitNode === participant.npub ? 'selected' : ''} ${
              !participant.offersExitNode ? 'disabled' : ''
            }`}
            type="button"
            on:click={() => onSelectExitNode(participant.npub)}
            disabled={!participant.offersExitNode}
          >
            <div class="row spread">
              <div class="item-title">
                {participant.magicDnsName || participant.magicDnsAlias || participant.npub}
              </div>
              <span class={`badge ${exitNodeAvailabilityClass(participant)}`}>
                {exitNodeAvailabilityText(participant)}
              </span>
            </div>
            <div class="item-sub">
              {participant.npub} | {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
            </div>
          </button>
        {/each}

        {#if exitNodeCandidates.length === 0}
          <div class="config-path">No peers match that search.</div>
        {/if}
      </div>
    </div>
  </div>
</section>
