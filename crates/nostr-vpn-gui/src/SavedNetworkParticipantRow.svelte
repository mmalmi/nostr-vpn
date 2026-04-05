<script lang="ts">
  import { Check, Copy, Trash2 } from 'lucide-svelte'

  export let magicDnsSuffix = ''
  export let networkLocalIsAdmin = false
  export let networkId: string
  export let participant: {
    npub: string
    pubkeyHex: string
    magicDnsAlias: string
    magicDnsName: string
    tunnelIp: string
    isAdmin: boolean
    offersExitNode: boolean
  }
  export let participantAliasDrafts: Record<string, string>
  export let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  export let copiedPeerNpub: string | null = null
  export let copyPeerNpub: (npub: string) => Promise<void>
  export let onParticipantAliasInput: (
    participantNpub: string,
    participantHex: string,
    value: string,
  ) => void
  export let onRemoveParticipant: (networkId: string, npub: string) => Promise<void>
</script>

<div class="item-row saved-participant-row">
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
        on:input={(event) =>
          onParticipantAliasInput(
            participant.npub,
            participant.pubkeyHex,
            (event.currentTarget as HTMLInputElement).value,
          )}
      />
      {#if magicDnsSuffix}
        <span class="alias-suffix">.{magicDnsSuffix}</span>
      {/if}
    </div>
    <div class="item-sub">
      {participant.magicDnsName || participant.magicDnsAlias || 'No alias'} | {participant.tunnelIp}
      {#if participant.isAdmin}
        | admin
      {/if}
      {#if participant.offersExitNode}
        | exit routes advertised
      {/if}
    </div>
  </div>
  <button
    class="btn ghost icon-btn"
    title="Delete participant"
    aria-label="Delete participant"
    disabled={!networkLocalIsAdmin}
    on:click={() => onRemoveParticipant(networkId, participant.npub)}
  >
    <Trash2 size={16} strokeWidth={2.2} />
  </button>
</div>
