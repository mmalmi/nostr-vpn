<script lang="ts">
  import { Check, Copy } from 'lucide-svelte'

  import { networkHasParticipant } from './lib/app-view'
  import type { LanPeerView, NetworkView, UiState } from './lib/types'

  export let state: UiState
  export let activeNetworkView: NetworkView
  export let inviteQrDataUrl = ''
  export let inviteQrError = ''
  export let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  export let copiedPeerNpub: string | null = null
  export let lanPairingDisplayRemainingSecs = 0
  export let lanPairingHelpText: (state: UiState) => string
  export let formatCountdown: (value: number) => string
  export let copyInvite: () => Promise<void>
  export let copyPeerNpub: (npub: string) => Promise<void>
  export let onStartLanPairing: () => Promise<void>
  export let onStopLanPairing: () => Promise<void>
  export let onJoinLanPeer: (invite: string) => Promise<void>

  $: lanJoinCandidates = state.lanPeers.filter(
    (peer: LanPeerView) => !networkHasParticipant(activeNetworkView, peer.npub),
  )
</script>

<div class="mesh-share-actions">
  <button class="btn copy-btn" data-testid="copy-network-invite" on:click={copyInvite}>
    <span class="copy-icon" aria-hidden="true">
      {#if copiedValue === 'invite'}
        <Check size={16} strokeWidth={2.3} />
      {:else}
        <Copy size={16} strokeWidth={2.2} />
      {/if}
    </span>
    <span>{copiedValue === 'invite' ? 'Copied' : 'Copy Invite'}</span>
  </button>
  <button
    class="btn"
    data-testid="lan-pairing-toggle"
    on:click={state.lanPairingActive ? onStopLanPairing : onStartLanPairing}
  >
    {state.lanPairingActive ? 'Stop LAN Pairing' : 'Start LAN Pairing'}
  </button>
  {#if state.lanPairingActive}
    <span class="badge warn lan-pairing-timer">
      {formatCountdown(lanPairingDisplayRemainingSecs)} left
    </span>
  {/if}
</div>

<div class="config-path">{lanPairingHelpText(state)}</div>
{#if inviteQrDataUrl}
  <div class="invite-qr-wrap">
    <img class="invite-qr" src={inviteQrDataUrl} alt={`Invite QR for ${activeNetworkView.name}`} />
  </div>
  <div class="invite-qr-caption">Scan on another device to join this mesh.</div>
{:else if inviteQrError}
  <div class="config-path">{inviteQrError}</div>
{/if}
{#if state.lanPairingActive}
  <div class="lan-title">Nearby pairing devices</div>
  {#if lanJoinCandidates.length === 0}
    <div class="config-path">Listening for invite broadcasts from nearby devices.</div>
  {:else}
    <div class="stack rows">
      {#each lanJoinCandidates as peer}
        <div class="item-row" data-testid="lan-peer-row">
          <div class="item-main">
            <div class="item-title">{peer.networkName || peer.nodeName || 'Nearby device'}</div>
            <div class="peer-npub-row">
              <div class="peer-npub-text">{peer.npub}</div>
              <button
                class="btn ghost icon-btn peer-npub-copy-btn"
                type="button"
                aria-label="Copy peer npub"
                title="Copy peer npub"
                data-testid="copy-peer-npub"
                on:click={() => copyPeerNpub(peer.npub)}
              >
                <span class="copy-icon" aria-hidden="true">
                  {#if copiedValue === 'peerNpub' && copiedPeerNpub === peer.npub}
                    <Check size={16} strokeWidth={2.3} />
                  {:else}
                    <Copy size={16} strokeWidth={2.2} />
                  {/if}
                </span>
              </button>
            </div>
            <div class="item-sub">
              {#if peer.networkName && peer.nodeName}
                {peer.nodeName} |
              {/if}
              {peer.endpoint} | seen {peer.lastSeenText}
            </div>
          </div>
          <button class="btn" on:click={() => onJoinLanPeer(peer.invite)}>Join</button>
        </div>
      {/each}
    </div>
  {/if}
{/if}
