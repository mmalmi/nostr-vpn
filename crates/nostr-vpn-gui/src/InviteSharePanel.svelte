<script lang="ts">
  import { Check, Copy } from 'lucide-svelte'

  import {
    inviteInviterParticipant,
    joinRequestButtonLabel,
    joinRequestStatusText,
    networkHasParticipant,
  } from './lib/app-view'
  import type { LanPeerView, NetworkView, UiState } from './lib/types'

  export let state: UiState
  export let activeNetworkView: NetworkView
  export let inviteQrDataUrl = ''
  export let inviteQrError = ''
  export let inviteInputDraft = ''
  export let inviteScanOpen = false
  export let inviteScanStatus = ''
  export let inviteScanError = ''
  export let participantInputDrafts: Record<string, string>
  export let participantAddAliasDrafts: Record<string, string>
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
  export let onRequestNetworkJoin: (networkId: string) => Promise<void>
  export let onInviteInput: (event: Event) => void
  export let onInvitePaste: (event: ClipboardEvent) => void
  export let onImportInvite: () => Promise<void>
  export let onStartInviteScan: () => Promise<void>
  export let onChooseInviteQrImage: () => void
  export let onCloseInviteScan: () => void
  export let onInviteScanFileSelected: (event: Event) => Promise<void>
  export let onAddParticipant: (networkId: string) => Promise<void>
  export let inviteScanInput: HTMLInputElement | null = null
  export let inviteScanVideo: HTMLVideoElement | null = null

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

<div class="participant-add-panel network-onboarding-panel">
  <div class="participant-add-label">Add devices</div>
  <div class="invite-help">
    Fastest: paste an invite from another device. LAN pairing can also broadcast yours nearby for 15 minutes.
  </div>
  {#if !activeNetworkView.localIsAdmin}
    <div class="config-path">Only admins can change the participant list for this network.</div>
  {/if}
  {#if activeNetworkView.inviteInviterNpub}
    <div class="mesh-share-actions">
      <button
        class="btn"
        data-testid="request-network-join"
        on:click={() => onRequestNetworkJoin(activeNetworkView.id)}
        disabled={
          Boolean(activeNetworkView.outboundJoinRequest) ||
          inviteInviterParticipant(activeNetworkView)?.state === 'online'
        }
      >
        {joinRequestButtonLabel(activeNetworkView)}
      </button>
      {#if activeNetworkView.outboundJoinRequest}
        <span class="badge warn">
          Requested {activeNetworkView.outboundJoinRequest.requestedAtText}
        </span>
      {:else if inviteInviterParticipant(activeNetworkView)?.state === 'online'}
        <span class="badge ok">Connected</span>
      {/if}
    </div>
    <div class="config-path">{joinRequestStatusText(activeNetworkView)}</div>
  {/if}
  <div class="invite-import-fields">
    <input
      class="text-input invite-import-input"
      placeholder="nvpn://invite/..."
      data-testid="invite-input"
      value={inviteInputDraft}
      on:input={onInviteInput}
      on:paste={onInvitePaste}
      on:keydown={(event) => event.key === 'Enter' && onImportInvite()}
    />
  </div>
  <div class="invite-scan-actions">
    <button class="btn" data-testid="invite-scan-start" on:click={onStartInviteScan}>
      Scan QR
    </button>
    <button class="btn" data-testid="invite-scan-image" on:click={onChooseInviteQrImage}>
      Choose Image
    </button>
    <input
      class="invite-scan-file-input"
      type="file"
      accept="image/*"
      capture="environment"
      bind:this={inviteScanInput}
      on:change={onInviteScanFileSelected}
    />
  </div>
  {#if inviteScanOpen}
    <div class="invite-scan-panel">
      <div class="invite-scan-preview">
        <video
          class="invite-scan-video"
          bind:this={inviteScanVideo}
          autoplay
          muted
          playsinline
        ></video>
        <div class="invite-scan-reticle" aria-hidden="true"></div>
      </div>
      <div class="invite-qr-caption">
        Point the camera at an invite QR. Use Cancel in the next prompt to just fill the field.
      </div>
      <button class="btn" data-testid="invite-scan-close" on:click={onCloseInviteScan}>
        Close Scanner
      </button>
    </div>
  {/if}
  {#if inviteScanStatus}
    <div class="config-path">{inviteScanStatus}</div>
  {/if}
  {#if inviteScanError}
    <div class="config-path mesh-id-note-error">{inviteScanError}</div>
  {/if}
  <div class="participant-add-separator">or add one manually</div>
  <div class="participant-add-fields">
    <input
      class="text-input participant-add-npub"
      placeholder="Participant npub"
      data-testid="participant-input"
      disabled={!activeNetworkView.localIsAdmin}
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
      disabled={!activeNetworkView.localIsAdmin}
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
      disabled={!activeNetworkView.localIsAdmin}
      on:click={() => onAddParticipant(activeNetworkView.id)}
    >
      Add
    </button>
  </div>
</div>
