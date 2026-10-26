<script lang="ts">
  import { fileAction, fileDownloadUrl, fileHistory } from './api';
  import { formatBytes } from './format';
  import type { FileTransfer } from './types';
  export let connected = true;
  export let transfers: FileTransfer[] = [];
  export let onChanged: () => void = () => {};
  let busy = '';
  let error = '';
  let history: FileTransfer[] = [];
  let nextCursor: string | null | undefined;
  let loadingHistory = false;
  $: liveIds = new Set(transfers.map(transfer => transfer.id));
  $: visibleTransfers = [...transfers, ...history.filter(transfer => !liveIds.has(transfer.id))];

  function statusText(transfer: FileTransfer): string {
    switch (transfer.status) {
      case 'queued': return connected ? 'Queued for sending' : 'Queued — connect VPN to send';
      case 'cancelling': return connected ? 'Cancelling…' : 'Cancellation queued';
      case 'declining': return connected ? 'Declining…' : 'Decline queued';
      case 'offered': return transfer.isSender ? 'Waiting for acceptance' : 'Wants to send you files';
      case 'preparing': return 'Preparing files…';
      case 'connecting': return 'Connecting…';
      case 'transferring': return transfer.isSender ? 'Sending…' : 'Receiving…';
      case 'paused': return connected ? 'Paused — ready to resume' : 'Paused — connect VPN to continue';
      case 'completed': return transfer.isSender ? 'Delivered' : 'Received';
      case 'cancelled': return 'Cancelled';
      case 'declined': return 'Declined';
      case 'failed': return 'Could not transfer files';
      default: return 'Waiting…';
    }
  }

  async function earlierFiles() {
    if (loadingHistory || nextCursor === null) return;
    loadingHistory = true; error = '';
    try {
      const knownIds = new Set(visibleTransfers.map(transfer => transfer.id));
      // The first history page can be the same 64 recent files already shown live.
      for (let request = 0; request < 2; request += 1) {
        const cursor: string | undefined = nextCursor ?? undefined;
        const page = await fileHistory(cursor);
        history = [...new Map([...history, ...page.transfers].map(transfer => [transfer.id, transfer])).values()];
        nextCursor = page.nextCursor;
        if (page.transfers.some(transfer => !knownIds.has(transfer.id)) || nextCursor === null || nextCursor === cursor) break;
      }
    } catch (reason) { error = reason instanceof Error ? reason.message : 'Could not load earlier files'; }
    finally { loadingHistory = false; }
  }
  async function act(id: string, action: 'accept' | 'decline' | 'cancel' | 'resume') {
    busy = id; error = '';
    try { await fileAction(id, action); onChanged(); }
    catch (reason) { error = reason instanceof Error ? reason.message : 'Could not update transfer'; }
    finally { busy = ''; }
  }
</script>

  <section class="detail-surface transfers" aria-label="File transfers">
    <div class="files-heading">
      <h3>Files</h3>
      {#if nextCursor !== null}
        <button class="small-button" disabled={loadingHistory} on:click={earlierFiles}>{loadingHistory ? 'Loading…' : 'Earlier files'}</button>
      {/if}
    </div>
    {#if !connected}<p class="muted-copy">Connect VPN to continue transfers.</p>{/if}
    {#if error}<p role="alert">{error}</p>{/if}
    {#if !visibleTransfers.length && nextCursor === null}<p class="muted-copy">No received files yet.</p>{/if}
    {#each visibleTransfers as transfer (transfer.id)}
      <div class="transfer">
        {#if transfer.status === 'unavailable'}
          <strong>Files unavailable</strong>
          <p role="alert">{transfer.error || 'Connect VPN to transfer files.'}</p>
        {:else}
        <strong>{transfer.files.map((file) => file.name).join(', ')}</strong>
        <div class="muted-copy">{transfer.isSender ? 'To' : 'From'} {transfer.peerName || transfer.peerNpub} · {formatBytes(transfer.totalBytes)}</div>
        <div class="status" role="status">{statusText(transfer)}</div>
        {#if ['preparing', 'connecting', 'transferring', 'paused'].includes(transfer.status)}
          <progress aria-label="Transfer progress" value={transfer.transferredBytes} max={Math.max(1, transfer.totalBytes)}></progress>
          <div class="muted-copy">{formatBytes(transfer.transferredBytes)} of {formatBytes(transfer.totalBytes)}</div>
        {/if}
        {#if transfer.error}<p role="alert">{transfer.error}</p>{/if}
        <div class="button-row">
          {#if transfer.status === 'offered' && !transfer.isSender}
            <button class="small-button primary" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'accept')}>Accept</button>
            <button class="small-button" disabled={busy === transfer.id} on:click={() => act(transfer.id, 'decline')}>Decline</button>
          {/if}
          {#if transfer.status === 'paused'}<button class="small-button" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'resume')}>Resume</button>{/if}
          {#if ['queued', 'offered', 'preparing', 'connecting', 'transferring', 'paused'].includes(transfer.status) && !(transfer.status === 'offered' && !transfer.isSender)}
            <button class="small-button" disabled={busy === transfer.id} on:click={() => act(transfer.id, 'cancel')}>Cancel</button>
          {/if}
          {#if transfer.status === 'completed' && !transfer.isSender}
            {#each transfer.files as file, index}<a class="small-button" href={fileDownloadUrl(transfer.id, index)} download={file.name}>Save {file.name}</a>{/each}
          {/if}
        </div>
        {/if}
      </div>
    {/each}
  </section>

<style>
  .transfers { margin: 16px; max-height: 260px; overflow: auto; gap: 4px; }
  h3 { margin: 0; }
  .files-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .transfer { padding: 8px 0; overflow-wrap: anywhere; }
  .transfer + .transfer { border-top: 1px solid var(--border, #8884); }
  progress { width: 100%; margin-top: 8px; }
  .status { margin: 6px 0; }
</style>
