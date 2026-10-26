<script lang="ts">
  import { fileAction, fileDownloadUrl } from './api';
  import { formatBytes } from './format';
  import type { FileTransfer } from './types';
  export let connected = true;
  export let transfers: FileTransfer[] = [];
  export let onChanged: () => void = () => {};
  let busy = '';
  let error = '';
  async function act(id: string, action: 'accept' | 'decline' | 'cancel' | 'resume') {
    busy = id; error = '';
    try { await fileAction(id, action); onChanged(); }
    catch (reason) { error = reason instanceof Error ? reason.message : 'Could not update transfer'; }
    finally { busy = ''; }
  }
</script>

{#if transfers.length}
  <section class="detail-surface transfers" aria-label="File transfers">
    <h3>Files</h3>
    {#if !connected}<p class="muted-copy">Connect VPN to continue transfers.</p>{/if}
    {#if error}<p role="alert">{error}</p>{/if}
    {#each transfers as transfer (transfer.id)}
      <div class="transfer">
        {#if transfer.status === 'unavailable'}
          <strong>Files unavailable</strong>
          <p role="alert">{transfer.error || 'Connect VPN to transfer files.'}</p>
        {:else}
        <strong>{transfer.files.map((file) => file.name).join(', ')}</strong>
        <div class="muted-copy">{transfer.isSender ? 'To' : 'From'} {transfer.peerName || transfer.peerNpub} · {formatBytes(transfer.totalBytes)}</div>
        {#if ['connecting', 'transferring'].includes(transfer.status)}
          <progress aria-label="Transfer progress" value={transfer.transferredBytes} max={Math.max(1, transfer.totalBytes)}></progress>
          <div class="muted-copy">{formatBytes(transfer.transferredBytes)} / {formatBytes(transfer.totalBytes)}</div>
        {:else}<div class="status">{transfer.status === 'offered' ? (transfer.isSender ? 'Waiting for acceptance' : 'Wants to send you files') : transfer.status}</div>{/if}
        {#if transfer.error}<p role="alert">{transfer.error}</p>{/if}
        <div class="button-row">
          {#if transfer.status === 'offered' && !transfer.isSender}
            <button class="small-button primary" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'accept')}>Accept</button>
            <button class="small-button" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'decline')}>Decline</button>
          {/if}
          {#if transfer.status === 'paused'}<button class="small-button" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'resume')}>Resume</button>{/if}
          {#if ['offered', 'preparing', 'connecting', 'transferring', 'paused'].includes(transfer.status) && !(transfer.status === 'offered' && !transfer.isSender)}
            <button class="small-button" disabled={busy === transfer.id || !connected} on:click={() => act(transfer.id, 'cancel')}>Cancel</button>
          {/if}
          {#if transfer.status === 'completed' && !transfer.isSender}
            {#each transfer.files as file, index}<a class="small-button" href={fileDownloadUrl(transfer.id, index)} download={file.name}>Save {file.name}</a>{/each}
          {/if}
        </div>
        {/if}
      </div>
    {/each}
  </section>
{/if}

<style>
  .transfers { margin: 16px; max-height: 260px; overflow: auto; gap: 4px; }
  h3 { margin: 0; }
  .transfer { padding: 8px 0; overflow-wrap: anywhere; }
  .transfer + .transfer { border-top: 1px solid var(--border, #8884); }
  progress { width: 100%; margin-top: 8px; }
  .status { text-transform: capitalize; margin: 6px 0; }
</style>
