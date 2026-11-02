<script lang="ts">
  import { onDestroy } from 'svelte';
  import { sendFile } from './api';
  import { formatBytes } from './format';
  export let npub: string;
  export let disabled = false;
  export let onChanged: () => void = () => {};
  let picker: HTMLInputElement;
  let busy = false;
  let error = '';
  let preparation = '';
  let controller: AbortController | undefined;
  onDestroy(() => controller?.abort());
  async function send(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    input.value = '';
    if (!files.length) return;
    if (files.length > 32) { error = 'Choose up to 32 files.'; return; }
    const recipient = npub;
    busy = true;
    error = '';
    const attempt = new AbortController();
    controller = attempt;
    try {
      for (const [index, file] of files.entries()) {
        if (attempt.signal.aborted) break;
        preparation = `Preparing ${index + 1} of ${files.length}: ${file.name} · ${formatBytes(file.size)}`;
        await sendFile(recipient, file, attempt.signal);
        onChanged();
      }
    } catch (reason) {
      if (!attempt.signal.aborted) error = reason instanceof Error ? reason.message : 'Could not send files';
    } finally { busy = false; controller = undefined; preparation = ''; }
  }
</script>

<input bind:this={picker} type="file" multiple hidden on:change={send} aria-label="Files to send" />
<button type="button" class="small-button" disabled={disabled || busy} on:click={() => picker.click()}>
  {busy ? 'Preparing files…' : 'Send files'}
</button>
{#if busy}
  <p class="muted-copy" role="status">{preparation}</p>
  <button type="button" class="small-button" on:click={() => controller?.abort()}>Cancel preparation</button>
{/if}
{#if error}<p role="alert">{error}</p>{/if}
