<script lang="ts">
  import { sendFile } from './api';
  export let npub: string;
  export let disabled = false;
  export let onChanged: () => void = () => {};
  let picker: HTMLInputElement;
  let busy = false;
  let error = '';
  async function send(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    input.value = '';
    if (!files.length) return;
    const recipient = npub;
    busy = true;
    error = '';
    try {
      for (const file of files) { await sendFile(recipient, file); onChanged(); }
    } catch (reason) { error = reason instanceof Error ? reason.message : 'Could not send files'; }
    finally { busy = false; }
  }
</script>

<input bind:this={picker} type="file" multiple hidden on:change={send} aria-label="Files to send" />
<button type="button" class="small-button" disabled={disabled || busy} on:click={() => picker.click()}>
  {busy ? 'Preparing files…' : 'Send files'}
</button>
{#if error}<p role="alert">{error}</p>{/if}
