<script lang="ts">
  import { onDestroy, onMount } from 'svelte'

  export let waitForNextPaint: (targetWindow: Window) => Promise<void>
  export let refresh: () => Promise<void>
  export let initializeDeepLinkHandling: () => Promise<void>
  export let markBootReady: () => void
  export let refreshAutostart: () => Promise<void>
  export let tickLanPairingCountdown: () => void

  let pollHandle: number | null = null
  let lanPairingTickHandle: number | null = null
  let disposed = false

  onMount(() => {
    lanPairingTickHandle = window.setInterval(tickLanPairingCountdown, 1000)

    void (async () => {
      await waitForNextPaint(window)
      if (disposed) {
        return
      }

      await refresh()
      if (disposed) {
        return
      }

      await initializeDeepLinkHandling()
      if (disposed) {
        return
      }

      markBootReady()
      await refreshAutostart()
      if (disposed) {
        return
      }

      pollHandle = window.setInterval(refresh, 1500)
    })()
  })

  onDestroy(() => {
    disposed = true
    if (pollHandle) {
      window.clearInterval(pollHandle)
    }
    if (lanPairingTickHandle) {
      window.clearInterval(lanPairingTickHandle)
    }
  })
</script>
