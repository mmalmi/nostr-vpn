import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const appSource = readFileSync(new URL('../App.svelte', import.meta.url), 'utf8')
const cssSource = readFileSync(new URL('../app.css', import.meta.url), 'utf8')

test('identity card renders the full own npub value', () => {
  assert.match(appSource, /\{state\.ownNpub\}/)
  assert.doesNotMatch(appSource, /short\(state\.ownNpub,\s*18,\s*14\)/)
})

test('identity card pubkey styling wraps instead of truncating', () => {
  assert.match(
    cssSource,
    /\.hero-copy-value\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;[^}]*user-select:\s*text;/s,
  )
})

test('identity card uses compact info-sized pubkey text', () => {
  assert.match(cssSource, /\.hero-copy-value\s*\{[^}]*font-size:\s*12px;/s)
})

test('peer rows render full npub text with copy actions', () => {
  assert.match(appSource, /data-testid="participant-npub"/)
  assert.match(appSource, /data-testid="copy-peer-npub"/)
  assert.match(appSource, /copyPeerNpub\(participant\.npub\)/)
})
