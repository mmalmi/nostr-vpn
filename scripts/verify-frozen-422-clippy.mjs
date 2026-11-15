#!/usr/bin/env node
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const commit = 'c09d4bf805779352bd7ccf9a6e7b7dc2477bbcfd'
const file = 'crates/nostr-vpn-cli/src/config_bootstrap.rs'
const expression = 'return nostr_vpn_core::platform_paths::linux_user_config_path();'

// The strict, immutable-source run 43763394581 reported this one style
// finding. Keep it visible while letting Clippy finish checking every target.
export function verifyDiagnostics(records, root) {
  let seen = 0
  let finished = false
  for (const item of records) {
    if (item.reason === 'build-finished') {
      assert.equal(item.success, true, 'Clippy did not complete every target')
      finished = true
    }
    if (item.reason !== 'compiler-message') continue
    const diagnostic = item.message
    if (!['warning', 'error', 'failure-note'].includes(diagnostic.level)) continue
    const primary = diagnostic.spans.filter((span) => span.is_primary)
    assert.equal(diagnostic.level, 'warning', diagnostic.rendered)
    assert.equal(diagnostic.code?.code, 'clippy::needless_return', diagnostic.rendered)
    assert.equal(diagnostic.message, 'unneeded `return` statement')
    assert.equal(item.target.name, 'nvpn')
    assert.deepEqual(item.target.kind, ['bin'])
    assert.equal(primary.length, 1)
    const [span] = primary
    assert.equal(resolve(root, span.file_name), resolve(root, file))
    assert.equal(span.line_start, 245)
    assert.equal(span.line_end, 245)
    assert.deepEqual(span.text.map((entry) => entry.text.trim()), [expression])
    seen++
  }
  assert.ok(finished && seen > 0, 'Missing completed build or the exact frozen-source finding')
}

function main() {
  const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim()
  assert.equal(process.platform, 'linux')
  assert.equal(git('rev-parse', 'HEAD'), commit)
  assert.equal(git('status', '--porcelain', '--untracked-files=all'), '')
  assert.equal(git('hash-object', file), '9b95a899c76bedc67bca33ba85918aef72967aad')
  assert.match(execFileSync('cargo', ['clippy', '--version'], { encoding: 'utf8' }), /^clippy 0\.1\.95\b/)
  const args = ['clippy', ...process.argv.slice(2), '--message-format=json', '--', '-D', 'warnings', '--force-warn', 'clippy::needless_return']
  const cargo = spawnSync('cargo', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 64 * 1024 * 1024 })
  if (cargo.error) throw cargo.error
  const records = cargo.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
  for (const item of records) {
    if (item.reason === 'compiler-message' && item.message?.rendered) process.stderr.write(item.message.rendered)
  }
  assert.equal(cargo.status, 0, 'The complete workspace Clippy build failed')
  verifyDiagnostics(records, process.cwd())
  console.log('Accepted the recorded Linux tail-return style finding at config_bootstrap.rs:245 for this frozen commit.')
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main()
