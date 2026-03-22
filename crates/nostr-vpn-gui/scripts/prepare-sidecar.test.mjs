import test from 'node:test'
import assert from 'node:assert/strict'

import {
  resolveBinaryExeSuffix,
  resolveCargoCommand,
  resolveTargetTriple,
} from './prepare-sidecar-lib.mjs'

test('windows cross-target binaries keep the .exe suffix on non-Windows hosts', () => {
  assert.equal(resolveBinaryExeSuffix('x86_64-pc-windows-msvc', { hostPlatform: 'darwin' }), '.exe')
})

test('windows cross-target sidecars use cargo-xwin when building from non-Windows hosts', () => {
  assert.equal(
    resolveCargoCommand('x86_64-pc-windows-msvc', {
      hostPlatform: 'darwin',
      hasCommand() {
        return true
      },
    }),
    'cargo-xwin',
  )
})

test('target triple prefers explicit Tauri target environment', () => {
  const targetTriple = resolveTargetTriple('/tmp/workspace', {
    env: { TAURI_ENV_TARGET_TRIPLE: 'x86_64-pc-windows-msvc' },
    execRustc() {
      throw new Error('rustc should not be called when target is explicit')
    },
  })

  assert.equal(targetTriple, 'x86_64-pc-windows-msvc')
})
