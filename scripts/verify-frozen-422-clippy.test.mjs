import assert from 'node:assert/strict'
import test from 'node:test'
import { verifyDiagnostics } from './verify-frozen-422-clippy.mjs'

function diagnostic() {
  return {
    reason: 'compiler-message',
    target: { name: 'nvpn', kind: ['bin'] },
    message: {
      level: 'warning',
      code: { code: 'clippy::needless_return' },
      message: 'unneeded `return` statement',
      spans: [{
        is_primary: true,
        file_name: 'crates/nostr-vpn-cli/src/config_bootstrap.rs',
        line_start: 245, line_end: 245,
        text: [{ text: '        return nostr_vpn_core::platform_paths::linux_user_config_path();' }],
      }],
    },
  }
}

const completed = { reason: 'build-finished', success: true }

test('the recorded bin and test diagnostic requires a completed workspace check', () => {
  verifyDiagnostics([diagnostic(), diagnostic(), completed], '/workspace')
  assert.throws(() => verifyDiagnostics([diagnostic()], '/workspace'))
  assert.throws(() => verifyDiagnostics([completed], '/workspace'))
  assert.throws(() => verifyDiagnostics([diagnostic(), { ...completed, success: false }], '/workspace'))
})

test('every other lint, target, source location or expression still fails the gate', () => {
  for (const change of [
    (d) => { d.message.code.code = 'clippy::unnecessary_cast' },
    (d) => { d.message.level = 'error' },
    (d) => { d.target.name = 'nvpn-web' },
    (d) => { d.message.spans[0].file_name = 'other.rs' },
    (d) => { d.message.spans[0].line_start++ },
    (d) => { d.message.spans[0].text[0].text = 'return another_value();' },
  ]) {
    const extra = diagnostic()
    change(extra)
    assert.throws(() => verifyDiagnostics([diagnostic(), extra, completed], '/workspace'))
  }
})
