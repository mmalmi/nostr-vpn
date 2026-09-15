import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const source = readFileSync('scripts/linux-vm-desktop-underlay-change-e2e.sh', 'utf8')
const capture = source.match(/^capture_remote_state\(\) \{[\s\S]*?^\}/m)?.[0]
assert.ok(capture)

for (const failure of ['', 'guest', 'peer']) {
  test(`Linux cleanup captures through the restored primary link and fails closed: ${failure || 'success'}`, () => {
    const root = mkdtempSync(join(tmpdir(), 'nvpn-linux-evidence-'))
    try {
      const result = spawnSync('bash', ['-c', `
set -euo pipefail
ARTIFACT_DIR="$1"
GUEST_STATE_DIR=/fixture/guest
PEER_STATE_DIR=/fixture/peer
GUEST_INITIALIZED=1
PEER_INITIALIZED=1
SECONDARY_PROXY=removed-secondary-network
run_primary() { echo primary >> "$ARTIFACT_DIR/probes.txt"; }
run_secondary_bounded() { echo removed-secondary >> "$ARTIFACT_DIR/probes.txt"; return 1; }
run_hypervisor_bounded() { return 0; }
capture_guest_state() { [[ "$NVPN_TEST_CAPTURE_FAILURE" != guest ]]; }
capture_peer_state() { [[ "$NVPN_TEST_CAPTURE_FAILURE" != peer ]]; }
${capture}
capture_remote_state
`, '_', root], {
        encoding: 'utf8', timeout: 5_000,
        env: { ...process.env, NVPN_TEST_CAPTURE_FAILURE: failure },
      })
      assert.equal(result.status, failure ? 1 : 0, result.stderr)
      assert.equal(readFileSync(join(root, 'probes.txt'), 'utf8'), 'primary\n')
      const evidence = readFileSync(join(root, 'runtime-evidence-capture.txt'), 'utf8')
      assert.match(evidence, new RegExp(`capture_failed=${failure ? 1 : 0}`))
      assert.equal(evidence.includes('REMOTE_RUNTIME_EVIDENCE_CAPTURED'), !failure)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
}
