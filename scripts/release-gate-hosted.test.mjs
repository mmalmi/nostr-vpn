import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const source = readFileSync(join(process.cwd(), 'scripts/release-gate.sh'), 'utf8')
const functions = [
  'build_release_gate_docker_images',
  'run_docker_isolated_functional_gates',
  'run_hosted_release_gate',
  'main',
].map((name) => source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0] ?? '').join('\n')

function runRoute(command, { complete = '0' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-hosted-route-'))
  try {
    const result = spawnSync('bash', ['-c', `
set -euo pipefail
ROOT_DIR="$1"
RELEASE_GATE_TARGET_SECS=1800
release_gate_mode_disabled() { [[ "$1" == 0 ]]; }
release_gate_state_init() { :; }
release_gate_parallel_init() { RELEASE_GATE_PARALLEL_LOG_DIR="$1"; }
release_gate_timing_init() { :; }
release_gate_cleanup() { :; }
release_gate_timing_run() { shift; "$@"; }
release_gate_enforce_complete_real_network_modes() { :; }
release_gate_require_complete_fixture_inputs() { :; }
seal_release_gate_app_candidate() { :; }
run_release_gate_candidate_preflight() { echo source-preflight; }
docker_release_gates_enabled() { return 0; }
ensure_release_gate_docker_prerequisites() { echo docker-prerequisites; }
run_host_validation_lane() { echo static-rust-and-cli; }
run_local_fips_transit_gate() { echo public-fips-transit; }
build_release_gate_docker_node_image() { echo build-node; }
build_release_gate_paid_exit_image() { echo build-private-mint; }
build_release_gate_web_image() { echo build-web; }
run_docker_signal_gates() { echo routing-and-roaming; }
release_gate_parallel_start() { echo "lane:$1"; RELEASE_GATE_PARALLEL_LAST_INDEX=0; }
release_gate_parallel_wait_group() { echo joined-functional-lanes; }
windows_platform_lane_requested() { echo forbidden-fleet-probe; return 99; }
${functions}
${command}
`, '_', root], {
      encoding: 'utf8',
      timeout: 10_000,
      env: { ...process.env, NVPN_RELEASE_GATE_LOG_DIR: join(root, 'logs'), NVPN_RELEASE_GATE_REQUIRE_COMPLETE: complete },
    })
    return { ...result, files: readdirSync(root) }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

test('hosted entrypoint runs portable checks without fleet or private mint preparation', () => {
  const result = runRoute('main --hosted')
  assert.equal(result.status, 0, result.stderr)
  for (const check of [
    'source-preflight', 'docker-prerequisites', 'static-rust-and-cli',
    'public-fips-transit', 'build-node', 'build-web', 'routing-and-roaming',
    'lane:Docker NAT-safe MTU', 'lane:Docker kernel WireGuard exit',
    'lane:Docker userspace WireGuard exit', 'lane:Web/StartOS manual join',
    'lane:Umbrel authenticated requester join', 'joined-functional-lanes',
  ]) assert.ok(result.stdout.includes(check), `missing ${check}`)
  assert.doesNotMatch(result.stdout, /forbidden-fleet|private-mint|Linux ARM64 CLI|Spilman/)
})

test('hosted entrypoint cannot satisfy complete fleet mode or ignore unknown arguments', () => {
  for (const [command, complete] of [['main --hosted', '1'], ['main --typo', '0']]) {
    const result = runRoute(command, { complete })
    assert.equal(result.status, 2, result.stderr)
    assert.deepEqual(result.files, [])
    assert.doesNotMatch(result.stdout, /source-preflight|build-node/)
  }
})

test('default Docker gate retains both paid-exit fixtures and their mint build', () => {
  const result = runRoute('build_release_gate_docker_images; run_docker_isolated_functional_gates')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /build-private-mint/)
  assert.match(result.stdout, /lane:Docker Spilman paid exit/)
  assert.match(result.stdout, /lane:Docker automatic Spilman paid exit/)
  assert.match(result.stdout, /joined-functional-lanes/)
})
