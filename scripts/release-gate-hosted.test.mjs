import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const source = readFileSync(join(process.cwd(), 'scripts/release-gate.sh'), 'utf8')
const functions = [
  'build_release_gate_docker_images',
  'run_docker_isolated_functional_gates',
  'run_hosted_release_gate',
  'main',
].map((name) => source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0] ?? '').join('\n')

function runRoute(command, { complete = '0', full = false, failCheck = '' } = {}) {
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
release_gate_cleanup() { echo "cleanup-status:$?"; }
release_gate_timing_run() {
  if [[ "$NVPN_TEST_FULL_ROUTE" == 1 ]]; then
    echo "check:$2"
    [[ "$2" != "$NVPN_TEST_FAIL_CHECK" ]] || return 75
  else
    shift; "$@"
  fi
}
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
windows_platform_lane_requested() {
  [[ "$NVPN_TEST_FULL_ROUTE" == 1 ]] && return 0
  echo forbidden-fleet-probe; return 99
}
macos_platform_lane_requested() { return 0; }
linux_platform_lane_requested() { return 0; }
${functions}
${command}
`, '_', root], {
      encoding: 'utf8',
      timeout: 10_000,
      env: {
        ...process.env,
        NVPN_RELEASE_GATE_LOG_DIR: join(root, 'logs'),
        NVPN_RELEASE_GATE_REQUIRE_COMPLETE: complete,
        NVPN_TEST_FULL_ROUTE: full ? '1' : '0',
        NVPN_TEST_FAIL_CHECK: failCheck,
      },
    })
    return { ...result, files: readdirSync(root, { recursive: true }) }
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

test('Docker readiness failure stops before expensive source validation', () => {
  const result = runRoute('main', {
    full: true, failCheck: 'ensure_release_gate_docker_prerequisites',
  })
  assert.equal(result.status, 75, result.stderr)
  assert.doesNotMatch(result.stdout, /check:run_release_gate_candidate_preflight|lane:/)
})

test('termination preserves a failed exit status for gate cleanup', () => {
  const result = runRoute('release_gate_timing_run() { kill -TERM "$$"; }; main')
  assert.equal(result.status, 143, result.stderr)
  assert.match(result.stdout, /cleanup-status:143/)
  assert.doesNotMatch(result.stdout, /Release gate passed|cleanup-status:0/)
})

test('an unresponsive Docker daemon fails the real preflight within its deadline', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-docker-readiness-'))
  try {
    writeFileSync(join(root, 'docker'), '#!/bin/sh\n[ "$1" = info ] && exec sleep 30\necho unexpected-docker-operation >&2\nexit 99\n', { mode: 0o755 })
    const body = source.match(/^ensure_release_gate_docker_prerequisites\(\) \{[\s\S]*?^\}/m)?.[0]
    assert.ok(body)
    const result = spawnSync('bash', ['-c', `
set -euo pipefail
source scripts/lib-release-gate-timeout.sh
${body}
ensure_release_gate_docker_prerequisites
`], {
      encoding: 'utf8', timeout: 22_000,
      env: { ...process.env, PATH: `${root}:${process.env.PATH}` },
    })
    assert.ifError(result.error)
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stderr, /Docker daemon readiness timed out after 15s/)
    assert.doesNotMatch(result.stderr, /unexpected-docker-operation/)
  } finally {
    rmSync(root, { recursive: true, force: true })
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

test('full gate completes and seals one serial phone window before the unattended tail', () => {
  const result = runRoute('main', { full: true })
  assert.equal(result.status, 0, result.stderr)
  const checks = result.stdout.split('\n').filter(line => line.startsWith('check:'))
    .map(line => line.slice('check:'.length))
  const first = checks.indexOf('run_mobile_idle_cpu_gates')
  const seal = checks.indexOf('seal_frozen_ios_release_gate')
  assert.deepEqual(checks.slice(first, seal + 1), [
    'run_mobile_idle_cpu_gates',
    'run_mobile_wireguard_exit_gates',
    'run_android_legacy_replacement_gate',
    'run_mobile_underlay_change_gates',
    'run_mobile_join_e2e_gate',
    'seal_frozen_ios_release_gate',
  ])
  assert.ok(checks.indexOf('verify_paid_exit_seller_ui_gates') < first)
  for (const check of [
    'run_windows_release_mobile_join_e2e_gate', 'run_linux_release_mobile_join_e2e_gate',
    'run_mobile_qr_join_latency_gate', 'run_local_fips_transit_gate',
    'run_docker_signal_gates', 'run_docker_isolated_functional_gates',
    'run_docker_perf_gate', './scripts/release-gate-host-pair-latency.sh',
    './scripts/release-gate-host-pair-loaded-latency.sh', 'run_macos_daemon_idle_cpu_gate',
  ]) assert.ok(checks.indexOf(check) > seal, `${check} interrupted the phone window or was omitted`)
  assert.match(result.stdout, /Release gate passed/)
})

test('cold desktop peer preparation joins before network timing starts', () => {
  const result = runRoute('main', { full: true })
  assert.equal(result.status, 0, result.stderr)
  const events = result.stdout.split('\n')
  const peer = events.indexOf('lane:Desktop underlay peer preparation')
  const joined = events.indexOf('joined-functional-lanes')
  const timing = events.indexOf('check:run_local_fips_websocket_timing_regression_gate')
  const desktop = events.indexOf('lane:macOS post-build UI, idle CPU, and desktop network')
  assert.ok(peer >= 0 && peer < joined, 'cold peer compilation must join platform preparation')
  assert.ok(joined < timing && timing < desktop, 'network measurements must follow joined builds')
  assert.equal(events.filter(event => event === 'lane:Desktop underlay peer preparation').length, 1)
})

test('desktop peer preparation builds once for reachable enabled consumers and propagates failure', () => {
  const bodies = ['release_gate_mode_disabled', 'prepare_desktop_underlay_peer']
    .map(name => source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0] ?? '').join('\n')
  for (const [linux, windows, reachable, complete, buildStatus, expected] of [
    ['required', 'required', 'yes', '0', 0, 'build'],
    ['off', 'required', 'yes', '0', 0, 'build'],
    ['off', 'off', 'yes', '0', 0, ''],
    ['auto', 'auto', 'no', '0', 0, ''],
    ['required', 'required', 'no', '1', 0, 'build'],
    ['required', 'required', 'yes', '1', 75, 'build'],
  ]) {
    const result = spawnSync('bash', ['-c', `
set -euo pipefail
DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS=2400
linux_underlay_gate_reachable() { [[ "$NVPN_TEST_REACHABLE" == yes ]]; }
windows_underlay_gate_reachable() { [[ "$NVPN_TEST_REACHABLE" == yes ]]; }
release_gate_run_with_timeout() {
  [[ "$2" == 2400 && "$3" == ./scripts/prepare-macos-release-fips-peer.sh ]]
  echo build
  return "$NVPN_TEST_BUILD_STATUS"
}
${bodies}
prepare_desktop_underlay_peer
`], {
      encoding: 'utf8', timeout: 5_000,
      env: { ...process.env,
        NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E: linux,
        NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E: windows,
        NVPN_RELEASE_GATE_REQUIRE_COMPLETE: complete,
        NVPN_TEST_REACHABLE: reachable, NVPN_TEST_BUILD_STATUS: String(buildStatus),
      },
    })
    assert.equal(result.status, buildStatus, result.stderr)
    assert.equal(result.stdout.trim(), expected)
  }
})

test('desktop evidence failure stops before phone work and phone failure cannot seal evidence', () => {
  for (const [failCheck, forbidden] of [
    ['verify_paid_exit_seller_ui_gates', 'run_mobile_idle_cpu_gates'],
    ['run_mobile_underlay_change_gates', 'seal_frozen_ios_release_gate'],
  ]) {
    const result = runRoute('main', { full: true, failCheck })
    assert.equal(result.status, 75, result.stderr)
    assert.ok(!result.stdout.includes(`check:${forbidden}`))
    assert.doesNotMatch(result.stdout, /Release gate passed/)
  }
})

test('an unattended tail failure follows the iOS seal without producing a complete gate summary', () => {
  const result = runRoute('main', { full: true, failCheck: 'run_docker_perf_gate' })
  assert.equal(result.status, 75, result.stderr)
  assert.match(result.stdout, /check:seal_frozen_ios_release_gate/)
  assert.doesNotMatch(result.stdout, /Release gate passed/)
  assert.ok(!result.files.some(path => path.endsWith('release-gate-summary.json')))
})
