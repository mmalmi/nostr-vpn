import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import {
  androidRuntimePayloads,
  buildReleaseGateAttestation,
  collectReleaseGateReceipts,
  startosExactPackageValidator,
  validateExactZipMembers,
  validateMacosPixelJoinReceipt,
} from './release-artifact-provenance-lib.mjs'
import { proveUnchangedPlatformInputs } from './release-component-source.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function write(path, value) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, value)
}

test('exact ZIP validation rejects publication payload extras', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-exact-zip-'))
  try {
    write(join(root, 'nvpn.exe'), 'cli')
    write(join(root, 'binaries', 'wintun.dll'), 'wintun')
    write(join(root, 'unexpected.txt'), 'extra')
    const exact = join(root, 'exact.zip')
    const extra = join(root, 'extra.zip')
    for (const [archive, members] of [
      [exact, ['nvpn.exe', 'binaries/wintun.dll']],
      [extra, ['nvpn.exe', 'binaries/wintun.dll', 'unexpected.txt']],
    ]) {
      const result = spawnSync('zip', ['-q', archive, ...members], {
        cwd: root,
        encoding: 'utf8',
      })
      assert.equal(result.status, 0, result.stderr)
    }
    assert.deepEqual(
      validateExactZipMembers(exact, ['nvpn.exe', 'binaries/wintun.dll']),
      ['binaries/wintun.dll', 'nvpn.exe'],
    )
    assert.throws(
      () => validateExactZipMembers(extra, ['nvpn.exe', 'binaries/wintun.dll']),
      /ZIP member set differs.*unexpected\.txt/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof excludes the cfg(test) exit fixture but retains its production parent', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-exit-fixture-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const commit = (path, content) => {
    write(join(root, path), content)
    git('add', path)
    git('commit', '-qm', path)
    return { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
  }
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    const parent = 'crates/nostr-vpn-app-core/src/ffi.rs'
    const receipt = commit(parent, '#[cfg(test)] mod tests {}')
    const fixture = commit('crates/nostr-vpn-app-core/src/ffi/tests_network/exit_state.rs', 'deterministic currency setting')
    const args = {
      candidateRoot: root, receiptCommit: receipt.commit, receiptTree: receipt.tree,
      candidateCommit: fixture.commit, candidateTree: fixture.tree,
    }
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({ ...args, platform }))
    }
    const changedParent = commit(parent, 'mod tests {}')
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.throws(() => proveUnchangedPlatformInputs({
        ...args, platform, candidateCommit: changedParent.commit, candidateTree: changedParent.tree,
      }), /changed product\/build input/)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('Windows runtime changes invalidate Windows while its include parent remains shared', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-windows-runtime-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const commit = (path, content) => {
    write(join(root, path), content)
    git('add', path)
    git('commit', '-qm', path)
    return { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
  }
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    const parent = 'crates/nostr-vpn-cli/src/fips_private_mesh.rs'
    const receipt = commit(parent, 'include!("fips_private_mesh/tunnel_runtime_windows.rs");')
    commit('crates/nostr-vpn-cli/src/fips_private_mesh/tunnel_runtime_windows.rs', '#[cfg(target_os = "windows")] fn refresh_dns() {}')
    const changed = commit('scripts/desktop-windows-underlay-change-e2e.ps1', 'Assert-StableDnsPolicy')
    const args = {
      candidateRoot: root, receiptCommit: receipt.commit, receiptTree: receipt.tree,
      candidateCommit: changed.commit, candidateTree: changed.tree,
    }
    for (const platform of ['android', 'ios', 'linux', 'macos']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({ ...args, platform }))
    }
    assert.throws(() => proveUnchangedPlatformInputs({ ...args, platform: 'windows' }), /changed product\/build input/)
    const changedParent = commit(parent, 'fn shared_runtime() {}')
    for (const platform of ['linux', 'macos', 'windows']) {
      assert.throws(() => proveUnchangedPlatformInputs({
        ...args, platform, candidateCommit: changedParent.commit, candidateTree: changedParent.tree,
      }), /changed product\/build input/)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof retains only unchanged platform product inputs', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-component-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const commit = (path, value) => {
    write(join(root, path), value)
    git('add', path)
    git('commit', '-qm', path)
    return { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
  }
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    const receipt = commit('android/App.kt', 'base')
    commit('ios/Sources/App.swift', 'ios')
    const candidate = commit('scripts/test-release-harness.sh', 'test')
    const args = {
      candidateRoot: root, platform: 'android',
      receiptCommit: receipt.commit, receiptTree: receipt.tree,
      candidateCommit: candidate.commit, candidateTree: candidate.tree,
    }
    assert.match(proveUnchangedPlatformInputs(args).changed_paths_sha256, /^[0-9a-f]{64}$/)
    const verifier = commit('scripts/release-source-verification.mjs', 'harness verifier')
    assert.doesNotThrow(() => proveUnchangedPlatformInputs({
      ...args, candidateCommit: verifier.commit, candidateTree: verifier.tree,
    }))
    const verifierTest = commit('scripts/release-source-verification.test.mjs', 'harness test')
    assert.doesNotThrow(() => proveUnchangedPlatformInputs({
      ...args, candidateCommit: verifierTest.commit, candidateTree: verifierTest.tree,
    }))
    for (const path of [
      'CONTRIBUTING.md',
      'scripts/android-release-foreground-idle-receipt.mjs',
      'scripts/ios-upload-receipt.mjs',
      'scripts/publish-release-refs.mjs',
      'scripts/release-mutation-gate.mjs',
      'scripts/release_common.sh',
      'scripts/umbrel-release.mjs',
      'scripts/windows-release-publication-proof.ps1',
    ]) {
      const publication = commit(path, 'publication harness')
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({
        ...args,
        candidateCommit: publication.commit,
        candidateTree: publication.tree,
      }))
    }
    const android = commit('android/App.kt', 'product change')
    assert.throws(() => proveUnchangedPlatformInputs({
      ...args, candidateCommit: android.commit, candidateTree: android.tree,
    }), /changed product\/build input android\/App.kt/)
    const changed = commit('Cargo.lock', 'shared')
    assert.throws(() => proveUnchangedPlatformInputs({
      ...args, candidateCommit: changed.commit, candidateTree: changed.tree,
    }), /changed product\/build input Cargo.lock/)
    const macReceipt = commit('macos/Sources/App.swift', 'base')
    const macHarnessPaths = [
      'crates/nostr-vpn-core/examples/desktop_manual_join_e2e_fixture.rs',
      'scripts/appstore-draft',
      'scripts/appstore_draft_metadata.py',
      'scripts/test_appstore_draft_metadata.py',
      'scripts/desktop-manual-join-ax.swift',
      'scripts/desktop-mobile-manual-join-atspi.py',
      'scripts/desktop-mobile-manual-join-windows-ui.ps1',
      'scripts/desktop-linux-underlay-change-e2e.sh',
      'scripts/e2e-device-roster.sh',
      'scripts/e2e-macos-release-network.sh',
      'scripts/e2e-macos-service-toggle.sh',
      'scripts/e2e-macos-service.sh',
      'scripts/e2e-windows-service-toggle.ps1',
      'scripts/lib-desktop-underlay-host-peer.sh',
      'scripts/lib-mobile-release-join-ui.sh',
      'scripts/macos-release-exit-dns-ui-remote.sh',
      'scripts/macos-release-mobile-join-remote.sh',
      'scripts/macos-vm-desktop-daemon-idle-e2e.sh',
      'scripts/macos-vm-desktop-wireguard-exit-e2e.sh',
      'scripts/macos-vm-release-exit-dns-ui-e2e.sh',
      'scripts/macos-vm-release-mobile-join-e2e.sh',
      'scripts/macos_exit_dns_ui_receipt.py',
      'scripts/macos_release_join_artifact.py',
      'scripts/mobile-release-join-e2e.sh',
      'scripts/mobile-release-join-ui-query.py',
      'scripts/mobile-wireguard-exit-e2e.sh',
      'scripts/prepare-macos-release-fips-peer.sh',
      'scripts/verify-host-linux-peer-artifact.py',
      'scripts/windows-vm-desktop-underlay-change-e2e.sh',
      'scripts/windows-vm-exit-dns-ui-e2e.sh',
      'scripts/windows-vm-release-mobile-join-e2e.sh',
      'scripts/windows-vm-service-toggle-e2e.sh',
    ]
    for (const path of macHarnessPaths) write(join(root, path), 'harness')
    git('add', '.')
    git('commit', '-qm', 'macOS join harness')
    const macHarness = {
      commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}'),
    }
    const macArgs = {
      candidateRoot: root, platform: 'macos',
      receiptCommit: macReceipt.commit, receiptTree: macReceipt.tree,
      candidateCommit: macHarness.commit, candidateTree: macHarness.tree,
    }
    assert.match(proveUnchangedPlatformInputs(macArgs).changed_paths_sha256, /^[0-9a-f]{64}$/)
    const macProduct = commit('macos/Sources/App.swift', 'changed')
    assert.throws(() => proveUnchangedPlatformInputs({
      ...macArgs, candidateCommit: macProduct.commit, candidateTree: macProduct.tree,
    }), /changed product\/build input macos\/Sources\/App.swift/)
    const testOnlyReceipt = commit(
      'crates/nostr-vpn-app-core/src/mobile_tunnel/config.rs',
      'pub const PRODUCT: bool = false;\n',
    )
    commit(
      'crates/nostr-vpn-app-core/src/mobile_tunnel/tests_core.rs',
      '#[test]\nfn regression() {}\n',
    )
    const testOnly = commit(
      'crates/nostr-vpn-app-core/src/mobile_tunnel/tests_runtime/websocket_join.rs',
      '#[test]\nfn websocket_regression() {}\n',
    )
    const testOnlyArgs = {
      candidateRoot: root, platform: 'android',
      receiptCommit: testOnlyReceipt.commit, receiptTree: testOnlyReceipt.tree,
      candidateCommit: testOnly.commit, candidateTree: testOnly.tree,
    }
    assert.match(
      proveUnchangedPlatformInputs(testOnlyArgs).changed_paths_sha256,
      /^[0-9a-f]{64}$/,
    )
    const sharedProduct = commit(
      'crates/nostr-vpn-app-core/src/mobile_tunnel/config.rs',
      'pub const PRODUCT: bool = true;\n',
    )
    assert.throws(() => proveUnchangedPlatformInputs({
      ...testOnlyArgs,
      candidateCommit: sharedProduct.commit,
      candidateTree: sharedProduct.tree,
    }), /changed product\/build input crates\/nostr-vpn-app-core\/src\/mobile_tunnel\/config\.rs/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

for (const [helper, nearbyHelper] of [
  ['native-lab.py', 'native-lab-helper.py'],
  ['docker-replace-nvpn-binary', 'docker-replace-nvpn-image'],
  ['verify.sh', 'verify-build.sh'],
  ['startos-release.mjs', 'startos-release-helper.mjs'],
  ['publish.sh', 'publish-build.sh'],
]) {
  test(`component proof treats only ${helper} as harness-only`, () => {
    const root = mkdtempSync(join(tmpdir(), 'nvpn-native-lab-component-proof-'))
    const git = (...args) => {
      const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
      assert.equal(result.status, 0, result.stderr)
      return result.stdout.trim()
    }
    const commit = (path, value, message) => {
      write(join(root, path), value)
      git('add', path)
      git('commit', '-qm', message)
      return { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
    }
    try {
      git('init', '-q')
      git('config', 'user.name', 'Release Test')
      git('config', 'user.email', 'release@example.invalid')
      const receipt = commit('README.md', 'base\n', 'receipt source')
      const nativeLab = commit(
        `scripts/${helper}`,
        'print("resource supervisor")\n',
        'native-lab harness change',
      )
      for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
        assert.doesNotThrow(() => proveUnchangedPlatformInputs({
          candidateRoot: root,
          platform,
          receiptCommit: receipt.commit,
          receiptTree: receipt.tree,
          candidateCommit: nativeLab.commit,
          candidateTree: nativeLab.tree,
        }))
      }
      git('checkout', '-q', '-b', 'nearby-script', receipt.commit)
      const nearby = commit(
        `scripts/${nearbyHelper}`,
        'print("ordinary script")\n',
        'nearby ordinary script change',
      )
      for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
        assert.throws(() => proveUnchangedPlatformInputs({
          candidateRoot: root,
          platform,
          receiptCommit: receipt.commit,
          receiptTree: receipt.tree,
          candidateCommit: nearby.commit,
          candidateTree: nearby.tree,
        }), new RegExp(`changed product/build input scripts/${nearbyHelper.replaceAll('.', '\\.')}`))
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
}

test('component proof separates the Umbrel web product from native platform inputs', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-umbrel-publisher-component-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const commit = (path, value, message) => {
    write(join(root, path), value)
    git('add', path)
    git('commit', '-qm', message)
    return { commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
  }
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    const receipt = commit('README.md', 'base\n', 'receipt source')
    const publisher = commit(
      'scripts/umbrel-release.mjs',
      'console.log("publish Umbrel image")\n',
      'Umbrel publication harness change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: publisher.commit,
        candidateTree: publisher.tree,
      }))
    }
    const authenticatedGate = commit(
      'scripts/e2e-umbrel-auth-join-docker.sh',
      'echo "verify authenticated Umbrel join"\n',
      'Umbrel authentication and join harness change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: authenticatedGate.commit,
        candidateTree: authenticatedGate.tree,
      }))
    }
    const webE2E = commit(
      'web/control-panel/e2e/umbrel-web.spec.ts',
      'test("Umbrel web release behavior")\n',
      'Umbrel web release test change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: webE2E.commit,
        candidateTree: webE2E.tree,
      }))
    }
    const webProduct = commit(
      'web/control-panel/src/App.svelte',
      '<main>Umbrel requester joined</main>\n',
      'Umbrel web product change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.doesNotThrow(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: webProduct.commit,
        candidateTree: webProduct.tree,
      }))
    }

    git('checkout', '-q', '-b', 'nearby-script', receipt.commit)
    const nearby = commit(
      'scripts/umbrel-release-helper.mjs',
      'console.log("ordinary script")\n',
      'nearby ordinary script change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.throws(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: nearby.commit,
        candidateTree: nearby.tree,
      }), /changed product\/build input scripts\/umbrel-release-helper\.mjs/)
    }

    git('checkout', '-q', '-b', 'shared-web-backend', receipt.commit)
    const sharedWebBackend = commit(
      'crates/nostr-vpn-web/src/main.rs',
      'fn main() {}\n',
      'shared web backend product change',
    )
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.throws(() => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit: receipt.commit,
        receiptTree: receipt.tree,
        candidateCommit: sharedWebBackend.commit,
        candidateTree: sharedWebBackend.tree,
      }), /changed product\/build input crates\/nostr-vpn-web\/src\/main\.rs/)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof scopes desktop crates and Rust test modules', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-desktop-component-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const paths = [
    'crates/nostr-vpn-cli/src/session_runtime/fips_status_helpers.rs',
    'crates/nostr-vpn-cli/src/macos_service.rs',
    'crates/nostr-vpn-wintun/src/lib.rs',
    'crates/nostr-vpn-cli/src/fips_private_mesh/tests_runtime.rs',
    'crates/nostr-vpn-cli/src/session_runtime/tests.rs',
    'crates/nostr-vpn-cli/src/tests/service_cli.rs',
    'scripts/e2e-fips-roaming-docker.sh',
    'crates/nostr-vpn-cli/src/wireguard_exit.rs',
    'crates/nostr-vpn-cli/src/wireguard_exit/linux_runtime.rs',
    'crates/nostr-vpn-cli/src/wireguard_exit/linux_commands.rs',
    'crates/nostr-vpn-cli/src/wireguard_exit/linux_tests.rs',
    'crates/nostr-vpn-cli/src/wireguard_exit/linux_tests/reconciliation.rs',
    'crates/nostr-vpn-cli/src/wireguard_exit_helpers.rs',
    'crates/nostr-vpn-cli/src/fips_private_mesh/linux_cleanup.rs',
    'crates/nostr-vpn-cli/src/fips_private_mesh/tests_network_cleanup.rs',
    'scripts/windows-vm-app-launch-smoke.sh',
    'crates/nostr-vpn-app-core/src/mobile_tunnel/ios_packet_flow.rs',
    'crates/nostr-vpn-app-core/src/c_abi/ios_packet_flow.rs',
    'crates/nostr-vpn-app-core/src/mobile_tunnel.rs',
  ]
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    for (const path of paths) write(join(root, path), 'base\n')
    git('add', '.')
    git('commit', '-qm', 'receipt source')
    const receiptCommit = git('rev-parse', 'HEAD')
    const receiptTree = git('rev-parse', 'HEAD^{tree}')

    const assertScope = (name, changedPaths, affected) => {
      git('checkout', '-q', '-b', name, receiptCommit)
      for (const path of changedPaths) write(join(root, path), 'changed\n')
      git('add', '.')
      git('commit', '-qm', name)
      const args = {
        candidateRoot: root,
        receiptCommit,
        receiptTree,
        candidateCommit: git('rev-parse', 'HEAD'),
        candidateTree: git('rev-parse', 'HEAD^{tree}'),
      }
      for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
        const prove = () => proveUnchangedPlatformInputs({
          ...args,
          platform,
        })
        if (affected.includes(platform)) {
          assert.throws(prove, /changed product\/build input/)
        } else {
          assert.doesNotThrow(prove)
        }
      }
    }

    assertScope('shared-cli', [paths[0]], ['linux', 'macos', 'windows'])
    assertScope('macos-service', [paths[1]], ['macos'])
    assertScope('windows-wintun', [paths[2]], ['windows'])
    assertScope('harness-only', paths.slice(3, 7), [])
    assertScope('linux-wireguard-exit-module', [paths[7]], ['linux'])
    assertScope('linux-wireguard-exit-sources', paths.slice(8, 10), ['linux'])
    assertScope('linux-wireguard-exit-tests', paths.slice(10, 12), [])
    assertScope(
      'wireguard-exit-boundary-control',
      [paths[12]],
      ['linux', 'macos', 'windows'],
    )
    assertScope('linux-cleanup', [paths[13]], ['linux'])
    assertScope('linux-cleanup-tests', [paths[14]], [])
    assertScope('windows-installer-build-gate', [paths[15]], ['windows'])
    assertScope('ios-packet-flow', paths.slice(16, 18), ['ios'])
    assertScope('ios-packet-flow-inclusion-boundary', [paths[18]],
      ['android', 'ios', 'linux', 'macos', 'windows'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('Android artifact survives the 8618306d8 harness delta but not a service change', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-harness-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const harnessDelta = [
    'CHANGELOG.md',
    'scripts/lib-mobile-android-release-gate.sh',
    'scripts/lib-mobile-android-underlay.sh',
    'scripts/mobile-android-smoke.sh',
    'scripts/mobile_release_artifact_receipt.py',
    'scripts/release-artifact-provenance-lib.test.mjs',
    'scripts/release-component-source.mjs',
    'scripts/test-mobile-android-release-cleanup-harness.sh',
    'scripts/test-mobile-underlay-change-harness.sh',
    'scripts/test-mobile-wireguard-exit-dns-harness.sh',
  ]
  const service = 'android/app/src/main/java/org/nostrvpn/app/vpn/NostrVpnService.kt'
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    for (const path of [...harnessDelta, service]) write(join(root, path), 'base\n')
    git('add', '.')
    git('commit', '-qm', '8618306d8 artifact source')
    const receiptCommit = git('rev-parse', 'HEAD')
    const receiptTree = git('rev-parse', 'HEAD^{tree}')

    for (const path of harnessDelta) write(join(root, path), 'changed\n')
    git('add', '.')
    git('commit', '-qm', '1296447e7 harness delta')
    const candidateCommit = git('rev-parse', 'HEAD')
    const candidateTree = git('rev-parse', 'HEAD^{tree}')
    const args = {
      candidateRoot: root,
      platform: 'android',
      receiptCommit,
      receiptTree,
      candidateCommit,
      candidateTree,
    }
    const proof = proveUnchangedPlatformInputs(args)
    assert.equal(
      proof.changed_paths_sha256,
      sha256(`${harnessDelta.sort().join('\0')}\0`),
    )

    write(join(root, service), 'product change\n')
    git('add', service)
    git('commit', '-qm', 'change Android VPN service')
    assert.throws(
      () => proveUnchangedPlatformInputs({
        ...args,
        candidateCommit: git('rev-parse', 'HEAD'),
        candidateTree: git('rev-parse', 'HEAD^{tree}'),
      }),
      /changed product\/build input android\/app\/src\/main\/java\/org\/nostrvpn\/app\/vpn\/NostrVpnService\.kt/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof treats the iOS physical gate as harness-only', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-ios-harness-proof-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const changedPaths = [
    'android/app/src/main/java/org/nostrvpn/app/vpn/NostrVpnService.kt',
    'Dockerfile.mobile-wireguard-exit-e2e',
    'Dockerfile.mobile-wireguard-exit-e2e.dockerignore',
    'ios/UITests/NostrVpnReleaseNetworkUITests.swift',
    'scripts/capture-mobile-ios-underlay-output.py',
    'scripts/lib-mobile-android-release-gate.sh',
    'scripts/lib-mobile-ios-release-network.sh',
    'scripts/lib-mobile-wireguard-fixture.sh',
    'scripts/mobile-wireguard-exit-remote-native.sh',
    'scripts/mobile-wireguard-exit-server.sh',
    'scripts/mobile-wireguard-tls-sni-count.py',
    'scripts/test-mobile-android-release-cleanup-harness.sh',
    'scripts/test-mobile-underlay-change-harness.sh',
  ]
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    for (const path of changedPaths) write(join(root, path), 'base\n')
    git('add', '.')
    git('commit', '-qm', 'base')
    const receiptCommit = git('rev-parse', 'HEAD')
    const receiptTree = git('rev-parse', 'HEAD^{tree}')

    for (const path of changedPaths) write(join(root, path), 'changed\n')
    git('add', '.')
    git('commit', '-qm', 'candidate')
    const candidateCommit = git('rev-parse', 'HEAD')
    const candidateTree = git('rev-parse', 'HEAD^{tree}')
    const args = {
      candidateRoot: root,
      receiptCommit,
      receiptTree,
      candidateCommit,
      candidateTree,
    }

    assert.throws(
      () => proveUnchangedPlatformInputs({ ...args, platform: 'android' }),
      /changed product\/build input android\/app\/src\/main\/java\/org\/nostrvpn\/app\/vpn\/NostrVpnService\.kt/,
    )
    const expectedDelta = sha256(`${changedPaths.sort().join('\0')}\0`)
    for (const platform of ['ios', 'linux', 'macos', 'windows']) {
      const proof = proveUnchangedPlatformInputs({ ...args, platform })
      assert.equal(proof.changed_paths_sha256, expectedDelta)
    }

    write(join(root, '.dockerignore'), 'changed product build context\n')
    git('add', '.dockerignore')
    git('commit', '-qm', 'change shared Docker build context')
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      assert.throws(
        () => proveUnchangedPlatformInputs({
          ...args,
          platform,
          candidateCommit: git('rev-parse', 'HEAD'),
          candidateTree: git('rev-parse', 'HEAD^{tree}'),
        }),
        /changed product\/build input \.dockerignore/,
      )
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof scopes the iOS build driver to iOS', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-ios-build-scope-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    write(join(root, 'tools/run-ios'), 'base\n')
    git('add', '.')
    git('commit', '-qm', 'base')
    const receiptCommit = git('rev-parse', 'HEAD')
    const receiptTree = git('rev-parse', 'HEAD^{tree}')
    write(join(root, 'tools/run-ios'), 'changed\n')
    git('commit', '-qam', 'iOS driver correction')
    const args = {
      candidateRoot: root, receiptCommit, receiptTree,
      candidateCommit: git('rev-parse', 'HEAD'),
      candidateTree: git('rev-parse', 'HEAD^{tree}'),
    }
    for (const platform of ['android', 'linux', 'macos', 'windows']) {
      assert.equal(proveUnchangedPlatformInputs({ ...args, platform }).platform, platform)
    }
    assert.throws(
      () => proveUnchangedPlatformInputs({ ...args, platform: 'ios' }),
      /changed product\/build input tools\/run-ios/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('component proof separates iOS harness and profile build inputs', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-release-script-scope-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  const profilePaths = [
    'scripts/ios-profiles',
    'scripts/ios_profile_certificate.py',
  ]
  const harnessPaths = [
    'scripts/desktop_mobile_manual_join_receipt.py',
    'scripts/e2e-web-startos-manual-join-docker.sh',
    'scripts/ios_xctestrun.py',
    'scripts/ios_frozen_archive.py',
    'scripts/ios_frozen_gate.py',
    'scripts/lib-ubuntu-vm-imported-release.sh',
    'scripts/lib-mobile-ios-release-artifact.sh',
    'scripts/lib-mobile-release-artifact-reuse.sh',
    'scripts/lib-mobile-release-join-artifacts.sh',
    'scripts/lib-macos-release-app-ownership.sh',
    'scripts/linux-release-mobile-join-remote.sh',
    'scripts/mobile-test-kit.sh',
    'scripts/mobile-underlay-local-timestamp.py',
    'scripts/release-network-evidence.py',
    'scripts/ubuntu-vm-release-mobile-join-e2e.sh',
    'scripts/validate-mobile-underlay-continuity.py',
    'scripts/windows-release-mobile-join-remote.ps1',
  ]
  const changedPaths = [...profilePaths, ...harnessPaths]
  try {
    git('init', '-q')
    git('config', 'user.name', 'Release Test')
    git('config', 'user.email', 'release@example.invalid')
    for (const path of changedPaths) write(join(root, path), 'base\n')
    git('add', '.')
    git('commit', '-qm', 'base')
    const receiptCommit = git('rev-parse', 'HEAD')
    const receiptTree = git('rev-parse', 'HEAD^{tree}')

    for (const path of harnessPaths) write(join(root, path), 'changed\n')
    git('add', '.')
    git('commit', '-qm', 'harness candidate')
    const harnessCommit = git('rev-parse', 'HEAD')
    const harnessTree = git('rev-parse', 'HEAD^{tree}')
    const harnessDelta = sha256(`${harnessPaths.sort().join('\0')}\0`)
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      const proof = proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform,
        receiptCommit,
        receiptTree,
        candidateCommit: harnessCommit,
        candidateTree: harnessTree,
      })
      assert.equal(proof.changed_paths_sha256, harnessDelta)
    }

    for (const path of profilePaths) write(join(root, path), 'changed\n')
    git('add', '.')
    git('commit', '-qm', 'iOS build candidate')
    const candidateCommit = git('rev-parse', 'HEAD')
    const candidateTree = git('rev-parse', 'HEAD^{tree}')
    const args = {
      candidateRoot: root,
      receiptCommit,
      receiptTree,
      candidateCommit,
      candidateTree,
    }

    assert.throws(
      () => proveUnchangedPlatformInputs({ ...args, platform: 'ios' }),
      /changed product\/build input scripts\/ios-profiles/,
    )
    const expectedDelta = sha256(`${changedPaths.sort().join('\0')}\0`)
    for (const platform of ['android', 'linux', 'macos', 'windows']) {
      const proof = proveUnchangedPlatformInputs({ ...args, platform })
      assert.equal(proof.changed_paths_sha256, expectedDelta)
    }

    const archiveReceiptCommit = candidateCommit
    const archiveReceiptTree = candidateTree
    write(join(root, 'scripts/ios_frozen_archive.py'), 'changed again\n')
    git('add', '.')
    git('commit', '-qm', 'iOS archive tooling')
    const archiveArgs = {
      candidateRoot: root,
      receiptCommit: archiveReceiptCommit,
      receiptTree: archiveReceiptTree,
      candidateCommit: git('rev-parse', 'HEAD'),
      candidateTree: git('rev-parse', 'HEAD^{tree}'),
    }
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      proveUnchangedPlatformInputs({ ...archiveArgs, platform })
    }

    const gateReceiptCommit = archiveArgs.candidateCommit
    const gateReceiptTree = archiveArgs.candidateTree
    write(join(root, 'scripts/ios_frozen_gate.py'), 'changed again\n')
    git('add', '.')
    git('commit', '-qm', 'iOS gate tooling')
    const gateArgs = {
      candidateRoot: root,
      receiptCommit: gateReceiptCommit,
      receiptTree: gateReceiptTree,
      candidateCommit: git('rev-parse', 'HEAD'),
      candidateTree: git('rev-parse', 'HEAD^{tree}'),
    }
    for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
      proveUnchangedPlatformInputs({ ...gateArgs, platform })
    }

    const desktopReceiptCommit = gateArgs.candidateCommit
    const desktopReceiptTree = gateArgs.candidateTree
    write(join(root, 'linux/src/main.rs'), 'changed product\n')
    git('add', '.')
    git('commit', '-qm', 'Linux product candidate')
    assert.throws(
      () => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform: 'linux',
        receiptCommit: desktopReceiptCommit,
        receiptTree: desktopReceiptTree,
        candidateCommit: git('rev-parse', 'HEAD'),
        candidateTree: git('rev-parse', 'HEAD^{tree}'),
      }),
      /changed product\/build input linux\/src\/main\.rs/,
    )

    write(join(root, 'windows/NostrVpn.Windows/App.xaml.cs'), 'changed product\n')
    git('add', '.')
    git('commit', '-qm', 'Windows product candidate')
    assert.throws(
      () => proveUnchangedPlatformInputs({
        candidateRoot: root,
        platform: 'windows',
        receiptCommit: desktopReceiptCommit,
        receiptTree: desktopReceiptTree,
        candidateCommit: git('rev-parse', 'HEAD'),
        candidateTree: git('rev-parse', 'HEAD^{tree}'),
      }),
      /changed product\/build input windows\/NostrVpn\.Windows\/App\.xaml\.cs/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

const desktopDnsCounterNames = [
  'profile_dns',
  'cloudflare',
  'quad9',
  'google',
  'fixture_dns',
]

function desktopDnsCase(expectedCounter) {
  return Object.fromEntries(
    desktopDnsCounterNames.flatMap((counter) => [
      [`before_${counter}`, 1],
      [`after_${counter}`, counter === expectedCounter ? 2 : 1],
    ]),
  )
}

function desktopDnsUiCases(appExecutableSha256, cliExecutableSha256) {
  const settings = {
    automatic: ['automatic', 'cloudflare'],
    cloudflare: ['encrypted', 'cloudflare'],
    quad9: ['encrypted', 'quad9'],
    custom: ['encrypted', 'custom'],
    'through-exit': ['through_exit', 'cloudflare'],
  }
  return Object.fromEntries(
    Object.entries(settings).map(([dnsCase, [mode, provider]]) => [
      dnsCase,
      {
        mode,
        provider,
        appExecutableSha256,
        cliExecutableSha256,
      },
    ]),
  )
}

const desktopDnsUiEvidenceFiles = Object.fromEntries(
  ['automatic', 'cloudflare', 'quad9', 'custom', 'through-exit'].map(
    (dnsCase, index) => [
      `${dnsCase}.json`,
      String(index + 10).padStart(64, '0'),
    ],
  ),
)

function zipTree(source, destination) {
  rmSync(destination, { force: true })
  const result = spawnSync('zip', ['-q', '-r', destination, '.'], {
    cwd: source,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  assert.equal(result.status, 0, result.stderr)
}

test('Android bundle proof compares real APK and AAB production payload bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-proof-test-'))
  try {
    const apkRoot = join(root, 'apk')
    const aabRoot = join(root, 'aab')
    const native = Buffer.from('production-native-payload')
    const dex = Buffer.from('production-dex-payload')
    write(
      join(apkRoot, 'lib', 'arm64-v8a', 'libnostr_vpn_app_core.so'),
      native,
    )
    write(join(apkRoot, 'classes.dex'), dex)
    write(
      join(aabRoot, 'base', 'lib', 'arm64-v8a', 'libnostr_vpn_app_core.so'),
      native,
    )
    write(join(aabRoot, 'base', 'dex', 'classes.dex'), dex)

    const apk = join(root, 'app.apk')
    const aab = join(root, 'app.aab')
    zipTree(apkRoot, apk)
    zipTree(aabRoot, aab)
    assert.deepEqual(androidRuntimePayloads(apk, aab), {
      app_core_arm64: sha256(native),
      classes_dex: sha256(dex),
    })

    write(
      join(aabRoot, 'base', 'dex', 'classes.dex'),
      Buffer.from('different-dex'),
    )
    zipTree(aabRoot, aab)
    assert.throws(
      () => androidRuntimePayloads(apk, aab),
      /differs from the physically gated APK/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('release receipt collection requires exact source and strict public UI gates', () => {
  const fixtureRoot = process.env.NVPN_FLEET_GATE_FIXTURE_ROOT
  const root =
    fixtureRoot ?? mkdtempSync(join(tmpdir(), 'nvpn-gate-receipts-test-'))
  if (fixtureRoot) {
    mkdirSync(root, { recursive: true })
  }
  try {
    const receiptCommit =
      process.env.NVPN_FLEET_GATE_APP_GIT_SHA ?? 'a'.repeat(40)
    const receiptTree =
      process.env.NVPN_FLEET_GATE_APP_GIT_TREE ?? 'b'.repeat(40)
    const candidateCommit =
      process.env.NVPN_FLEET_GATE_CANDIDATE_APP_GIT_SHA ?? receiptCommit
    const candidateTree =
      process.env.NVPN_FLEET_GATE_CANDIDATE_APP_GIT_TREE ?? receiptTree
    const commit = receiptCommit
    const tree = receiptTree
    const candidateRoot = process.env.NVPN_FLEET_GATE_CANDIDATE_ROOT
    const source = {
      appGitSha: receiptCommit,
      appGitTree: receiptTree,
      appVersion: process.env.NVPN_FLEET_GATE_APP_VERSION ?? '4.1.5',
      fipsGitSha:
        process.env.NVPN_FLEET_GATE_FIPS_GIT_SHA ?? 'c'.repeat(40),
      fipsGitTree:
        process.env.NVPN_FLEET_GATE_FIPS_GIT_TREE ?? 'd'.repeat(40),
      fipsVersion: process.env.NVPN_FLEET_GATE_FIPS_VERSION ?? '0.4.45',
    }
    const candidateSource = {
      ...source,
      appGitSha: candidateCommit,
      appGitTree: candidateTree,
    }
    const mobileJoinPath = join(root, 'mobile-join.json')
    const macosJoinPath = join(root, 'macos-join.json')
    const paths = {
      android: {
        install: join(root, 'android-install.json'),
        physical: join(root, 'android.json'),
        foreground_idle_cpu: join(root, 'android-foreground-idle.json'),
        foreground_idle_cpu_raw: join(root, 'android-foreground-idle-raw.json'),
        mobile_join: mobileJoinPath,
        wireguard_dns: join(root, 'android-wg.json'),
        underlay_lifecycle: join(root, 'android-underlay.json'),
        replacement_singleton: join(root, 'android-replacement.json'),
      },
      ios: {
        desktop_mobile_join: macosJoinPath,
        frozen_archive: join(root, 'ios.json'),
        join_variant: join(root, 'ios-join-test-variant.json'),
        mobile_artifact: join(root, 'ios-artifact.json'),
        mobile_join: mobileJoinPath,
        wireguard_dns: join(root, 'ios-wg.json'),
        underlay_lifecycle: join(root, 'ios-underlay.json'),
      },
      linux: {
        arm64_cli: join(root, 'linux-arm64-cli.json'),
        artifact: join(root, 'linux-artifact.json'),
        package_install: join(root, 'linux-package-install.json'),
        public_ui_join: join(root, 'linux-join.json'),
        network: join(root, 'linux-network.json'),
      },
      macos: {
        artifact: join(root, 'macos-artifact.json'),
        network_artifact: join(root, 'macos-network-artifact.json'),
        public_ui_join: macosJoinPath,
        network: join(root, 'macos-network.json'),
      },
      windows: {
        artifact: join(root, 'windows-artifact.json'),
        installer: join(root, 'windows-installer.json'),
        public_ui_join: join(root, 'windows-join.json'),
        network: join(root, 'windows-network.json'),
      },
    }
    const summary = join(root, 'summary.json')
    writeFileSync(summary, JSON.stringify({
      elapsedSeconds:
        process.env.NVPN_FLEET_GATE_TARGET_STATUS === 'missed' ? 301 : 42,
      targetSeconds: 300,
      targetStatus:
        process.env.NVPN_FLEET_GATE_TARGET_STATUS === 'missed'
          ? 'missed'
          : 'met',
    }))
    writeFileSync(paths.linux.arm64_cli, JSON.stringify({
      receiptSchema: 1,
      artifactType: 'exact native-smoked Linux ARM64 static CLI',
      appGitSha: source.appGitSha,
      appGitTree: source.appGitTree,
    }))
    const androidArtifact = {
      ...source,
      receiptSchema: 2,
      artifactType: 'Android Release APK',
      apkSha256: '1'.repeat(64),
      installedApkSha256: '1'.repeat(64),
      aabSha256: '0'.repeat(64),
      apkDerivedFromAab: true,
      bundleReceiptSha256: 'f'.repeat(64),
      bundletoolVersion: '1.18.3',
      bundletoolSha256:
        'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29',
      package: 'fi.siriusbusiness.nvpn',
      signerCertificateSha256: '2'.repeat(64),
      companySigningVerified: true,
      debuggable: false,
      fipsCoreVersion: source.fipsVersion,
      fipsCargoMetadataReceiptSha256: 'd'.repeat(64),
    }
    const iosArtifact = {
      ...source,
      receiptSchema: 2,
      artifactType: 'iOS company Ad Hoc Release app',
      appBundleTreeSha256: '3'.repeat(64),
      appCodeDirectoryHash: '4'.repeat(40),
      packetTunnelCodeDirectoryHash: '5'.repeat(40),
      appExecutableSha256: '6'.repeat(64),
      packetTunnelExecutableSha256: '7'.repeat(64),
      signerCertificateSha256: '8'.repeat(64),
      installedBundleIdentifier: 'fi.siriusbusiness.nvpn',
      fipsCoreVersion: source.fipsVersion,
    }
    const androidText = JSON.stringify(androidArtifact)
    const androidForegroundIdleRaw = {
      ok: true,
      mode: 'android-package',
      label: 'Android Release foreground VPN-off',
      maxPercent: 2,
      sampleSeconds: 60,
      settleSeconds: 10,
      elapsedSeconds: 60.25,
      cpuPercent: 1.25,
      package: androidArtifact.package,
      pids: [1234],
      clockTicks: 100,
      generatedAt: '2026-08-09T17:30:55Z',
    }
    const androidForegroundIdleRawText = JSON.stringify(
      androidForegroundIdleRaw,
    )
    const androidForegroundIdle = {
      ...source,
      receiptSchema: 1,
      artifactType:
        'Android exact Release foreground VPN-off idle CPU gate',
      platform: 'android',
      mode: 'foreground-vpn-off-idle',
      artifactReceiptSha256: sha256(androidText),
      artifactIdentity: {
        apkSha256: androidArtifact.apkSha256,
        installedApkSha256: androidArtifact.installedApkSha256,
        package: androidArtifact.package,
        signerCertificateSha256:
          androidArtifact.signerCertificateSha256,
      },
      rawIdleCpuReceiptSha256: sha256(androidForegroundIdleRawText),
      foregroundActivityVerified: true,
      vpnInactiveBeforeSample: true,
      releaseNonDebuggable: true,
      sample: androidForegroundIdleRaw,
    }
    const androidInstall = {
      artifact: 'Android Release APK',
      apkSha256: androidArtifact.apkSha256,
      installedApkSha256: androidArtifact.installedApkSha256,
      signerCertificateSha256: androidArtifact.signerCertificateSha256,
      appGitSha: androidArtifact.appGitSha,
      appGitTree: androidArtifact.appGitTree,
      fipsGitSha: androidArtifact.fipsGitSha,
      fipsGitTree: androidArtifact.fipsGitTree,
      package: androidArtifact.package,
      preexistingCanonicalPackage: true,
      replacementInstall: true,
      replacementInstallVerified: true,
      debuggable: false,
      canonicalPackageCount: 1,
      canonicalProcessCount: 1,
    }
    const androidInstallText = JSON.stringify(androidInstall)
    const iosText = JSON.stringify(iosArtifact)
    const iosJoinVariant = {
      ...iosArtifact,
      artifactType: 'iOS Ad Hoc Release join-test variant',
      appBundleTreeSha256: '9'.repeat(64),
      appCodeDirectoryHash: 'a'.repeat(40),
      appExecutableSha256: 'b'.repeat(64),
      fileSharingFixture: {
        bundleIdentifier: iosArtifact.installedBundleIdentifier,
        displayName: 'Nostr VPN Test Files',
        scope: 'join-test-variant-only',
      },
      joinTestingCompilationCondition: 'NVPN_RELEASE_JOIN_TESTING',
      joinTestingCompilationConditionEnabled: true,
      productionArtifactReceiptSha256: sha256(iosText),
      productionAppByteIdentical: false,
      companySigningVerified: true,
      debuggable: false,
    }
    const iosJoinVariantText = JSON.stringify(iosJoinVariant)
    writeFileSync(paths.android.physical, androidText)
    writeFileSync(paths.android.install, androidInstallText)
    writeFileSync(
      paths.android.foreground_idle_cpu_raw,
      androidForegroundIdleRawText,
    )
    writeFileSync(
      paths.android.foreground_idle_cpu,
      JSON.stringify(androidForegroundIdle),
    )
    writeFileSync(paths.ios.mobile_artifact, iosText)
    writeFileSync(paths.ios.join_variant, iosJoinVariantText)
    const networkReceipt = (platform, mode, artifact, artifactText) => ({
      ...source,
      appGitSha: artifact.appGitSha,
      appGitTree: artifact.appGitTree,
      fipsGitSha: artifact.fipsGitSha,
      fipsGitTree: artifact.fipsGitTree,
      receiptSchema: 1,
      artifactType: `physical ${platform} Release ${mode} gate`,
      platform,
      mode,
      artifactReceiptSha256: sha256(artifactText),
      artifactIdentity: platform === 'android'
        ? {
            apkSha256: artifact.apkSha256,
            installedApkSha256: artifact.installedApkSha256,
            package: artifact.package,
            signerCertificateSha256: artifact.signerCertificateSha256,
          }
        : {
            appBundleTreeSha256: artifact.appBundleTreeSha256,
            appCodeDirectoryHash: artifact.appCodeDirectoryHash,
            packetTunnelCodeDirectoryHash:
              artifact.packetTunnelCodeDirectoryHash,
            appExecutableSha256: artifact.appExecutableSha256,
            packetTunnelExecutableSha256:
              artifact.packetTunnelExecutableSha256,
            signerCertificateSha256: artifact.signerCertificateSha256,
            installedBundleIdentifier: artifact.installedBundleIdentifier,
          },
      dnsCases: Object.fromEntries(
        (mode === 'wireguard-dns'
          ? [
              'automatic-profile',
              'cloudflare-doh',
              'quad9-doh',
              'custom-doh',
              'through-exit',
            ]
          : ['automatic-profile'])
          .map((label) => {
            const policy = {
              'automatic-profile': ['dns-profile', ['query', 'profile']],
              'cloudflare-doh': [
                'doh-cloudflare',
                ['cloudflareSni'],
              ],
              'quad9-doh': ['doh-quad9', ['quad9Sni']],
              'custom-doh': ['doh-google', ['googleSni']],
              'through-exit': ['dns-through', ['query', 'through']],
            }[label]
            const counters = [
              'query',
              'profile',
              'cloudflareSni',
              'quad9Sni',
              'googleSni',
              'through',
              'forward',
            ]
            const before = Object.fromEntries(
              counters.map((counter) => [counter, 1]),
            )
            const after = { ...before }
            for (const counter of policy[1]) {
              if (platform !== 'ios' || !counter.endsWith('Sni')) {
                after[counter] += 1
              }
            }
            return [label, {
              dnsEvidence: policy[0],
              wireGuardRxBytesBefore: 1,
              wireGuardRxBytesAfter: 2,
              wireGuardTxBytesBefore: 1,
              wireGuardTxBytesAfter: 2,
              forwardedPacketsBefore: 1,
              forwardedPacketsAfter: 2,
              dnsPathCountersBefore: before,
              dnsPathCountersAfter: after,
              dnsPathCountersBeforeObservedAtUnix: 1,
              dnsPathCountersAfterObservedAtUnix: 2,
            }]
          }),
      ),
      support: mode === 'wireguard-dns'
        ? {
            ...(platform === 'android'
              ? {
                  startStopCycles: 2,
                  directBeforeConnectedAfter: true,
                }
              : { rapidStartStopCycles: 8 }),
          }
        : {
            lifecycleCycles: 3,
            underlayCycles: [{
              dnsAndWireGuardRecoveryMilliseconds: 200,
              firstReversePayloadRecoveryMilliseconds: 200,
              freshDnsFixtureExactQueryCount: 1,
              freshDnsQueryHost:
                '12345678-1234-1234-1234-123456789abc.fixture.test',
              gate: 'wifi-radio-off-on-recovery',
              noValidatedPhysicalFallbackEvidenceCount:
                platform === 'android' ? 2 : 1,
              originalWifiRestoredEvidenceCount: 1,
              outageReversePayloads: 0,
              processIdentifierCounts: platform === 'android'
                ? { app: 1, nativeTunnel: 1 }
                : { app: 1, packetTunnel: 1 },
            }],
            ...(platform === 'android'
              ? { postForegroundDnsHttpsAndTunnelCycles: 3 }
              : {}),
          },
      evidenceFiles: mode === 'wireguard-dns'
        ? {
            'receipt.json': 'e'.repeat(64),
            [`mobile-${platform}-network-counter-ledger.tsv`]:
              'e'.repeat(64),
          }
        : Object.fromEntries(
            (platform === 'android'
              ? [
                  'mobile-android-underlay-1-summary.json',
                  'mobile-android-underlay-1-markers.tsv',
                  'mobile-android-underlay-1-continuity.log',
                  'mobile-android-underlay-fresh-dns-fixture.json',
                  'mobile-android-radio-bounce-dns-1.log',
                  'mobile-android-radio-bounce-udp-1.log',
                ]
              : [
                  'mobile-ios-release-network-automatic-profile-1-continuity.json',
                  'mobile-ios-release-network-automatic-profile-1-host-markers.tsv',
                  'mobile-ios-release-network-automatic-profile-1-processes.json',
                  'mobile-ios-release-network-automatic-profile-1-reverse-payload.log',
                  'mobile-ios-release-network-automatic-profile-1-runner-markers.log',
                  'mobile-ios-underlay-fresh-dns-fixture.json',
                ]).concat(`mobile-${platform}-network-counter-ledger.tsv`)
              .map((path) => [path, 'e'.repeat(64)]),
          ),
    })
    writeFileSync(
      paths.android.wireguard_dns,
      JSON.stringify(networkReceipt(
        'android',
        'wireguard-dns',
        androidArtifact,
        androidText,
      )),
    )
    writeFileSync(
      paths.android.underlay_lifecycle,
      JSON.stringify(networkReceipt(
        'android',
        'underlay-lifecycle',
        androidArtifact,
        androidText,
      )),
    )
    writeFileSync(paths.android.replacement_singleton, JSON.stringify({
      ...source,
      receiptSchema: 1,
      artifactType: 'Android Release replacement/singleton gate',
      artifactReceiptSha256: sha256(androidText),
      apkSha256: androidArtifact.apkSha256,
      installedApkSha256: androidArtifact.installedApkSha256,
      package: androidArtifact.package,
      signerCertificateSha256: androidArtifact.signerCertificateSha256,
      canonicalPackageCount: 1,
      retiredPackageCount: 0,
      canonicalMainProcessCount: 1,
      canonicalReplacementInstallVerified: true,
      sealedReleaseNonDebuggable: true,
      shippedRemovalPrompt: true,
      vpnServiceInactiveWhilePromptShown: true,
      systemUninstallConfirmed: true,
    }))
    writeFileSync(
      paths.ios.wireguard_dns,
      JSON.stringify(networkReceipt(
        'ios',
        'wireguard-dns',
        iosArtifact,
        iosText,
      )),
    )
    writeFileSync(
      paths.ios.underlay_lifecycle,
      JSON.stringify(networkReceipt(
        'ios',
        'underlay-lifecycle',
        iosArtifact,
        iosText,
      )),
    )
    writeFileSync(mobileJoinPath, JSON.stringify({
      schema: 1,
      platform: 'mobile',
      coverageScope: 'android-ios-mobile-only',
      harnessGitSha: '8'.repeat(40),
      harnessGitTree: '9'.repeat(40),
      artifact: {
        android: {
          appGitSha: androidArtifact.appGitSha,
          appGitTree: androidArtifact.appGitTree,
          fipsGitSha: androidArtifact.fipsGitSha,
          fipsGitTree: androidArtifact.fipsGitTree,
          artifactReceiptSha256: sha256(androidText),
          apkSha256: androidArtifact.apkSha256,
          installedApkSha256: androidArtifact.installedApkSha256,
          package: androidArtifact.package,
          signerCertificateSha256:
            androidArtifact.signerCertificateSha256,
        },
        ios: {
          appGitSha: iosJoinVariant.appGitSha,
          appGitTree: iosJoinVariant.appGitTree,
          fipsGitSha: iosJoinVariant.fipsGitSha,
          fipsGitTree: iosJoinVariant.fipsGitTree,
          artifactReceiptSha256: sha256(iosJoinVariantText),
          productionArtifactReceiptSha256: sha256(iosText),
          joinTestingCompilationCondition: 'NVPN_RELEASE_JOIN_TESTING',
          joinTestingCompilationConditionEnabled: true,
          fileSharingFixture: iosJoinVariant.fileSharingFixture,
          productionAppByteIdentical: false,
          appBundleTreeSha256: iosJoinVariant.appBundleTreeSha256,
          appCodeDirectoryHash: iosJoinVariant.appCodeDirectoryHash,
          packetTunnelCodeDirectoryHash:
            iosJoinVariant.packetTunnelCodeDirectoryHash,
          appExecutableSha256: iosJoinVariant.appExecutableSha256,
          packetTunnelExecutableSha256:
            iosJoinVariant.packetTunnelExecutableSha256,
          signerCertificateSha256: iosJoinVariant.signerCertificateSha256,
          installedBundleIdentifier: iosJoinVariant.installedBundleIdentifier,
        },
      },
      publicUiOnly: true,
      productionImageImportQr: false,
      iosJoinTestVariant: true,
      testOnlyImageImportQr: true,
      productionQrDecoderPath: true,
      productionJoinApprovalPath: true,
      productionRosterPath: true,
      actualRenderedQrScreenCapture: {
        androidRenderedScreenSha256: 'a'.repeat(64),
        iosRenderedScreenSha256: 'b'.repeat(64),
      },
      privateAppStateRead: false,
      appLaunchArgumentsOrEnvironment: false,
      deliveryDeadlineMilliseconds: 15_000,
      deliveryMilliseconds: {
        'iPhone-admin-to-Pixel-QR': 100,
        'Pixel-admin-to-iPhone-QR': 100,
        'iPhone-admin-to-Pixel-manual': 100,
        'Pixel-admin-to-iPhone-manual': 100,
      },
      contentWidth: {
        minimumRequiredBasisPoints: 9800,
        maximumAllowedBasisPoints: 10_000,
        androidObservedBasisPoints: 10_000,
        iosObservedBasisPoints: 10_000,
      },
      qr: {
        iphoneAdminPixelJoiner: true,
        pixelAdminIphoneJoiner: true,
        pendingQrBackgroundForeground: true,
        exactRosterOnBothSides: true,
        joinerRelaunchDurable: true,
        androidJoinerRelaunchDurable: true,
        iphoneJoinerRelaunchDurable: true,
      },
      manual: {
        iphoneAdminPixelJoiner: true,
        pixelAdminIphoneJoiner: true,
        exactRosterOnBothSides: true,
        acceptedRosterOnly: true,
        iphoneAdminPixelJoinerRelaunchDurable: true,
        pixelAdminIphoneJoinerRelaunchDurable: true,
      },
    }))
    const macosArtifact = {
      ...source,
      receiptSchema: 1,
      companySigningVerified: true,
      builtOnHost: true,
      builtOnTestVm: false,
      fipsCoreVersion: source.fipsVersion,
      appExecutableSha256: '9'.repeat(64),
      cliExecutableSha256: 'a'.repeat(64),
    }
    const macosText = JSON.stringify(macosArtifact)
    writeFileSync(paths.macos.artifact, macosText)
    writeFileSync(paths.macos.network_artifact, macosText)
    writeFileSync(paths.macos.public_ui_join, JSON.stringify({
      ...source,
      schema: 1,
      platform: 'macos',
      artifact: {
        ...source,
        artifactReceiptSha256: sha256(macosText),
        appExecutableSha256: macosArtifact.appExecutableSha256,
        android: {
          appGitSha: androidArtifact.appGitSha,
          appGitTree: androidArtifact.appGitTree,
          fipsGitSha: androidArtifact.fipsGitSha,
          fipsGitTree: androidArtifact.fipsGitTree,
          artifactReceiptSha256: sha256(androidText),
          artifactReceiptSize: Buffer.byteLength(androidText),
          installReceiptSha256: sha256('independent exact macOS join install'),
          installReceiptSize: 820,
          apkSha256: androidArtifact.apkSha256,
          installedApkSha256: androidArtifact.installedApkSha256,
          package: androidArtifact.package,
          signerCertificateSha256:
            androidArtifact.signerCertificateSha256,
        },
        ios: {
          appGitSha: iosJoinVariant.appGitSha,
          appGitTree: iosJoinVariant.appGitTree,
          fipsGitSha: iosJoinVariant.fipsGitSha,
          fipsGitTree: iosJoinVariant.fipsGitTree,
          artifactReceiptSha256: sha256(iosJoinVariantText),
          appBundleTreeSha256: iosJoinVariant.appBundleTreeSha256,
          appCodeDirectoryHash: iosJoinVariant.appCodeDirectoryHash,
          packetTunnelCodeDirectoryHash:
            iosJoinVariant.packetTunnelCodeDirectoryHash,
          appExecutableSha256: iosJoinVariant.appExecutableSha256,
          packetTunnelExecutableSha256:
            iosJoinVariant.packetTunnelExecutableSha256,
          signerCertificateSha256:
            iosJoinVariant.signerCertificateSha256,
          installedBundleIdentifier:
            iosJoinVariant.installedBundleIdentifier,
        },
      },
      publicUiOnly: true,
      privateAppStateRead: false,
      privateStateRead: false,
      fixtureInvoked: false,
      acceptedSelectorSemantics: 'participant-state-not-pending',
      appLaunchArgumentsOrEnvironment: false,
      desktopAdminAndroidJoiner: true,
      androidAdminDesktopJoiner: true,
      desktopAdminIphoneJoiner: true,
      iphoneAdminDesktopJoiner: true,
      exactRosterOnBothSides: true,
      acceptedRosterRetainedAcrossRelaunch: true,
      desktopRelaunchDurability: true,
      pixelRelaunchDurability: true,
      desktopAdminIphoneJoinerRelaunchDurable: true,
      iphoneAdminDesktopJoinerRelaunchDurable: true,
      deliveryDeadlineMilliseconds: 15_000,
      deliveryMilliseconds: {
        'macOS-admin-to-Android-manual': 100,
        'Android-admin-to-macOS-manual': 100,
        'macOS-admin-to-iPhone-manual': 100,
        'iPhone-admin-to-macOS-manual': 100,
      },
    }))
    writeFileSync(paths.macos.network, JSON.stringify({
      ...source,
      receiptSchema: 1,
      artifactType: 'macos Release desktop network gate',
      platform: 'macos',
      summary: {
        artifactReceiptSha256: sha256(macosText),
        dnsPolicyCount: 5,
        dnsUiPolicyCount: 5,
        dnsUiCases: desktopDnsUiCases(
          macosArtifact.appExecutableSha256,
          macosArtifact.cliExecutableSha256,
        ),
        handoffRecoveryMilliseconds: [100, 200],
        underlayActivationMilliseconds: [300, 400],
        handoffTransitionMilliseconds: [400, 600],
        crashRestartPayloadMilliseconds: 300,
        directRestored: true,
        singletonAfterCrashRecovery: true,
      },
      evidenceFiles: { 'direct.txt': 'f'.repeat(64) },
      desktopDnsUiEvidenceFiles,
    }))
    const mobileJoinSha = sha256(readFileSync(mobileJoinPath))
    const macosJoinSha = sha256(readFileSync(paths.macos.public_ui_join))
    const iosWgSha = sha256(readFileSync(paths.ios.wireguard_dns))
    const iosUnderlaySha = sha256(
      readFileSync(paths.ios.underlay_lifecycle),
    )
    writeFileSync(paths.ios.frozen_archive, JSON.stringify({
      ...source,
      receiptSchema: 1,
      artifactType: 'iOS frozen archive physical-gate seal',
      mobileArtifactReceiptSha256: sha256(iosText),
      mobileJoinIosVariantReceiptSha256: sha256(iosJoinVariantText),
      requiredRealDeviceGates: [
        'background-foreground-and-rapid-start-stop',
        'bidirectional-mobile-qr-and-manual-join',
        'desktop-mobile-manual-join',
        'wifi-radio-off-on-recovery',
        'wireguard-exit-and-five-dns-policies',
      ],
      realDeviceGateReceiptSha256: {
        'background-foreground-and-rapid-start-stop': [
          iosWgSha,
          iosUnderlaySha,
        ],
        'bidirectional-mobile-qr-and-manual-join': [
          mobileJoinSha,
          sha256(iosJoinVariantText),
        ],
        'desktop-mobile-manual-join': [
          macosJoinSha,
          sha256(iosJoinVariantText),
        ],
        'wifi-radio-off-on-recovery': [iosUnderlaySha],
        'wireguard-exit-and-five-dns-policies': [iosWgSha],
      },
    }))
    for (const platform of ['linux', 'windows']) {
      const desktopArtifact = {
        ...source,
        schema: platform === 'linux' ? 2 : 1,
        fipsVersion: '0.4.45',
        appVersion: '4.1.5',
        ...(platform === 'linux'
          ? {
              builderMode: 'remote-native',
              builtOnHostMac: false,
              builtOnRemoteVm: true,
              builderHostOs: 'Linux',
              builderHostArchitecture: 'x86_64',
              containerImageId: `sha256:${'1'.repeat(64)}`,
              dockerfileSha256: '2'.repeat(64),
              containerPayloadSha256: '3'.repeat(64),
            }
          : {}),
        artifacts: {
          app: { sha256: 'a'.repeat(64), size: 100 },
          cli: { sha256: 'b'.repeat(64), size: 200 },
          ...(platform === 'linux'
            ? {
                debianPackage: { sha256: 'c'.repeat(64), size: 300 },
                muslCli: { sha256: 'd'.repeat(64), size: 400 },
                muslCliArchive: {
                  sha256: 'e'.repeat(64),
                  size: 500,
                },
              }
            : {}),
          ...(platform === 'windows'
            ? {
                appCore: { sha256: 'c'.repeat(64), size: 300 },
                wintun: { sha256: 'd'.repeat(64), size: 400 },
              }
            : {}),
        },
      }
      const desktopArtifactText = JSON.stringify(desktopArtifact)
      writeFileSync(paths[platform].artifact, desktopArtifactText)
      if (platform === 'windows') {
        writeFileSync(paths.windows.installer, JSON.stringify({
          ...source,
          receiptSchema: 2,
          platform: 'windows',
          artifactType: 'exact installed Windows Release setup',
          tag: `v${desktopArtifact.appVersion}`,
          installerName:
            `nostr-vpn-v${desktopArtifact.appVersion}-windows-x64-setup.exe`,
          installerSha256: 'e'.repeat(64),
          installerSize: 500,
          installerInstalledAndLaunched: true,
          installedAppStayedAlive: true,
          smokeReceiptSha256: 'f'.repeat(64),
          payloads: Object.fromEntries(
            ['app', 'appCore', 'cli', 'wintun'].map((name) => [
              name,
              desktopArtifact.artifacts[name],
            ]),
          ),
          builtOnWindowsVm: true,
          builtOnHostMac: false,
        }))
      }
      if (platform === 'linux') {
        writeFileSync(paths.linux.package_install, JSON.stringify({
          ...source,
          schema: 2,
          artifactType:
            'exact Debian package installed on Ubuntu VM',
          appVersion: desktopArtifact.appVersion,
          builderMode: desktopArtifact.builderMode,
          builtOnHostMac: desktopArtifact.builtOnHostMac,
          builtOnRemoteVm: desktopArtifact.builtOnRemoteVm,
          builderHostOs: desktopArtifact.builderHostOs,
          builderHostArchitecture: desktopArtifact.builderHostArchitecture,
          containerImageId: desktopArtifact.containerImageId,
          dockerfileSha256: desktopArtifact.dockerfileSha256,
          containerPayloadSha256:
            desktopArtifact.containerPayloadSha256,
          package: 'nostr-vpn',
          packageArchitecture: 'amd64',
          packageInstalledByDpkg: true,
          installedStatus: 'installed',
          installedAppPath: '/usr/bin/nostr-vpn',
          installedCliPath: '/usr/bin/nvpn',
          debSha256: desktopArtifact.artifacts.debianPackage.sha256,
          debSize: desktopArtifact.artifacts.debianPackage.size,
          installedAppSha256: desktopArtifact.artifacts.app.sha256,
          installedCliSha256: desktopArtifact.artifacts.cli.sha256,
          muslCliSha256: desktopArtifact.artifacts.muslCli.sha256,
          muslArchiveSha256:
            desktopArtifact.artifacts.muslCliArchive.sha256,
          bundleReceiptSha256: sha256(desktopArtifactText),
          packagePayloadVerifiedBeforeInstall: true,
          desktopEntryPresent: true,
          iconThemeAssetPresent: true,
          muslArchiveExtractedAndExecuted: true,
        }))
      }
      writeFileSync(paths[platform].public_ui_join, JSON.stringify({
        schema: 2,
        platform,
        artifact: {
          desktop: {
            appGitSha: desktopArtifact.appGitSha,
            appGitTree: desktopArtifact.appGitTree,
            fipsGitSha: desktopArtifact.fipsGitSha,
            fipsGitTree: desktopArtifact.fipsGitTree,
            fipsVersion: desktopArtifact.fipsVersion,
            artifactReceiptSha256: sha256(desktopArtifactText),
            artifactReceiptSize: Buffer.byteLength(desktopArtifactText),
            appSha256: desktopArtifact.artifacts.app.sha256,
            appSize: desktopArtifact.artifacts.app.size,
            cliSha256: desktopArtifact.artifacts.cli.sha256,
            cliSize: desktopArtifact.artifacts.cli.size,
            appVersion: desktopArtifact.appVersion,
            ...(platform === 'windows'
              ? {
                  appCoreSha256:
                    desktopArtifact.artifacts.appCore.sha256,
                  appCoreSize: desktopArtifact.artifacts.appCore.size,
                }
              : {}),
          },
          android: {
            appGitSha: androidArtifact.appGitSha,
            appGitTree: androidArtifact.appGitTree,
            fipsGitSha: androidArtifact.fipsGitSha,
            fipsGitTree: androidArtifact.fipsGitTree,
            fipsVersion: androidArtifact.fipsCoreVersion,
            fipsMetadataReceiptSha256:
              androidArtifact.fipsCargoMetadataReceiptSha256,
            artifactReceiptSha256: sha256(androidText),
            artifactReceiptSize: Buffer.byteLength(androidText),
            installReceiptSha256: sha256(androidInstallText),
            installReceiptSize: Buffer.byteLength(androidInstallText),
            apkSha256: androidArtifact.apkSha256,
            apkSize: 400,
            signerCertificateSha256:
              androidArtifact.signerCertificateSha256,
            package: androidArtifact.package,
          },
        },
        publicUiOnly: true,
        privateStateRead: false,
        fixtureInvoked: false,
        appLaunchArgumentsOrEnvironment: false,
        acceptedSelectorSemantics: 'participant-state-not-pending',
        desktopRelaunchDurability: true,
        pixelRelaunchDurability: true,
        completionDeadlineSeconds: 15,
        desktopAdminPixelJoiner: {
          desktopAccepted: true,
          pixelAccepted: true,
          desktopRelaunchAccepted: true,
          pixelRelaunchAccepted: true,
          deliveryMilliseconds: 100,
        },
        pixelAdminDesktopJoiner: {
          desktopAccepted: true,
          pixelAccepted: true,
          desktopRelaunchAccepted: true,
          pixelRelaunchAccepted: true,
          deliveryMilliseconds: 100,
        },
      }))
      writeFileSync(paths[platform].network, JSON.stringify({
        ...source,
        receiptSchema: 1,
        artifactType: `${platform} Release desktop network gate`,
        platform,
        summary: {
          dnsPolicyCount: 5,
          dnsUiPolicyCount: 5,
          dnsUiCases: desktopDnsUiCases(
            desktopArtifact.artifacts.app.sha256,
            desktopArtifact.artifacts.cli.sha256,
          ),
          dnsCases: {
            automatic: desktopDnsCase('profile_dns'),
            cloudflare: desktopDnsCase('cloudflare'),
            custom: desktopDnsCase('google'),
            quad9: desktopDnsCase('quad9'),
            'through-exit': desktopDnsCase('fixture_dns'),
          },
          handoffs: {
            primaryToSecondary: {
              recoveryMilliseconds: 100,
              payloadDelta: 1,
              wireGuardPayloadDelta: 1,
              rebindDelta: 1,
            },
            secondaryToPrimary: {
              recoveryMilliseconds: 100,
              payloadDelta: 1,
              wireGuardPayloadDelta: 1,
              rebindDelta: 1,
            },
          },
          directRestored: true,
          singletonAfterCrashRecovery: true,
          testedCliSha256: desktopArtifact.artifacts.cli.sha256,
          testedCliSize: desktopArtifact.artifacts.cli.size,
          ...(platform === 'linux'
            ? {
                crashRepairMilliseconds: 100,
                artifactReceiptSha256: sha256(desktopArtifactText),
              }
            : { nativeWireGuardOwnerFilesRepaired: true }),
        },
        evidenceFiles: { 'direct-receipt.json': 'f'.repeat(64) },
        desktopDnsUiEvidenceFiles,
      }))
    }

    const evidence = collectReleaseGateReceipts({
      commit,
      tree,
      releaseGateSummaryPath: summary,
      platformReceiptPaths: paths,
    })
    assert.deepEqual(
      Object.keys(evidence.platformGateReceipts).sort(),
      ['android', 'ios', 'linux', 'macos', 'windows'],
    )

    const fullMacosText = readFileSync(paths.macos.public_ui_join, 'utf8')
    const pixelReceipt = JSON.parse(fullMacosText)
    pixelReceipt.selectedDirections = 'pixel'
    for (const key of [
      'desktopAdminIphoneJoiner', 'iphoneAdminDesktopJoiner',
      'desktopAdminIphoneJoinerRelaunchDurable',
      'iphoneAdminDesktopJoinerRelaunchDurable',
    ]) pixelReceipt[key] = false
    delete pixelReceipt.artifact.ios
    delete pixelReceipt.deliveryMilliseconds['macOS-admin-to-iPhone-manual']
    delete pixelReceipt.deliveryMilliseconds['iPhone-admin-to-macOS-manual']
    const pixelArgs = {
      receipt: pixelReceipt,
      artifactReceipt: JSON.parse(readFileSync(paths.macos.artifact, 'utf8')),
      artifactReceiptSha256: sha256(readFileSync(paths.macos.artifact)),
      androidArtifact: JSON.parse(readFileSync(paths.android.physical, 'utf8')),
      androidArtifactReceiptSha256: sha256(readFileSync(paths.android.physical)),
      androidInstallReceiptSha256: pixelReceipt.artifact.android.installReceiptSha256,
      androidInstallReceiptSize: pixelReceipt.artifact.android.installReceiptSize,
    }
    assert.deepEqual(validateMacosPixelJoinReceipt(pixelArgs), pixelReceipt.deliveryMilliseconds)
    for (const mutate of [
      (r) => { r.pixelRelaunchDurability = false },
      (r) => { r.desktopAdminIphoneJoiner = true },
      (r) => { r.selectedDirections = 'all' },
      (r) => { r.publicUiOnly = false },
      (r) => { r.deliveryMilliseconds['macOS-admin-to-Android-manual'] = 15_001 },
      (r) => { delete r.deliveryMilliseconds['Android-admin-to-macOS-manual'] },
      (r) => { r.artifact.appExecutableSha256 = '0'.repeat(64) },
      (r) => { r.artifact.android.installedApkSha256 = '0'.repeat(64) },
      (r) => { r.artifact.android.installReceiptSha256 = '0'.repeat(64) },
      (r) => { r.artifact.android.installReceiptSize += 1 },
    ]) {
      const receipt = structuredClone(pixelReceipt)
      mutate(receipt)
      assert.throws(() => validateMacosPixelJoinReceipt({ ...pixelArgs, receipt }))
    }
    // A retained Pixel receipt alone must never satisfy the full release gate.
    writeFileSync(paths.macos.public_ui_join, JSON.stringify(pixelReceipt))
    assert.throws(() => collectReleaseGateReceipts({
      commit, tree, releaseGateSummaryPath: summary, platformReceiptPaths: paths,
    }), /macOS\/mobile public-UI join receipt is incomplete/)
    writeFileSync(paths.macos.public_ui_join, fullMacosText)
    const hostSource = readFileSync(join(process.cwd(),
      'scripts/macos-vm-release-mobile-join-e2e.sh'), 'utf8')
    assert.ok(hostSource.includes('reuse_pixel_coverage() {'))
    const reuseFunction = 'reuse_pixel_coverage() {' + hostSource
      .split('reuse_pixel_coverage() {')[1].split('\nwrite_component_proof()')[0]
    assert.match(hostSource, /&& -z "\$REUSED_PIXEL_RECEIPT_SHA256" \]\]; then/)
    const retainedPath = join(root, 'retained-pixel.json')
    const reuseOutput = join(root, 'resume-macos')
    pixelReceipt.artifact.android.installReceiptSha256 = sha256(readFileSync(paths.android.install))
    pixelReceipt.artifact.android.installReceiptSize = readFileSync(paths.android.install).length
    write(retainedPath, JSON.stringify(pixelReceipt))
    write(join(reuseOutput, 'macos/artifact.json'), readFileSync(paths.macos.artifact))
    const reuse = () => spawnSync('bash', ['-euo', 'pipefail', '-c', `${reuseFunction}\nreuse_pixel_coverage`], {
      encoding: 'utf8',
      env: {
        ...process.env, ROOT: process.cwd(), REUSE_PIXEL_RECEIPT: retainedPath,
        RESULT_DIR: reuseOutput, ANDROID_ARTIFACT_RECEIPT: paths.android.physical,
        ANDROID_INSTALL_RECEIPT: paths.android.install,
      },
    })
    const reused = reuse()
    assert.equal(reused.status, 0, reused.stderr)
    assert.equal(reused.stdout.trim(), sha256(readFileSync(retainedPath)))
    assert.deepEqual(readFileSync(join(reuseOutput, 'macos/reused-pixel-summary.json')),
      readFileSync(retainedPath))
    assert.equal(readFileSync(join(reuseOutput, 'macos/delivery-times.tsv'), 'utf8'),
      Object.entries(pixelReceipt.deliveryMilliseconds).map(([label, ms]) => `${label}\t${ms}\n`).join(''))
    assert.equal(reuse().status, 0, 'identical retained evidence is reusable')
    const retainedTimingsPath = join(reuseOutput, 'macos/delivery-times.tsv')
    const retainedTimings = readFileSync(retainedTimingsPath)
    writeFileSync(retainedTimingsPath, 'changed evidence\n')
    assert.notEqual(reuse().status, 0, 'a rerun must reject changed retained evidence')
    assert.equal(readFileSync(retainedTimingsPath, 'utf8'), 'changed evidence\n')
    writeFileSync(retainedTimingsPath, retainedTimings)

    const wireguardText = readFileSync(paths.android.wireguard_dns, 'utf8')
    const combinedWireguard = JSON.parse(wireguardText)
    const underlayForCombined = JSON.parse(
      readFileSync(paths.android.underlay_lifecycle, 'utf8'),
    )
    combinedWireguard.coveredModes = [
      'wireguard-dns',
      'underlay-lifecycle',
    ]
    Object.assign(combinedWireguard.support, underlayForCombined.support)
    Object.assign(
      combinedWireguard.evidenceFiles,
      underlayForCombined.evidenceFiles,
    )
    writeFileSync(
      paths.android.wireguard_dns,
      JSON.stringify(combinedWireguard),
    )
    assert.doesNotThrow(() => collectReleaseGateReceipts({
      commit,
      tree,
      releaseGateSummaryPath: summary,
      platformReceiptPaths: paths,
    }))
    const separateAndroidUnderlayPath = paths.android.underlay_lifecycle
    paths.android.underlay_lifecycle = paths.android.wireguard_dns
    assert.doesNotThrow(() => collectReleaseGateReceipts({
      commit,
      tree,
      releaseGateSummaryPath: summary,
      platformReceiptPaths: paths,
    }))
    paths.android.underlay_lifecycle = separateAndroidUnderlayPath
    const separateAndroidUnderlayText = readFileSync(
      separateAndroidUnderlayPath,
      'utf8',
    )
    rmSync(separateAndroidUnderlayPath)
    assert.doesNotThrow(() => collectReleaseGateReceipts({
      commit,
      tree,
      releaseGateSummaryPath: summary,
      platformReceiptPaths: paths,
    }))
    writeFileSync(separateAndroidUnderlayPath, separateAndroidUnderlayText)
    combinedWireguard.coveredModes = ['wireguard-dns', 'underlay-lifecycle']
    delete combinedWireguard.support.underlayCycles
    writeFileSync(
      paths.android.wireguard_dns,
      JSON.stringify(combinedWireguard),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /underlay\/lifecycle receipt is incomplete/,
    )
    writeFileSync(paths.android.wireguard_dns, wireguardText)

    const assertRejectedReceiptMutation = (path, mutate, error) => {
      const original = readFileSync(path, 'utf8')
      const mutated = JSON.parse(original)
      mutate(mutated)
      writeFileSync(path, JSON.stringify(mutated))
      assert.throws(
        () => collectReleaseGateReceipts({
          commit,
          tree,
          releaseGateSummaryPath: summary,
          platformReceiptPaths: paths,
        }),
        error,
      )
      writeFileSync(path, original)
    }
    assertRejectedReceiptMutation(
      paths.macos.network,
      (receipt) => {
        receipt.summary.handoffTransitionMilliseconds[0] += 1
      },
      /macOS desktop network receipt is incomplete/,
    )
    const originalMacosNetwork = readFileSync(paths.macos.network, 'utf8')
    const networkArtifact = {
      ...macosArtifact,
      manualJoinDriverSha256: 'b'.repeat(64),
      packageTreeSha256: 'c'.repeat(64),
    }
    const networkArtifactText = JSON.stringify(networkArtifact)
    writeFileSync(paths.macos.network_artifact, networkArtifactText)
    const separatelyPackagedNetwork = JSON.parse(originalMacosNetwork)
    separatelyPackagedNetwork.summary.artifactReceiptSha256 = sha256(networkArtifactText)
    writeFileSync(paths.macos.network, JSON.stringify(separatelyPackagedNetwork))
    assert.doesNotThrow(() => collectReleaseGateReceipts({
      commit, tree, releaseGateSummaryPath: summary, platformReceiptPaths: paths,
    }))
    for (const key of [
      'appExecutableSha256', 'cliExecutableSha256', 'appBundleTreeSha256',
      'appGitSha', 'fipsGitSha', 'signerCertificateSha256',
    ]) {
      assertRejectedReceiptMutation(
        paths.macos.network_artifact,
        (receipt) => { receipt[key] = '0'.repeat(64) },
        /macOS network and join packages contain different product evidence/,
      )
    }
    assertRejectedReceiptMutation(
      paths.macos.network,
      (receipt) => { receipt.summary.artifactReceiptSha256 = '0'.repeat(64) },
      /macOS desktop network receipt is incomplete/,
    )
    writeFileSync(paths.macos.network_artifact, macosText)
    writeFileSync(paths.macos.network, originalMacosNetwork)
    const androidIdentityPaths = [
      paths.android.physical,
      paths.android.install,
      paths.android.foreground_idle_cpu,
      paths.android.wireguard_dns,
      paths.android.underlay_lifecycle,
      paths.android.replacement_singleton,
    ]
    const originalAndroidIdentityFiles = new Map(
      androidIdentityPaths.map((path) => [path, readFileSync(path, 'utf8')]),
    )
    const oldCommit = 'e'.repeat(40)
    const oldTree = 'f'.repeat(40)
    for (const path of androidIdentityPaths) {
      const receipt = JSON.parse(originalAndroidIdentityFiles.get(path))
      receipt.appGitSha = oldCommit
      receipt.appGitTree = oldTree
      writeFileSync(path, JSON.stringify(receipt))
    }
    const originalMobileJoin = readFileSync(mobileJoinPath, 'utf8')
    const oldMobileJoin = JSON.parse(originalMobileJoin)
    oldMobileJoin.artifact.android.appGitSha = oldCommit
    oldMobileJoin.artifact.android.appGitTree = oldTree
    writeFileSync(mobileJoinPath, JSON.stringify(oldMobileJoin))
    const originalDesktopJoinFiles = new Map()
    for (const platform of ['linux', 'windows']) {
      const path = paths[platform].public_ui_join
      const original = readFileSync(path, 'utf8')
      originalDesktopJoinFiles.set(path, original)
      const receipt = JSON.parse(original)
      receipt.artifact.android.appGitSha = oldCommit
      receipt.artifact.android.appGitTree = oldTree
      writeFileSync(path, JSON.stringify(receipt))
    }
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /Physical Android artifact receipt.*release candidate/i,
      'a self-consistent signed old Android component must not be promotable',
    )
    for (const [path, original] of originalAndroidIdentityFiles) {
      writeFileSync(path, original)
    }
    writeFileSync(mobileJoinPath, originalMobileJoin)
    for (const [path, original] of originalDesktopJoinFiles) {
      writeFileSync(path, original)
    }
    assertRejectedReceiptMutation(
      mobileJoinPath,
      (receipt) => {
        receipt.coverageScope = 'android-ios-desktop'
      },
      /mobile join receipt is not strict public-UI\/relaunch evidence/,
    )
    assertRejectedReceiptMutation(
      mobileJoinPath,
      (receipt) => {
        receipt.contentWidth.androidObservedBasisPoints = 10_001
      },
      /mobile join receipt is not strict public-UI\/relaunch evidence/,
    )
    assertRejectedReceiptMutation(
      mobileJoinPath,
      (receipt) => {
        receipt.qr.iphoneJoinerRelaunchDurable = false
      },
      /mobile join receipt is not strict public-UI\/relaunch evidence/,
    )
    assertRejectedReceiptMutation(
      mobileJoinPath,
      (receipt) => {
        receipt.manual.pixelAdminIphoneJoinerRelaunchDurable = false
      },
      /mobile join receipt is not strict public-UI\/relaunch evidence/,
    )
    assertRejectedReceiptMutation(
      mobileJoinPath,
      (receipt) => {
        receipt.artifact.ios.appCodeDirectoryHash = '0'.repeat(40)
      },
      /iOS mobile join artifact identity differs at appCodeDirectoryHash/,
    )
    assertRejectedReceiptMutation(
      paths.ios.join_variant,
      (receipt) => {
        receipt.joinTestingCompilationConditionEnabled = false
      },
      /join-test variant receipt is incomplete/,
    )
    assertRejectedReceiptMutation(
      paths.ios.join_variant,
      (receipt) => {
        receipt.fileSharingFixture.scope = 'production'
      },
      /join-test variant receipt is incomplete/,
    )
    assertRejectedReceiptMutation(
      paths.ios.join_variant,
      (receipt) => {
        receipt.productionArtifactReceiptSha256 = '0'.repeat(64)
      },
      /join-test variant receipt is incomplete/,
    )
    assertRejectedReceiptMutation(
      macosJoinPath,
      (receipt) => {
        receipt.iphoneAdminDesktopJoinerRelaunchDurable = false
      },
      /macOS\/mobile public-UI join receipt is incomplete/,
    )
    assertRejectedReceiptMutation(
      macosJoinPath,
      (receipt) => {
        receipt.artifact.android.installReceiptSha256 = 'invalid'
      },
      /macOS\/Android join install receipt/i,
    )
    assertRejectedReceiptMutation(
      paths.windows.public_ui_join,
      (receipt) => {
        receipt.artifact.android.artifactReceiptSha256 = '0'.repeat(64)
      },
      /not bound to the exact desktop\/Android artifacts/,
    )
    assertRejectedReceiptMutation(
      paths.android.install,
      (receipt) => {
        receipt.replacementInstall = false
      },
      /install receipt is not bound to the exact physical artifact/,
    )
    assertRejectedReceiptMutation(
      paths.android.install,
      (receipt) => {
        receipt.appGitTree = '0'.repeat(40)
      },
      /install receipt is not bound to the exact physical artifact/,
    )
    assertRejectedReceiptMutation(
      paths.android.wireguard_dns,
      (receipt) => {
        receipt.appGitSha = '0'.repeat(40)
      },
      /not exact source\/artifact evidence/,
    )
    assertRejectedReceiptMutation(
      paths.android.wireguard_dns,
      (receipt) => {
        delete receipt.evidenceFiles[
          'mobile-android-network-counter-ledger.tsv'
        ]
      },
      /lacks its durable counter ledger/,
    )
    assertRejectedReceiptMutation(
      paths.android.foreground_idle_cpu,
      (receipt) => {
        receipt.sample.cpuPercent = 2.01
      },
      /foreground VPN-off idle CPU receipt is incomplete/,
    )
    assertRejectedReceiptMutation(
      paths.android.foreground_idle_cpu,
      (receipt) => {
        receipt.artifactReceiptSha256 = '0'.repeat(64)
      },
      /foreground VPN-off idle CPU receipt is not exact artifact evidence/,
    )
    assertRejectedReceiptMutation(
      paths.android.foreground_idle_cpu_raw,
      (receipt) => {
        receipt.cpuPercent = 1.5
      },
      /foreground VPN-off idle CPU raw receipt SHA-256 differs/,
    )
    assertRejectedReceiptMutation(
      paths.linux.public_ui_join,
      (receipt) => {
        receipt.artifact.desktop.appGitTree = '0'.repeat(40)
      },
      /not bound to the exact desktop\/Android artifacts/,
    )
    for (const platform of ['android', 'ios']) {
      assertRejectedReceiptMutation(
        paths[platform].underlay_lifecycle,
        (receipt) => {
          receipt.support.underlayCycles.push({
            ...receipt.support.underlayCycles[0],
          })
        },
        /underlay\/lifecycle receipt is incomplete/,
      )
      assertRejectedReceiptMutation(
        paths[platform].underlay_lifecycle,
        (receipt) => {
          receipt.support.underlayCycles[0]
            .noValidatedPhysicalFallbackEvidenceCount = 0
        },
        /underlay\/lifecycle receipt is incomplete/,
      )
      assertRejectedReceiptMutation(
        paths[platform].underlay_lifecycle,
        (receipt) => {
          const path = Object.keys(receipt.evidenceFiles)
            .find((name) => name.endsWith(
              platform === 'android' ? '-summary.json' : 'continuity.json',
            ))
          delete receipt.evidenceFiles[path]
        },
        /underlay\/lifecycle receipt is incomplete/,
      )
      assertRejectedReceiptMutation(
        paths[platform].underlay_lifecycle,
        (receipt) => {
          receipt.support.underlayCycles[0]
            .processIdentifierCounts.app = 2
        },
        /underlay\/lifecycle receipt is incomplete/,
      )
      assertRejectedReceiptMutation(
        paths[platform].underlay_lifecycle,
        (receipt) => {
          receipt.support.underlayCycles[0].freshDnsFixtureExactQueryCount = 0
        },
        /underlay\/lifecycle receipt is incomplete/,
      )
    }

    if (fixtureRoot) {
      const fleetEvidence = collectReleaseGateReceipts({
        commit: candidateCommit,
        tree: candidateTree,
        candidateRoot,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      })
      const artifactSha256 =
        process.env.NVPN_FLEET_GATE_ARTIFACT_SHA256 ?? 'e'.repeat(64)
      const artifactSize = Number(
        process.env.NVPN_FLEET_GATE_ARTIFACT_SIZE ?? 42,
      )
      const payloadSha256 =
        process.env.NVPN_FLEET_GATE_PAYLOAD_SHA256 ?? artifactSha256
      assert.match(artifactSha256, /^[0-9a-f]{64}$/)
      assert.match(payloadSha256, /^[0-9a-f]{64}$/)
      assert.ok(Number.isSafeInteger(artifactSize) && artifactSize > 0)
      const releaseAssetPath =
        `assets/nvpn-v${source.appVersion}-x86_64-unknown-linux-musl.tar.gz`
      const payloadLabel = 'nvpn'
      const assets = [{
        name: releaseAssetPath.slice('assets/'.length),
        path: releaseAssetPath,
        sha256: artifactSha256,
        size: artifactSize,
      }]
      const releaseGateAttestation = buildReleaseGateAttestation({
        commit: candidateCommit,
        tree: candidateTree,
        assets,
        releaseGateSummarySha256: fleetEvidence.releaseGateSummarySha256,
        platformGateReceipts: fleetEvidence.platformGateReceipts,
        platformSourceEquivalence: fleetEvidence.platformSourceEquivalence,
        assetProofs: {
          [releaseAssetPath]: {
            platform: 'linux',
            verification: 'gate-payload-identity',
            artifact_sha256: artifactSha256,
            gate_receipt_sha256:
              fleetEvidence.platformGateReceipts.linux.artifact,
            payloads: { [payloadLabel]: payloadSha256 },
          },
        },
      })
      const tag = `v${source.appVersion}`
      const releasePath = join(root, 'release.json')
      writeFileSync(releasePath, JSON.stringify({
        id: tag,
        title: tag,
        tag,
        commit: candidateCommit,
        draft: process.env.NVPN_FLEET_GATE_DRAFT !== 'false',
        assets,
        android_release_gate: {
          receipt_schema: androidArtifact.receiptSchema,
          apk_path: 'assets/nostr-vpn-v4.1.5-android-arm64.apk',
          apk_sha256: androidArtifact.apkSha256,
          app_git_sha: androidArtifact.appGitSha,
          app_git_tree: androidArtifact.appGitTree,
          package: androidArtifact.package,
          signer_certificate_sha256:
            androidArtifact.signerCertificateSha256,
          ...(fleetEvidence.platformSourceEquivalence.android
            ? {
                source_equivalence:
                  fleetEvidence.platformSourceEquivalence.android,
              }
            : {}),
        },
        release_gate_attestation: releaseGateAttestation,
      }))
      writeFileSync(
        join(root, 'fleet-gate-fixture.json'),
        JSON.stringify({
          releaseAssetPath,
          payloadLabel,
          request: {
            candidateRoot,
            releasePath,
            source: candidateSource,
            receiptPaths: {
              releaseGateSummary: summary,
              platforms: paths,
            },
          },
        }),
      )
      return
    }

    const windowsInstaller = readFileSync(
      paths.windows.installer,
      'utf8',
    )
    const replacedWindowsInstaller = JSON.parse(windowsInstaller)
    replacedWindowsInstaller.installerInstalledAndLaunched = false
    writeFileSync(
      paths.windows.installer,
      JSON.stringify(replacedWindowsInstaller),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /Windows exact installer gate receipt is incomplete/,
    )
    writeFileSync(paths.windows.installer, windowsInstaller)

    const mismatchedWindowsPayload = JSON.parse(windowsInstaller)
    mismatchedWindowsPayload.payloads.cli.sha256 = '0'.repeat(64)
    writeFileSync(
      paths.windows.installer,
      JSON.stringify(mismatchedWindowsPayload),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /cli payload differs from the real platform gate/,
    )
    writeFileSync(paths.windows.installer, windowsInstaller)

    const androidNetwork = readFileSync(paths.android.wireguard_dns, 'utf8')
    for (const label of ['automatic-profile', 'through-exit']) {
      const providerFallback = JSON.parse(androidNetwork)
      providerFallback.dnsCases[label]
        .dnsPathCountersAfter.cloudflareSni += 1
      writeFileSync(
        paths.android.wireguard_dns,
        JSON.stringify(providerFallback),
      )
      assert.throws(
        () => collectReleaseGateReceipts({
          commit,
          tree,
          releaseGateSummaryPath: summary,
          platformReceiptPaths: paths,
        }),
        new RegExp(`${label} used the wrong cloudflareSni DNS path`),
      )
    }
    writeFileSync(paths.android.wireguard_dns, androidNetwork)

    const wrongAndroidDnsPath = JSON.parse(androidNetwork)
    const cloudflare =
      wrongAndroidDnsPath.dnsCases['cloudflare-doh']
    cloudflare.dnsPathCountersAfter.cloudflareSni =
      cloudflare.dnsPathCountersBefore.cloudflareSni
    cloudflare.dnsPathCountersAfter.query =
      cloudflare.dnsPathCountersBefore.query + 1
    writeFileSync(
      paths.android.wireguard_dns,
      JSON.stringify(wrongAndroidDnsPath),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /used the wrong (query|cloudflareSni) DNS path/,
    )
    writeFileSync(paths.android.wireguard_dns, androidNetwork)

    const linuxPackageInstall = readFileSync(
      paths.linux.package_install,
      'utf8',
    )
    const wrongDebPackage = JSON.parse(linuxPackageInstall)
    wrongDebPackage.debSha256 = '0'.repeat(64)
    writeFileSync(
      paths.linux.package_install,
      JSON.stringify(wrongDebPackage),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /Debian package was not installed and verified/,
    )
    writeFileSync(paths.linux.package_install, linuxPackageInstall)

    const windowsNetwork = readFileSync(paths.windows.network, 'utf8')
    const tamperedWindowsNetwork = JSON.parse(windowsNetwork)
    tamperedWindowsNetwork.summary.directRestored = false
    writeFileSync(
      paths.windows.network,
      JSON.stringify(tamperedWindowsNetwork),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /desktop network summary is incomplete/,
    )
    writeFileSync(paths.windows.network, windowsNetwork)

    const wrongDesktopDnsPath = JSON.parse(windowsNetwork)
    wrongDesktopDnsPath.summary.dnsCases.cloudflare.after_quad9 = 2
    writeFileSync(
      paths.windows.network,
      JSON.stringify(wrongDesktopDnsPath),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /cloudflare used the wrong DNS resolver path/,
    )
    writeFileSync(paths.windows.network, windowsNetwork)

    const wrongWindowsDnsUiArtifact = JSON.parse(windowsNetwork)
    wrongWindowsDnsUiArtifact.summary.dnsUiCases.quad9.appExecutableSha256 =
      '0'.repeat(64)
    writeFileSync(
      paths.windows.network,
      JSON.stringify(wrongWindowsDnsUiArtifact),
    )
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /quad9 DNS UI readback is not bound to the exact gated app and CLI/,
    )
    writeFileSync(paths.windows.network, windowsNetwork)

    writeFileSync(paths.windows.public_ui_join, JSON.stringify({
      ...source,
      schema: 1,
      platform: 'windows',
      publicUiOnly: true,
      privateStateRead: true,
      fixtureInvoked: false,
      acceptedSelectorSemantics: 'participant-state-not-pending',
      desktopRelaunchDurability: true,
      pixelRelaunchDurability: true,
    }))
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: summary,
        platformReceiptPaths: paths,
      }),
      /strict real public-UI join receipt/,
    )
  } finally {
    if (!fixtureRoot) {
      rmSync(root, { recursive: true, force: true })
    }
  }
})

test('desktop evidence builder accepts the real repeated five-case DNS ledger', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-desktop-evidence-test-'))
  try {
    const commit = 'a'.repeat(40)
    const tree = 'b'.repeat(40)
    write(
      join(root, 'source-provenance.txt'),
      `nvpn_base_commit=${commit}\nnvpn_tree=${tree}\n`,
    )
    const testedCliSha256 = 'c'.repeat(64)
    const testedCliSize = 123
    const testedArtifactReceipt = JSON.stringify({
      schema: 2,
      builderMode: 'remote-native',
      builtOnHostMac: false,
      builtOnRemoteVm: true,
      builderHostOs: 'Linux',
      builderHostArchitecture: 'x86_64',
      containerImageId: `sha256:${'1'.repeat(64)}`,
      dockerfileSha256: '2'.repeat(64),
      containerPayloadSha256: '3'.repeat(64),
      appGitSha: commit,
      appGitTree: tree,
      artifacts: {
        cli: {
          sha256: testedCliSha256,
          size: testedCliSize,
        },
      },
    })
    write(
      join(root, 'tested-artifact-receipt.json'),
      testedArtifactReceipt,
    )
    write(
      join(root, 'tested-artifact.json'),
      JSON.stringify({
        cliSha256: testedCliSha256,
        cliSize: testedCliSize,
        artifactReceiptSha256: sha256(testedArtifactReceipt),
      }),
    )
    const handoff = JSON.stringify({
      recovery_milliseconds: 100,
      payload_successes_before: 1,
      payload_successes_after: 2,
      wireguard_payload_successes_before: 1,
      wireguard_payload_successes_after: 2,
      rebind_receipts_before: 1,
      rebind_receipts_after: 2,
    })
    write(join(root, 'secondary-receipt.json'), handoff)
    write(join(root, 'primary-receipt.json'), handoff)
    write(
      join(root, 'dns-matrix.txt'),
      [
        ['automatic', 'profile_dns'],
        ['cloudflare', 'cloudflare'],
        ['quad9', 'quad9'],
        ['custom', 'google'],
        ['through-exit', 'fixture_dns'],
      ].flatMap(([name, expectedCounter]) => [
        `case=${name}`,
        ...desktopDnsCounterNames.flatMap((counter) => [
          `before_${counter}=1`,
          `after_${counter}=${counter === expectedCounter ? 2 : 1}`,
        ]),
      ]).join('\n') + '\n',
    )
    write(join(root, 'direct-receipt.json'), JSON.stringify({
      wireguard_interface_removed: true,
      wireguard_endpoint_route_removed: true,
      wireguard_policy_rule_removed: true,
      wireguard_policy_table_empty: true,
      verified_https: true,
    }))
    write(join(root, 'crash-repair-receipt.json'), JSON.stringify({
      sigkill_exit_code: 137,
      fresh_wireguard_handshake: true,
      through_exit_dns_before_crash: true,
      verified_https_before_crash: true,
      cleanup_journal_survived_sigkill: true,
      startup_repair_without_explicit_command: true,
      cleanup_journal_removed: true,
      physical_default_restored: true,
      public_dns_restored: true,
      verified_https_after_restart: true,
      restart_daemon_count: 1,
      restart_repair_milliseconds: 100,
    }))
    const dnsUiDir = join(root, 'dns-ui')
    const dnsUiSettings = {
      automatic: ['automatic', 'cloudflare', '', '', ''],
      cloudflare: ['encrypted', 'cloudflare', '', '', ''],
      quad9: ['encrypted', 'quad9', '', '', ''],
      custom: [
        'encrypted',
        'custom',
        'https://dns.google/dns-query',
        '8.8.8.8,8.8.4.4',
        '',
      ],
      'through-exit': [
        'through_exit',
        'cloudflare',
        '',
        '',
        '10.99.79.53',
      ],
    }
    for (const [dnsCase, values] of Object.entries(dnsUiSettings)) {
      const [
        exitDnsMode,
        exitDnsDohProvider,
        exitDnsCustomDohUrl,
        exitDnsCustomDohBootstrapIps,
        exitDnsThroughExitServers,
      ] = values
      write(join(dnsUiDir, `${dnsCase}.json`), JSON.stringify({
        receiptSchema: 1,
        platform: 'linux',
        case: dnsCase,
        evidenceSource: 'shipped-ui-restart-readback',
        savedViaShippedUi: true,
        uiRestartReadback: true,
        releaseBlackbox: true,
        publicUiOnly: true,
        privateStateRead: false,
        appGitSha: commit,
        appGitTree: tree,
        appExecutableSha256: 'd'.repeat(64),
        cliExecutableSha256: testedCliSha256,
        exitDnsMode,
        exitDnsDohProvider,
        exitDnsCustomDohUrl,
        exitDnsCustomDohBootstrapIps,
        exitDnsThroughExitServers,
      }))
    }
    const output = join(root, 'receipt.json')
    const result = spawnSync(
      'python3',
      [
        join(process.cwd(), 'scripts/release-network-evidence.py'),
        'desktop',
        '--platform',
        'linux',
        '--artifact-dir',
        root,
        '--dns-ui-dir',
        dnsUiDir,
        '--app-git-sha',
        commit,
        '--app-git-tree',
        tree,
        '--output',
        output,
      ],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 0, result.stderr)
    const receipt = JSON.parse(readFileSync(output, 'utf8'))
    assert.equal(receipt.summary.dnsPolicyCount, 5)
    assert.equal(receipt.summary.directRestored, true)
    assert.equal(receipt.summary.singletonAfterCrashRecovery, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('StartOS post-build proof requires the real exact-package inspector result', () => {
  const asset = {
    path: 'assets/nostr-vpn-v4.1.5-startos-x86_64.s9pk',
    sha256: 'a'.repeat(64),
    size: 42,
  }
  const receipts = Object.fromEntries(
    ['android', 'ios', 'linux', 'macos', 'windows'].map(
      (platform, index) => [
        platform,
        { gate: String(index + 1).padStart(64, '0') },
      ],
    ),
  )
  const baseProof = {
    platform: 'startos',
    verification: 'post-build-exact-package-gate',
    artifact_sha256: asset.sha256,
    gate_receipt_sha256: 'f'.repeat(64),
    payloads: {
      manifest_json: 'b'.repeat(64),
      package: asset.sha256,
    },
  }
  const build = (proof) => buildReleaseGateAttestation({
    commit: 'c'.repeat(40),
    tree: 'd'.repeat(40),
    assets: [asset],
    releaseGateSummarySha256: 'f'.repeat(64),
    platformGateReceipts: receipts,
    assetProofs: { [asset.path]: proof },
  })

  assert.throws(
    () => build(baseProof),
    /lacks a real exact-package StartOS validation/,
  )
  assert.doesNotThrow(() => build({
    ...baseProof,
    post_build_validator: startosExactPackageValidator,
  }))
  assert.throws(
    () => build({
      ...baseProof,
      post_build_validator: startosExactPackageValidator,
      payloads: {
        ...baseProof.payloads,
        package: 'e'.repeat(64),
      },
    }),
    /lacks a real exact-package StartOS validation/,
  )
})
