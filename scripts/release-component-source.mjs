import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const platforms = ['android', 'ios', 'linux', 'macos', 'windows']
const desktopPlatforms = new Set(['linux', 'macos', 'windows'])
const sharedRoots = ['.cargo', 'assets', 'crates', 'docker', 'src', 'tools']
const sharedFiles = [
  'Cargo.lock', 'Cargo.toml', 'build.rs', 'rust-toolchain',
  'rust-toolchain.toml', 'scripts/sync-versions.mjs',
]
const harnessOnlyPaths = new Set([
  'Dockerfile.mobile-wireguard-exit-e2e',
  'Dockerfile.mobile-wireguard-exit-e2e.dockerignore',
  'scripts/android-release-foreground-idle-receipt.mjs',
  'scripts/native-lab.py',
  'crates/nostr-vpn-app-core/src/mobile_tunnel/tests_core.rs',
  'crates/nostr-vpn-app-core/src/mobile_tunnel/tests_runtime/websocket_join.rs',
  'crates/nostr-vpn-core/examples/desktop_manual_join_e2e_fixture.rs',
  'scripts/appstore-draft',
  'scripts/appstore_draft_metadata.py',
  'scripts/test_appstore_draft_metadata.py',
  'scripts/e2e-fips-roaming-docker.sh',
  'scripts/e2e-umbrel-auth-join-docker.sh',
  'scripts/e2e-web-startos-manual-join-docker.sh',
  'scripts/capture-mobile-ios-underlay-output.py',
  'scripts/desktop-manual-join-ax.swift',
  'scripts/desktop_mobile_manual_join_receipt.py',
  'scripts/desktop-mobile-manual-join-atspi.py',
  'scripts/desktop-mobile-manual-join-windows-ui.ps1',
  'scripts/desktop-linux-underlay-change-e2e.sh',
  'scripts/desktop-linux-underlay-peer-e2e.sh',
  'scripts/e2e-macos-release-network.sh',
  'scripts/e2e-macos-service-toggle.sh',
  'scripts/e2e-macos-service.sh',
  'scripts/e2e-windows-service-toggle.ps1',
  'scripts/ios_xctestrun.py',
  'scripts/ios-build',
  'scripts/ios_frozen_archive.py',
  'scripts/ios_frozen_gate.py',
  'scripts/ios-upload-receipt.mjs',
  'scripts/lib-desktop-underlay-host-peer.sh',
  'scripts/lib-ubuntu-vm-imported-release.sh',
  'scripts/linux-vm-desktop-underlay-change-e2e.sh',
  'scripts/lib-mobile-android-release-gate.sh',
  'scripts/lib-mobile-android-underlay.sh',
  'scripts/lib-mobile-ios-release-network.sh',
  'scripts/lib-mobile-release-artifact-reuse.sh',
  'scripts/lib-mobile-release-join-artifacts.sh',
  'scripts/lib-mobile-release-join-ui.sh',
  'scripts/lib-mobile-wireguard-fixture.sh',
  'scripts/lib-macos-release-app-ownership.sh',
  'scripts/linux-release-mobile-join-remote.sh',
  'scripts/mobile-android-smoke.sh',
  'scripts/mobile_release_artifact_receipt.py',
  'scripts/mobile-underlay-local-timestamp.py',
  'scripts/mobile-release-join-ui-query.py',
  'scripts/mobile-release-join-e2e.sh',
  'scripts/mobile-wireguard-exit-e2e.sh',
  'scripts/mobile-wireguard-exit-remote-native.sh',
  'scripts/mobile-wireguard-exit-server.sh',
  'scripts/mobile-wireguard-tls-sni-count.py',
  'scripts/macos-release-exit-dns-ui-remote.sh',
  'scripts/macos-release-mobile-join-remote.sh',
  'scripts/macos-vm-desktop-daemon-idle-e2e.sh',
  'scripts/macos-vm-desktop-wireguard-exit-e2e.sh',
  'scripts/macos-vm-release-exit-dns-ui-e2e.sh',
  'scripts/macos-vm-release-mobile-join-e2e.sh',
  'scripts/macos_exit_dns_ui_receipt.py',
  'scripts/macos_release_join_artifact.py',
  'scripts/prepare-macos-release-fips-peer.sh',
  'scripts/publish-release-refs.mjs',
  'scripts/release-network-evidence.py',
  'scripts/release-mutation-gate.mjs',
  'scripts/release-source-verification.mjs',
  'scripts/release_common.sh',
  'scripts/umbrel-release.mjs',
  'web/control-panel/e2e/umbrel-web.spec.ts',
  'scripts/ubuntu-vm-release-mobile-join-e2e.sh',
  'scripts/validate-mobile-underlay-continuity.py',
  'scripts/verify-host-linux-peer-artifact.py',
  'scripts/windows-release-publication-proof.ps1',
  'scripts/windows-release-mobile-join-remote.ps1',
  'scripts/windows-vm-desktop-underlay-change-e2e.sh',
  'scripts/windows-vm-exit-dns-ui-e2e.sh',
  'scripts/windows-vm-release-mobile-join-e2e.sh',
  'scripts/windows-vm-service-toggle-e2e.sh',
])
const buildScripts = {
  android: [/prepare-android-release-from-bundle/],
  ios: [
    /scripts\/ios-profiles$/,
    /scripts\/ios_profile_certificate\.py$/,
    /lib-mobile-ios-release-artifact/,
  ],
  linux: [/build-host-linux-/, /build-nvpn-linux-musl$/, /host-linux-native-builder-/, /host_linux_package_content/, /lib-host-linux-/],
  macos: [/build-.*macos/, /scripts\/macos-build$/, /lib-macos-release-app-ownership/, /verify-macos-release-publication-artifacts/],
  windows: [/windows-build\.ps1$/],
}

function git(root, args, label) {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (result.status !== 0) {
    throw new Error(`${label}: ${String(result.stderr || result.error?.message || 'git failed').trim()}`)
  }
  return String(result.stdout ?? '').trim()
}

function isProductInput(path, platform) {
  if (harnessOnlyPaths.has(path)) return false
  // The control panel is a real product, but it is packaged only into the
  // independently rebuilt and inspected Umbrel/StartOS web artifacts. It is
  // not linked or copied into any of the five native platform artifacts whose
  // retained receipts this classifier governs.
  if (path.startsWith('web/control-panel/')) return false
  if (
    path === 'crates/nostr-vpn-cli/src/wireguard_exit/linux_tests.rs'
    || path.startsWith('crates/nostr-vpn-cli/src/wireguard_exit/linux_tests/')
  ) return false
  if (
    path.startsWith('crates/')
    && (
      /\/tests\//.test(path)
      || /\/src\/tests\//.test(path)
      || /\/tests(?:_[^/]+)?\.rs$/.test(path)
    )
  ) return false
  if (path.startsWith('crates/nostr-vpn-cli/')) {
    if (path === 'crates/nostr-vpn-cli/src/fips_private_mesh/linux_cleanup.rs') {
      return platform === 'linux'
    }
    if (
      path === 'crates/nostr-vpn-cli/src/wireguard_exit.rs'
      || path.startsWith('crates/nostr-vpn-cli/src/wireguard_exit/')
    ) {
      return platform === 'linux'
    }
    if (path === 'crates/nostr-vpn-cli/src/macos_service.rs') {
      return platform === 'macos'
    }
    return desktopPlatforms.has(platform)
  }
  if (path.startsWith('crates/nostr-vpn-wintun/')) {
    return platform === 'windows'
  }
  const root = path.split('/')[0]
  if (sharedFiles.includes(path) || sharedRoots.includes(root)) return true
  if (platforms.includes(root)) {
    return root === platform && !/\/(?:UI)?Tests?\//.test(`/${path}/`)
  }
  if (path.startsWith('scripts/')) {
    for (const [owner, patterns] of Object.entries(buildScripts)) {
      if (patterns.some((pattern) => pattern.test(path))) return owner === platform
    }
    if (/^scripts\/test-|\.test\.mjs$|release-gate|release-artifact-provenance|release-component-source|local-release|publication|fleet[-_]release/.test(path)) {
      return false
    }
    return true
  }
  return !(
    path.startsWith('.github/')
    || path.startsWith('docs/')
    || ['AGENTS.md', 'CHANGELOG.md', 'README.md'].includes(path)
  )
}

function requireTree(root, commit, tree, label) {
  if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) {
    throw new Error(`${label} has an invalid commit/tree.`)
  }
  if (git(root, ['rev-parse', `${commit}^{tree}`], `${label} lookup`) !== tree) {
    throw new Error(`${label} recorded tree is not the commit tree.`)
  }
}

export function proveUnchangedPlatformInputs({
  candidateRoot, platform, receiptCommit, receiptTree,
  candidateCommit, candidateTree,
}) {
  if (!platforms.includes(platform)) {
    throw new Error(`Unsupported component-proof platform: ${platform}`)
  }
  requireTree(candidateRoot, receiptCommit, receiptTree, 'Receipt source')
  requireTree(candidateRoot, candidateCommit, candidateTree, 'Candidate source')
  if (spawnSync('git', ['merge-base', '--is-ancestor', receiptCommit, candidateCommit], {
    cwd: candidateRoot,
    stdio: 'ignore',
  }).status !== 0) {
    throw new Error('Receipt source is not an ancestor of the release candidate.')
  }
  const changedPaths = git(candidateRoot, [
    'diff', '--name-only', '--no-renames', '--diff-filter=ACDMRTUXB', '-z',
    receiptCommit, candidateCommit, '--',
  ], 'Receipt source diff').split('\0').filter(Boolean).sort()
  const relevant = changedPaths.find((path) => isProductInput(path, platform))
  if (relevant) {
    throw new Error(`${platform} receipt cannot be retained: changed product/build input ${relevant}.`)
  }
  return {
    policy: 'unchanged-platform-product-inputs-v1',
    platform,
    receipt_app_git_sha: receiptCommit,
    receipt_app_git_tree: receiptTree,
    candidate_app_git_sha: candidateCommit,
    candidate_app_git_tree: candidateTree,
    changed_paths_sha256: createHash('sha256')
      .update(`${changedPaths.join('\0')}\0`).digest('hex'),
  }
}
