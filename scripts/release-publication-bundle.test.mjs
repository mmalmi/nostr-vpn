import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import {
  buildReleaseManifest,
  buildReleaseManifestFiles,
  readWorkspaceVersionTag,
} from './local-release-lib.mjs'
import {
  buildReleaseGateAttestation,
  startosExactPackageValidator,
} from './release-artifact-provenance-lib.mjs'

const tag = readWorkspaceVersionTag(
  readFileSync(join(process.cwd(), 'Cargo.toml'), 'utf8'),
)
const marketingVersion = tag.slice(1)
const commit = 'a'.repeat(40)
const tree = 'b'.repeat(40)
const releaseGateSummary = 'f'.repeat(64)

const assetNames = [
  `nostr-vpn-${tag}-android-arm64.apk`,
  `nostr-vpn-${tag}-linux-x64.deb`,
  `nvpn-${tag}-x86_64-unknown-linux-musl.tar.gz`,
  `nvpn-${tag}-aarch64-unknown-linux-musl.tar.gz`,
  `nostr-vpn-${tag}-macos-arm64.app.tar.gz`,
  `nostr-vpn-${tag}-macos-arm64.dmg`,
  `nostr-vpn-${tag}-startos-aarch64.s9pk`,
  `nostr-vpn-${tag}-startos-x86_64.s9pk`,
  `nostr-vpn-${tag}-windows-x64-setup.exe`,
]

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function startosManifestSha256(arch) {
  return createHash('sha256')
    .update(canonicalJson({
      id: 'nostr-vpn',
      images: [{ id: 'app', arch: [arch] }],
      virtualNetworking: true,
      version: `${marketingVersion}:0`,
    }))
    .digest('hex')
}

function platformForAsset(name) {
  if (name.includes('android')) return 'android'
  if (name.includes('linux')) return 'linux'
  if (name.includes('macos')) return 'macos'
  if (name.includes('windows')) return 'windows'
  return 'startos'
}

function makeStage() {
  const sandbox = mkdtempSync(join(tmpdir(), 'nvpn-publication-bundle-test-'))
  const root = join(sandbox, 'stage')
  const assetsDir = join(root, 'assets')
  mkdirSync(assetsDir, { recursive: true })
  for (const name of assetNames) {
    writeFileSync(join(assetsDir, name), `exact locally gated ${name}\n`)
  }
  const fakeBin = join(sandbox, 'fake-bin')
  mkdirSync(fakeBin)
  const fakeStartCli = join(fakeBin, 'start-cli')
  writeFileSync(
    fakeStartCli,
    `#!/bin/sh
case "$3" in
  *-startos-aarch64.s9pk) arch=aarch64 ;;
  *-startos-x86_64.s9pk) arch=x86_64 ;;
  *) exit 2 ;;
esac
printf '{"id":"nostr-vpn","version":"${marketingVersion}:0","virtualNetworking":true,"images":[{"id":"app","arch":["%s"]}]}\\n' "$arch"
`,
  )
  chmodSync(fakeStartCli, 0o755)

  const manifest = buildReleaseManifest({
    tag,
    commit,
    createdAt: 1,
    assetPaths: assetNames.map((name) => join(assetsDir, name)),
    draft: true,
    androidReleaseGate: {
      receipt_schema: 2,
      apk_path: `assets/nostr-vpn-${tag}-android-arm64.apk`,
      apk_sha256: '',
      app_git_sha: commit,
      app_git_tree: tree,
      package: 'fi.siriusbusiness.nvpn',
      signer_certificate_sha256: 'c'.repeat(64),
    },
  })
  const apk = manifest.assets.find((asset) => asset.name.endsWith('.apk'))
  manifest.android_release_gate.apk_sha256 = apk.sha256

  const receipts = Object.fromEntries(
    ['android', 'ios', 'linux', 'macos', 'windows'].map(
      (platform, index) => [
        platform,
        { gate: String(index + 1).padStart(64, '0') },
      ],
    ),
  )
  const proofs = Object.fromEntries(
    manifest.assets.map((asset) => {
      const platform = platformForAsset(asset.name)
      const startosArch = asset.name.includes('aarch64')
        ? 'aarch64'
        : 'x86_64'
      return [
        asset.path,
        {
          platform,
          verification:
            platform === 'startos'
              ? 'post-build-exact-package-gate'
              : 'gate-payload-identity',
          artifact_sha256: asset.sha256,
          gate_receipt_sha256:
            platform === 'startos'
              ? releaseGateSummary
              : receipts[platform].gate,
          ...(platform === 'startos'
            ? { post_build_validator: startosExactPackageValidator }
            : {}),
          payloads:
            platform === 'startos'
              ? {
                  manifest_json: startosManifestSha256(startosArch),
                  package: asset.sha256,
                }
              : { runtime: asset.sha256 },
        },
      ]
    }),
  )
  manifest.release_gate_attestation = buildReleaseGateAttestation({
    commit,
    tree,
    assets: manifest.assets,
    releaseGateSummarySha256: releaseGateSummary,
    platformGateReceipts: receipts,
    assetProofs: proofs,
  })
  for (const [name, text] of buildReleaseManifestFiles(manifest)) {
    writeFileSync(join(root, name), text)
  }
  writeFileSync(join(root, 'notes.md'), '# exact gated release\n')
  return { manifest, root }
}

function writeManifest(root, manifest) {
  for (const [name, text] of buildReleaseManifestFiles(manifest)) {
    writeFileSync(join(root, name), text)
  }
}

function verify(root, overrides = {}) {
  return spawnSync(
    process.execPath,
    [
      'scripts/verify-release-publication-bundle.mjs',
      '--stage-dir',
      root,
      '--tag',
      overrides.tag ?? tag,
      '--commit',
      overrides.commit ?? commit,
      '--tree',
      overrides.tree ?? tree,
      '--require-draft',
    ],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PATH: `${join(dirname(root), 'fake-bin')}:${process.env.PATH}`,
      },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
}

test('publication verifier accepts only the exact locally gated staged tree', async (t) => {
  await t.test('accepts an intact complete bundle', () => {
    const { root } = makeStage()
    try {
      const result = verify(root)
      assert.equal(result.status, 0, result.stderr)
      assert.equal(JSON.parse(result.stdout).assetCount, assetNames.length)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })

  await t.test('rejects replaced asset bytes', () => {
    const { root } = makeStage()
    try {
      writeFileSync(
        join(root, 'assets', assetNames[0]),
        `forged locally gated ${assetNames[0]}\n`,
      )
      const result = verify(root)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /size mismatch|SHA-256 mismatch/)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })

  await t.test('rejects a missing exact-artifact proof', () => {
    const { manifest, root } = makeStage()
    try {
      delete manifest.release_gate_attestation.asset_proofs[
        manifest.assets[0].path
      ]
      writeManifest(root, manifest)
      const result = verify(root)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /exactly one proof for every staged asset/)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })

  await t.test('rejects an unexpected asset', () => {
    const { root } = makeStage()
    try {
      writeFileSync(join(root, 'assets', 'forged.bin'), 'forged')
      const result = verify(root)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /asset directory differs from the manifest/)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })

  await t.test('rejects a mismatched clean source tree', () => {
    const { root } = makeStage()
    try {
      const result = verify(root, { tree: 'e'.repeat(40) })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /tree differs from the exact locally gated tree/)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })

  await t.test('rejects symlink substitution', () => {
    const { root } = makeStage()
    try {
      const assetPath = join(root, 'assets', assetNames[0])
      const targetPath = join(root, 'forged-target')
      writeFileSync(targetPath, readFileSync(assetPath))
      unlinkSync(assetPath)
      symlinkSync(targetPath, assetPath)
      const result = verify(root)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /non-symlink file/)
    } finally {
      rmSync(dirname(root), { recursive: true, force: true })
    }
  })
})
