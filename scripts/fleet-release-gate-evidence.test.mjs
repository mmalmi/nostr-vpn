import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { validateFleetReleaseGateEvidence } from './fleet-release-gate-evidence.mjs'
import { buildReleaseGateAttestation } from './release-artifact-provenance-lib.mjs'

const platforms = {
  android: [
    'foreground_idle_cpu',
    'foreground_idle_cpu_raw',
    'install',
    'mobile_join',
    'physical',
    'replacement_singleton',
    'underlay_lifecycle',
    'wireguard_dns',
  ],
  ios: [
    'desktop_mobile_join',
    'frozen_archive',
    'join_variant',
    'mobile_artifact',
    'mobile_join',
    'underlay_lifecycle',
    'wireguard_dns',
  ],
  linux: [
    'arm64_cli',
    'artifact',
    'network',
    'package_install',
    'public_ui_join',
  ],
  macos: ['artifact', 'network_artifact', 'network', 'public_ui_join'],
  windows: ['artifact', 'installer', 'network', 'public_ui_join'],
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function gitObject(root, revision) {
  const result = spawnSync('git', ['rev-parse', revision], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  assert.equal(result.status, 0, result.stderr || `could not resolve ${revision}`)
  return result.stdout.trim()
}

function sourceHistoryFixture(root) {
  const git = (...args) => {
    const result = spawnSync('git', args, {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    assert.equal(result.status, 0, result.stderr || `git ${args.join(' ')} failed`)
  }
  git('init', '--quiet')
  writeFileSync(join(root, 'README.md'), 'receipt source\n')
  git('add', 'README.md')
  git(
    '-c', 'user.name=Release Test',
    '-c', 'user.email=release-test@example.invalid',
    'commit', '--quiet', '-m', 'receipt source',
  )
  const receiptAppGitSha = gitObject(root, 'HEAD')
  const receiptAppGitTree = gitObject(root, 'HEAD^{tree}')
  writeFileSync(join(root, 'README.md'), 'candidate source\n')
  git('add', 'README.md')
  git(
    '-c', 'user.name=Release Test',
    '-c', 'user.email=release-test@example.invalid',
    'commit', '--quiet', '-m', 'candidate source',
  )
  return {
    receiptAppGitSha,
    receiptAppGitTree,
    candidateAppGitSha: gitObject(root, 'HEAD'),
    candidateAppGitTree: gitObject(root, 'HEAD^{tree}'),
  }
}

function json(path, value) {
  writeFileSync(path, JSON.stringify(value))
}

function fixture(root) {
  const source = {
    appGitSha: 'a'.repeat(40),
    appGitTree: 'b'.repeat(40),
    appVersion: '4.1.5',
    fipsGitSha: 'c'.repeat(40),
    fipsGitTree: 'd'.repeat(40),
    fipsVersion: '0.4.45',
  }
  const releaseGateSummary = join(root, 'summary.json')
  json(releaseGateSummary, {
    elapsedSeconds: 301,
    targetSeconds: 300,
    targetStatus: 'missed',
  })

  const sharedMobileJoin = join(root, 'mobile-join.json')
  const receiptPaths = Object.fromEntries(
    Object.entries(platforms).map(([platform, names]) => [
      platform,
      Object.fromEntries(
        names.map((name) => [
          name,
          name === 'mobile_join'
            ? sharedMobileJoin
            : join(root, `${platform}-${name}.json`),
        ]),
      ),
    ]),
  )
  for (const receipts of Object.values(receiptPaths)) {
    for (const path of Object.values(receipts)) {
      json(path, {})
    }
  }
  for (const [platform, name, versionField] of [
    ['android', 'physical', 'fipsCoreVersion'],
    ['ios', 'mobile_artifact', 'fipsCoreVersion'],
    ['macos', 'artifact', 'fipsCoreVersion'],
    ['macos', 'network_artifact', 'fipsCoreVersion'],
    ['linux', 'artifact', 'fipsVersion'],
    ['windows', 'artifact', 'fipsVersion'],
  ]) {
    json(receiptPaths[platform][name], {
      fipsGitSha: source.fipsGitSha,
      fipsGitTree: source.fipsGitTree,
      [versionField]: source.fipsVersion,
    })
  }

  const platformGateReceipts = Object.fromEntries(
    Object.entries(receiptPaths).map(([platform, receipts]) => [
      platform,
      Object.fromEntries(
        Object.entries(receipts).map(([name, path]) => [
          name,
          sha256(readFileSync(path)),
        ]),
      ),
    ]),
  )
  const assets = [
    {
      name: 'nostr-vpn-v4.1.5-linux-x64.deb',
      path: 'assets/nostr-vpn-v4.1.5-linux-x64.deb',
      sha256: 'e'.repeat(64),
      size: 42,
    },
  ]
  const attestation = buildReleaseGateAttestation({
    commit: source.appGitSha,
    tree: source.appGitTree,
    assets,
    releaseGateSummarySha256: sha256(readFileSync(releaseGateSummary)),
    platformGateReceipts,
    assetProofs: {
      [assets[0].path]: {
        platform: 'linux',
        verification: 'gate-payload-identity',
        artifact_sha256: assets[0].sha256,
        gate_receipt_sha256: platformGateReceipts.linux.artifact,
        payloads: { runtime: assets[0].sha256 },
      },
    },
  })
  const release = {
    id: 'v4.1.5',
    title: 'v4.1.5',
    tag: 'v4.1.5',
    commit: source.appGitSha,
    draft: true,
    assets,
    release_gate_attestation: attestation,
  }
  const releasePath = join(root, 'release.json')
  json(releasePath, release)
  return {
    attestation,
    receiptPaths,
    release,
    releaseGateSummary,
    releasePath,
    request: {
      candidateRoot: root,
      releasePath,
      source,
      receiptPaths: {
        releaseGateSummary,
        platforms: receiptPaths,
      },
    },
  }
}

function withFixture(callback) {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-fleet-gate-test-'))
  try {
    callback(fixture(root))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

function collectorFixture(root, overrides = {}) {
  const history = sourceHistoryFixture(root)
  const env = {
    ...process.env,
    NVPN_FLEET_GATE_FIXTURE_ROOT: root,
    NVPN_FLEET_GATE_TARGET_STATUS: overrides.targetStatus ?? 'missed',
    NVPN_FLEET_GATE_DRAFT: String(overrides.draft ?? true),
    NVPN_FLEET_GATE_APP_GIT_SHA:
      overrides.receiptAppGitSha ?? history.receiptAppGitSha,
    NVPN_FLEET_GATE_APP_GIT_TREE:
      overrides.receiptAppGitTree ?? history.receiptAppGitTree,
    NVPN_FLEET_GATE_CANDIDATE_APP_GIT_SHA:
      overrides.candidateAppGitSha ?? history.candidateAppGitSha,
    NVPN_FLEET_GATE_CANDIDATE_APP_GIT_TREE:
      overrides.candidateAppGitTree ?? history.candidateAppGitTree,
    NVPN_FLEET_GATE_CANDIDATE_ROOT:
      overrides.candidateRoot ?? root,
  }
  delete env.NODE_TEST_CONTEXT
  const generated = spawnSync(
    process.execPath,
    [
      '--test',
      '--test-name-pattern=release receipt collection requires exact source',
      join(process.cwd(), 'scripts/release-artifact-provenance-lib.test.mjs'),
    ],
    {
      cwd: process.cwd(),
      encoding: 'utf8',
      env,
    },
  )
  assert.equal(generated.status, 0, generated.stderr || generated.stdout)
  return JSON.parse(readFileSync(join(root, 'fleet-gate-fixture.json'), 'utf8'))
}

test('accepts real collector evidence through the function and CLI', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-fleet-gate-positive-'))
  try {
    const value = collectorFixture(root, {
      draft: true,
      targetStatus: 'missed',
    })
    const release = JSON.parse(readFileSync(value.request.releasePath, 'utf8'))
    assert.deepEqual(
      Object.keys(
        release.release_gate_attestation.platform_source_equivalence,
      ).sort(),
      ['android', 'ios', 'linux', 'macos', 'windows'],
    )
    assert.equal(
      release.android_release_gate.source_equivalence.policy,
      'unchanged-platform-product-inputs-v1',
    )
    for (const draft of [true, false]) {
      json(value.request.releasePath, { ...release, draft })
      const validated = validateFleetReleaseGateEvidence(value.request)
      assert.equal(validated.schema, 1)
      assert.equal(validated.release.draft, draft)
      assert.deepEqual(Object.keys(validated.platformGateReceipts).sort(), [
        'android',
        'ios',
        'linux',
        'macos',
        'windows',
      ])
      assert.equal(
        validated.assetProofs[value.releaseAssetPath].payloads[
          value.payloadLabel
        ],
        validated.assets[0].sha256,
      )
      assert.equal(
        validated.platformGateReceipts.linux.arm64_cli,
        release.release_gate_attestation.platform_gate_receipts.linux
          .arm64_cli,
      )

      const cli = spawnSync(
        process.execPath,
        [join(process.cwd(), 'scripts/fleet-release-gate-evidence.mjs')],
        { encoding: 'utf8', input: JSON.stringify(value.request) },
      )
      assert.equal(cli.status, 0, cli.stderr)
      assert.deepEqual(JSON.parse(cli.stdout), validated)
    }

    const arm64Path = value.request.receiptPaths.platforms.linux.arm64_cli
    const arm64Receipt = readFileSync(arm64Path)
    writeFileSync(arm64Path, Buffer.concat([arm64Receipt, Buffer.from('\n')]))
    assert.throws(
      () => validateFleetReleaseGateEvidence(value.request),
      /linux arm64_cli receipt hash differs/i,
    )
    writeFileSync(arm64Path, arm64Receipt)

    const { candidateRoot: omittedCandidateRoot, ...withoutCandidateRoot } =
      value.request
    assert.ok(omittedCandidateRoot)
    assert.throws(
      () => validateFleetReleaseGateEvidence(withoutCandidateRoot),
      /request must contain exactly/i,
    )

    json(value.request.releasePath, {
      ...release,
      release_gate_attestation: {
        ...release.release_gate_attestation,
        platform_source_equivalence: {},
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(value.request),
      /source equivalence|release candidate and physical receipt/i,
    )

    json(value.request.releasePath, {
      ...release,
      android_release_gate: {
        ...release.android_release_gate,
        source_equivalence: {
          ...release.android_release_gate.source_equivalence,
          changed_paths_sha256: '0'.repeat(64),
        },
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(value.request),
      /release candidate and physical receipt/i,
    )

    const forgedAndroidProof = {
      ...release.android_release_gate.source_equivalence,
      changed_paths_sha256: '0'.repeat(64),
    }
    json(value.request.releasePath, {
      ...release,
      android_release_gate: {
        ...release.android_release_gate,
        source_equivalence: forgedAndroidProof,
      },
      release_gate_attestation: {
        ...release.release_gate_attestation,
        platform_source_equivalence: {
          ...release.release_gate_attestation.platform_source_equivalence,
          android: forgedAndroidProof,
        },
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(value.request),
      /collected release-gate source equivalence differs/i,
    )

    json(value.request.releasePath, {
      ...release,
      android_release_gate: {
        ...release.android_release_gate,
        app_git_tree: '0'.repeat(40),
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(value.request),
      /Android release gate does not match the release candidate and physical receipt/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('rejects trivial passed and mocked files through the function and CLI', () => {
  withFixture(({ releasePath, request }) => {
    for (const value of [{ passed: true }, { mocked: true }]) {
      json(releasePath, value)
      assert.throws(
        () => validateFleetReleaseGateEvidence(request),
        /release identity/i,
      )
      const cli = spawnSync(
        process.execPath,
        [join(process.cwd(), 'scripts/fleet-release-gate-evidence.mjs')],
        { encoding: 'utf8', input: JSON.stringify(request) },
      )
      assert.equal(cli.status, 1)
      assert.equal(cli.stdout, '')
      assert.match(cli.stderr, /evidence rejected.*release identity/i)
    }
  })
})

test('rejects wrong source, FIPS receipts, schema, hashes, and key sets', () => {
  withFixture((fixtureValue) => {
    const { attestation, receiptPaths, release, releasePath, request } =
      fixtureValue
    for (const [field, value, error] of [
      ['appGitSha', '1'.repeat(40), /release identity/i],
      ['appGitTree', '2'.repeat(40), /wrong source tree/i],
      ['appVersion', '4.1.6', /release identity/i],
      ['fipsGitSha', '3'.repeat(40), /wrong exact FIPS/i],
      ['fipsGitTree', '4'.repeat(40), /wrong exact FIPS/i],
      ['fipsVersion', '0.4.46', /wrong exact FIPS/i],
    ]) {
      assert.throws(
        () =>
          validateFleetReleaseGateEvidence({
            ...request,
            source: { ...request.source, [field]: value },
          }),
        error,
      )
    }

    for (const [platform, name, field] of [
      ['android', 'physical', 'fipsCoreVersion'],
      ['ios', 'mobile_artifact', 'fipsCoreVersion'],
      ['macos', 'artifact', 'fipsCoreVersion'],
      ['macos', 'network_artifact', 'fipsCoreVersion'],
      ['linux', 'artifact', 'fipsVersion'],
      ['windows', 'artifact', 'fipsVersion'],
    ]) {
      const path = receiptPaths[platform][name]
      const original = readFileSync(path)
      json(path, {
        fipsGitSha: request.source.fipsGitSha,
        fipsGitTree: request.source.fipsGitTree,
        [field]: '0.0.0',
      })
      assert.throws(
        () => validateFleetReleaseGateEvidence(request),
        /wrong exact FIPS/i,
      )
      writeFileSync(path, original)
    }

    json(releasePath, {
      ...release,
      release_gate_attestation: {
        ...attestation,
        receipt_schema: 2,
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(request),
      /wrong policy/i,
    )

    json(releasePath, {
      ...release,
      release_gate_attestation: {
        ...attestation,
        platform_gate_receipts: {
          ...attestation.platform_gate_receipts,
          linux: {
            ...attestation.platform_gate_receipts.linux,
            artifact: '0'.repeat(64),
          },
        },
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(request),
      /not linked to its platform gate|receipt hash differs/i,
    )

    json(releasePath, {
      ...release,
      release_gate_attestation: {
        ...attestation,
        platform_gate_receipts: {
          ...attestation.platform_gate_receipts,
          linux: Object.fromEntries(
            Object.entries(attestation.platform_gate_receipts.linux).filter(
              ([name]) => name !== 'package_install',
            ),
          ),
        },
      },
    })
    assert.throws(
      () => validateFleetReleaseGateEvidence(request),
      /attested receipts must contain exactly/i,
    )
    json(releasePath, release)

    const { package_install: omitted, ...linuxWithoutPackageInstall } =
      receiptPaths.linux
    assert.ok(omitted)
    assert.throws(
      () =>
        validateFleetReleaseGateEvidence({
          ...request,
          receiptPaths: {
            ...request.receiptPaths,
            platforms: {
              ...receiptPaths,
              linux: linuxWithoutPackageInstall,
            },
          },
        }),
      /linux receipt paths must contain exactly/i,
    )
    assert.throws(
      () =>
        validateFleetReleaseGateEvidence({
          ...request,
          receiptPaths: {
            ...request.receiptPaths,
            platforms: {
              ...receiptPaths,
              plan9: {},
            },
          },
        }),
      /receipt path platforms must contain exactly/i,
    )
    assert.throws(
      () =>
        validateFleetReleaseGateEvidence({
          ...request,
          extra: true,
        }),
      /request must contain exactly/i,
    )
  })
})

test('allows missed target and either draft value before the real oracle', () => {
  withFixture(
    ({ attestation, release, releaseGateSummary, releasePath, request }) => {
      for (const draft of [true, false]) {
        json(releasePath, { ...release, draft })
        assert.throws(
          () => validateFleetReleaseGateEvidence(request),
          /Physical Android artifact receipt lacks an exact component-origin/i,
        )
      }

      json(releaseGateSummary, {
        elapsedSeconds: 1,
        targetSeconds: 300,
        targetStatus: 'passed',
      })
      const passedAttestation = {
        ...attestation,
        release_gate_summary_sha256: sha256(readFileSync(releaseGateSummary)),
      }
      json(releasePath, {
        ...release,
        release_gate_attestation: passedAttestation,
      })
      assert.throws(
        () => validateFleetReleaseGateEvidence(request),
        /completion receipt is incomplete/i,
      )

      json(releaseGateSummary, {
        elapsedSeconds: 301,
        targetSeconds: 300,
        targetStatus: 'missed',
        mocked: false,
      })
      json(releasePath, {
        ...release,
        release_gate_attestation: {
          ...attestation,
          release_gate_summary_sha256: sha256(readFileSync(releaseGateSummary)),
        },
      })
      assert.throws(
        () => validateFleetReleaseGateEvidence(request),
        /completion receipt must contain exactly/i,
      )
    },
  )
})
