import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  preflightIosPublication,
  publishExactIosDistribution,
} from './ios-release-publication.mjs'
import {
  captureIosUploadIntent,
  finalizeIosUploadReceipt,
  iosUploadReceiptPaths,
  planIosUploadReconciliation,
  reconcileIosUploadReceipts,
  validateIosPendingUploadReceipt,
  validateIosUploadIntent,
  validateIosUploadReceipt,
  writeAcceptedIosPendingUpload,
  writeIosUploadIntent,
} from './ios-upload-receipt.mjs'

const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)))

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function binding(path) {
  return {
    path: realpathSync(path),
    sha256: sha256(path),
    size: statSync(path).size,
  }
}

function createJournalFixture() {
  const repoRoot = mkdtempSync(join(tmpdir(), 'nvpn-ios-upload-journal-'))
  const exportDir = join(repoRoot, 'dist', 'ios', 'export')
  const frozenDir = join(repoRoot, 'dist', 'ios', 'frozen')
  const stageDir = join(repoRoot, 'stage')
  for (const path of [
    exportDir,
    frozenDir,
    stageDir,
  ]) {
    mkdirSync(path, { recursive: true })
  }

  const now = Math.floor(Date.now() / 1000)
  const commit = '1'.repeat(40)
  const tree = '2'.repeat(40)
  const signer = '3'.repeat(64)
  const ipaPath = join(exportDir, 'NostrVpnIos.ipa')
  const exportReceiptPath = join(frozenDir, 'app-store-receipt.json')
  writeFileSync(ipaPath, 'exact frozen IPA bytes\n')
  const ipaSha256 = sha256(ipaPath)
  const exportReceipt = {
    receiptSchema: 1,
    artifactType: 'iOS export from frozen xcarchive',
    distribution: 'app-store-connect',
    appGitSha: commit,
    appGitTree: tree,
    ipaSha256,
    identity: {
      appBundleIdentifier: 'fi.siriusbusiness.nvpn',
      appBuildGitSha: commit,
      buildNumber: '4010501',
      marketingVersion: '4.1.5',
      packetTunnelBuildGitSha: commit,
    },
    signing: {
      signerCertificateSha256: signer,
      signingTeamIdentifier: 'ABCDEFGHIJ',
    },
  }
  writeFileSync(exportReceiptPath, `${JSON.stringify(exportReceipt)}\n`)
  const stagedManifest = {
    tag: 'v4.1.5',
    commit,
    release_gate_attestation: { app_git_tree: tree },
    ios_app_store_gate: {
      receipt_schema: 1,
      app_git_sha: commit,
      app_git_tree: tree,
      bundle_id: 'fi.siriusbusiness.nvpn',
      marketing_version: '4.1.5',
      build_number: '4010501',
      ipa_sha256: ipaSha256,
      ipa_size: statSync(ipaPath).size,
      export_receipt_sha256: sha256(exportReceiptPath),
      signing_team_id: 'ABCDEFGHIJ',
      signer_certificate_sha256: signer,
    },
  }
  const stageRelease = join(stageDir, 'release.json')
  writeFileSync(stageRelease, `${JSON.stringify(stagedManifest)}\n`)

  const mutationEnv = {
    ...process.env,
    NVPN_RELEASE_STAGE_DIR: stageDir,
    NVPN_RELEASE_TAG: stagedManifest.tag,
  }
  const frozen = {
    ipaPath,
    gate: {
      ipa_sha256: ipaSha256,
      ipa_size: statSync(ipaPath).size,
      bundle_id: stagedManifest.ios_app_store_gate.bundle_id,
      marketing_version:
        stagedManifest.ios_app_store_gate.marketing_version,
      build_number: stagedManifest.ios_app_store_gate.build_number,
    },
  }
  const testflight = {
    schema: 1,
    status: 'passed',
    bundleId: frozen.gate.bundle_id,
    version: frozen.gate.marketing_version,
    buildNumber: frozen.gate.build_number,
    buildPresent: true,
    buildId: 'asc-build-id',
    uploadedDate: new Date(now * 1000).toISOString(),
    processingState: 'VALID',
    audience: 'APP_STORE_ELIGIBLE',
  }
  return {
    frozen,
    mutationEnv,
    now,
    repoRoot,
    stageDir,
    stagedManifest,
    testflight,
  }
}

function captureAndWriteIntent(fixture) {
  const value = captureIosUploadIntent({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
  })
  return writeIosUploadIntent({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    intent: value,
  })
}

function writePending(fixture, intentReceipt, source) {
  return writeAcceptedIosPendingUpload({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    intentReceipt,
    acceptanceSource: source,
  })
}

function writeFinal(fixture, pendingReceipt) {
  return finalizeIosUploadReceipt({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    pendingReceipt,
    testflight: fixture.testflight,
  })
}

function exactStat(path) {
  const metadata = statSync(path)
  return {
    bytes: readFileSync(path),
    ino: metadata.ino,
    mode: metadata.mode,
    mtimeMs: metadata.mtimeMs,
  }
}

function assertExactStat(path, expected) {
  const actual = exactStat(path)
  assert.deepEqual(actual.bytes, expected.bytes)
  assert.equal(actual.ino, expected.ino)
  assert.equal(actual.mode, expected.mode)
  assert.equal(actual.mtimeMs, expected.mtimeMs)
}

test('iOS upload journals are immutable and bind exact release bytes', () => {
  const fixture = createJournalFixture()
  const intent = captureAndWriteIntent(fixture)
  assert.equal(intent.created, true)
  assert.match(
    intent.value.attemptId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  )
  assert.equal(statSync(intent.path).mode & 0o777, 0o600)

  const intentBeforeRetry = exactStat(intent.path)
  const competingIntent = captureAndWriteIntent(fixture)
  assert.equal(competingIntent.created, false)
  assert.equal(competingIntent.value.attemptId, intent.value.attemptId)
  assertExactStat(intent.path, intentBeforeRetry)

  const waiting = reconcileIosUploadReceipts({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    testflight: { ...fixture.testflight, buildPresent: false },
  })
  assert.equal(waiting.uploadAction, 'wait-intent')
  assertExactStat(intent.path, intentBeforeRetry)

  const visible = reconcileIosUploadReceipts({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    testflight: fixture.testflight,
  })
  assert.equal(visible.uploadAction, 'recover-intent')

  const pending = writePending(
    fixture,
    intent,
    'app-store-connect-visible',
  )
  assert.equal(pending.created, true)
  assert.equal(statSync(pending.path).mode & 0o777, 0o600)
  const pendingBeforeRetry = exactStat(pending.path)
  const pendingRetry = writePending(
    fixture,
    intent,
    'transporter-returned',
  )
  assert.equal(pendingRetry.created, false)
  assert.equal(
    pendingRetry.value.acceptanceSource,
    'app-store-connect-visible',
  )
  assertExactStat(pending.path, pendingBeforeRetry)
  assert.deepEqual(
    validateIosPendingUploadReceipt({
      repoRoot: fixture.repoRoot,
      frozen: fixture.frozen,
      stagedManifest: fixture.stagedManifest,
      mutationEnv: fixture.mutationEnv,
    }).value,
    pending.value,
  )

  const readyToFinalize = reconcileIosUploadReceipts({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    testflight: fixture.testflight,
  })
  assert.equal(readyToFinalize.uploadAction, 'finalize-pending')

  const final = writeFinal(fixture, pending)
  assert.equal(final.created, true)
  assert.equal(statSync(final.path).mode & 0o777, 0o600)
  const finalBeforeRetry = exactStat(final.path)
  const finalRetry = writeFinal(fixture, pending)
  assert.equal(finalRetry.created, false)
  assertExactStat(final.path, finalBeforeRetry)

  const complete = reconcileIosUploadReceipts({
    repoRoot: fixture.repoRoot,
    frozen: fixture.frozen,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fixture.mutationEnv,
    testflight: fixture.testflight,
  })
  assert.equal(complete.uploadAction, 'use-final')
  assert.equal(complete.intentReceipt.path, intent.path)
  assert.equal(complete.pendingReceipt.path, pending.path)
  assert.equal(complete.finalReceipt.path, final.path)
  assert.ok(existsSync(intent.path))
  assert.ok(existsSync(pending.path))
  assert.ok(existsSync(final.path))
  assert.deepEqual(
    validateIosUploadReceipt({
      repoRoot: fixture.repoRoot,
      frozen: fixture.frozen,
      stagedManifest: fixture.stagedManifest,
      mutationEnv: fixture.mutationEnv,
      testflight: fixture.testflight,
    }).value,
    final.value,
  )
})

test('iOS upload reconciliation fails closed for orphan and broken chains', () => {
  const intent = { path: '/private/intent', value: {} }
  const pending = { path: '/private/pending', value: {} }
  const final = { path: '/private/final', value: {} }
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: false,
      intentReceipt: null,
      pendingReceipt: null,
      finalReceipt: null,
    }),
    'create-intent',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: false,
      intentReceipt: intent,
      pendingReceipt: null,
      finalReceipt: null,
    }),
    'wait-intent',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      buildValid: false,
      intentReceipt: intent,
      pendingReceipt: null,
      finalReceipt: null,
    }),
    'wait-intent',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      intentReceipt: intent,
      pendingReceipt: null,
      finalReceipt: null,
    }),
    'recover-intent',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: false,
      intentReceipt: intent,
      pendingReceipt: pending,
      finalReceipt: null,
    }),
    'wait-pending',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      intentReceipt: intent,
      pendingReceipt: pending,
      finalReceipt: null,
    }),
    'finalize-pending',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      intentReceipt: intent,
      pendingReceipt: pending,
      finalReceipt: final,
    }),
    'use-final',
  )
  for (const state of [
    {
      buildPresent: true,
      intentReceipt: null,
      pendingReceipt: null,
      finalReceipt: null,
    },
    {
      buildPresent: false,
      intentReceipt: null,
      pendingReceipt: pending,
      finalReceipt: null,
    },
    {
      buildPresent: true,
      intentReceipt: intent,
      pendingReceipt: null,
      finalReceipt: final,
    },
    {
      buildPresent: false,
      intentReceipt: intent,
      pendingReceipt: pending,
      finalReceipt: final,
    },
  ]) {
    assert.throws(
      () => planIosUploadReconciliation(state),
      /orphan|predecessor|no exact valid|no exact build/i,
    )
  }
})

test('iOS upload journals reject path collisions, symlinks, modes, and tampering', () => {
  const fixture = createJournalFixture()
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv: fixture.mutationEnv,
  })
  assert.throws(
    () =>
      iosUploadReceiptPaths({
        repoRoot: fixture.repoRoot,
        mutationEnv: {
          ...fixture.mutationEnv,
          NVPN_IOS_UPLOAD_INTENT_PATH: paths.final,
        },
      }),
    /must differ/i,
  )
  assert.throws(
    () =>
      iosUploadReceiptPaths({
        repoRoot: fixture.repoRoot,
        mutationEnv: {
          ...fixture.mutationEnv,
          NVPN_IOS_UPLOAD_INTENT_PATH: 'relative-intent.json',
        },
      }),
    /must be absolute/i,
  )

  const symlinkFixture = createJournalFixture()
  const symlinkPaths = iosUploadReceiptPaths({
    repoRoot: symlinkFixture.repoRoot,
    mutationEnv: symlinkFixture.mutationEnv,
  })
  const outside = join(symlinkFixture.repoRoot, 'outside.json')
  writeFileSync(outside, 'do not overwrite\n')
  symlinkSync(outside, symlinkPaths.intent)
  const desired = captureIosUploadIntent({
    repoRoot: symlinkFixture.repoRoot,
    frozen: symlinkFixture.frozen,
    stagedManifest: symlinkFixture.stagedManifest,
    mutationEnv: symlinkFixture.mutationEnv,
  })
  assert.throws(
    () =>
      writeIosUploadIntent({
        repoRoot: symlinkFixture.repoRoot,
        frozen: symlinkFixture.frozen,
        stagedManifest: symlinkFixture.stagedManifest,
        mutationEnv: symlinkFixture.mutationEnv,
        intent: desired,
      }),
    /regular non-symlink/i,
  )
  assert.equal(readFileSync(outside, 'utf8'), 'do not overwrite\n')

  const mismatchedFixture = createJournalFixture()
  captureAndWriteIntent(mismatchedFixture)
  assert.throws(
    () =>
      reconcileIosUploadReceipts({
        repoRoot: mismatchedFixture.repoRoot,
        frozen: mismatchedFixture.frozen,
        stagedManifest: mismatchedFixture.stagedManifest,
        mutationEnv: mismatchedFixture.mutationEnv,
        testflight: {
          ...mismatchedFixture.testflight,
          version: '4.1.4',
        },
      }),
    /exact valid build/i,
  )
  assert.equal(
    existsSync(
      iosUploadReceiptPaths({
        repoRoot: mismatchedFixture.repoRoot,
        mutationEnv: mismatchedFixture.mutationEnv,
      }).pending,
    ),
    false,
  )

  const intent = captureAndWriteIntent(fixture)
  chmodSync(intent.path, 0o644)
  assert.throws(
    () =>
      validateIosUploadIntent({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
      }),
    /mode must be 0600/i,
  )
  chmodSync(intent.path, 0o600)

  const pending = writePending(fixture, intent, 'transporter-returned')
  const final = writeFinal(fixture, pending)
  const originalPending = readFileSync(pending.path)
  writeFileSync(
    pending.path,
    `${JSON.stringify({
      ...pending.value,
      attemptId: '00000000-0000-4000-8000-000000000000',
    })}\n`,
  )
  assert.throws(
    () =>
      reconcileIosUploadReceipts({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
        testflight: fixture.testflight,
      }),
    /attempt|binding|differ|invalid/i,
  )
  writeFileSync(pending.path, originalPending)
  assert.throws(
    () =>
      validateIosUploadReceipt({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
        testflight: {
          ...fixture.testflight,
          buildId: 'substituted-build-id',
        },
      }),
    /final iOS upload receipt is invalid/i,
  )
  assert.throws(
    () =>
      validateIosUploadReceipt({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
        testflight: {
          ...fixture.testflight,
          processingState: 'PROCESSING',
        },
      }),
    /exact valid build/i,
  )
  assert.throws(
    () =>
      validateIosUploadReceipt({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
        testflight: {
          ...fixture.testflight,
          uploadedDate: '2000-01-01T00:00:00.000Z',
        },
      }),
    /exact valid build/i,
  )
  assert.ok(existsSync(final.path))

  writeFileSync(fixture.frozen.ipaPath, 'tampered IPA\n')
  assert.throws(
    () =>
      validateIosUploadIntent({
        repoRoot: fixture.repoRoot,
        frozen: fixture.frozen,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fixture.mutationEnv,
      }),
    /differs from exact frozen staging|authorization binding/i,
  )
})

function writeExecutable(path, source) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, source)
  chmodSync(path, 0o755)
}

function installFakeAppleBoundary(fixture) {
  const scripts = join(fixture.repoRoot, 'scripts')
  const state = join(fixture.repoRoot, 'asc-state.json')
  const visible = join(fixture.repoRoot, 'asc-visible.json')
  const uploadLog = join(fixture.repoRoot, 'upload.log')
  const barrierLog = join(fixture.repoRoot, 'preflight-barrier.log')
  const preflightLog = join(fixture.repoRoot, 'asc-preflight.log')
  const transporter = join(fixture.repoRoot, 'iTMSTransporter')
  const absent = {
    ...fixture.testflight,
    buildPresent: false,
    buildId: null,
    uploadedDate: null,
    processingState: null,
    audience: null,
  }
  writeFileSync(state, `${JSON.stringify(absent)}\n`)
  writeFileSync(visible, `${JSON.stringify(fixture.testflight)}\n`)
  writeFileSync(uploadLog, '')
  writeFileSync(barrierLog, '')
  writeFileSync(preflightLog, '')
  writeExecutable(transporter, '#!/bin/sh\nexit 0\n')
  writeExecutable(
    join(scripts, 'ios-build'),
	    `#!/bin/sh
	set -eu
	case "$1" in
	  ios-upload-preflight)
	    [ "\${FAKE_UPLOAD_PREFLIGHT_MODE:-success}" = success ] || exit 87
	    ;;
	  ios-upload)
	    printf 'upload\\n' >> "$FAKE_UPLOAD_LOG"
	    sleep "\${FAKE_UPLOAD_DELAY:-0}"
	    cp "$FAKE_ASC_VISIBLE" "$FAKE_ASC_STATE"
	    if [ "\${FAKE_UPLOAD_MODE:-success}" = accept-crash ]; then
	      exit 86
	    fi
	    ;;
	  *)
	    exit 2
	    ;;
	esac
	`,
  )
  writeExecutable(
    join(scripts, 'testflight-internal'),
    `#!/bin/sh
set -eu
case "$1" in
  preflight)
    printf 'read\\n' >> "$FAKE_ASC_PREFLIGHT_LOG"
    if [ "\${FAKE_PREFLIGHT_BARRIER:-false}" = true ] &&
       ! grep -q '"buildPresent":true' "$FAKE_ASC_STATE"; then
      printf 'ready\\n' >> "$FAKE_PREFLIGHT_BARRIER_LOG"
      attempts=0
      while [ "$(wc -l < "$FAKE_PREFLIGHT_BARRIER_LOG" | tr -d ' ')" -lt 2 ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 200 ] || exit 91
        sleep 0.01
      done
    fi
    cat "$FAKE_ASC_STATE"
    ;;
  wait)
    attempts=0
    limit="\${FAKE_WAIT_ATTEMPTS:-200}"
    until grep -q '"buildPresent":true' "$FAKE_ASC_STATE"; do
      attempts=$((attempts + 1))
      [ "$attempts" -lt "$limit" ] || exit 92
      sleep 0.01
    done
    ;;
  put|public|public-status)
    ;;
  *)
    exit 2
    ;;
esac
`,
  )
  writeExecutable(
    join(scripts, 'appstore-draft'),
    `#!/bin/sh
set -eu
case "$1" in
  preflight)
    printf '%s\\n' '{"schema":1,"status":"passed","bundleId":"fi.siriusbusiness.nvpn","version":"4.1.5","buildNumber":"4010501","reviewState":"READY_FOR_SALE","versionState":"READY_FOR_SALE"}'
    ;;
  status)
    ;;
  *)
    exit 2
    ;;
esac
`,
  )
  return {
    mutationEnv: {
      ...fixture.mutationEnv,
      FAKE_ASC_STATE: state,
      FAKE_ASC_VISIBLE: visible,
      FAKE_UPLOAD_LOG: uploadLog,
      FAKE_PREFLIGHT_BARRIER_LOG: barrierLog,
      FAKE_ASC_PREFLIGHT_LOG: preflightLog,
      NVPN_TESTFLIGHT_REVIEW_NOTES: 'Complete beta reviewer instructions.',
      NVPN_APPSTORE_REVIEW_NOTES: 'Complete App Review instructions.',
      NVPN_ITMS_TRANSPORTER: transporter,
    },
    state,
    uploadLog,
    preflightLog,
  }
}

function uploadCount(path) {
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).length
}

test('publication rejects missing review material before Apple contact or upload intent', () => {
  for (const missing of [
    ['NVPN_TESTFLIGHT_REVIEW_NOTES'],
    ['NVPN_APPSTORE_REVIEW_NOTES'],
    ['NVPN_TESTFLIGHT_REVIEW_NOTES', 'NVPN_APPSTORE_REVIEW_NOTES'],
  ]) {
    const fixture = createJournalFixture()
    const fake = installFakeAppleBoundary(fixture)
    const mutationEnv = { ...fake.mutationEnv }
    for (const name of missing) mutationEnv[name] = '  '
    assert.throws(
      () => preflightIosPublication({
        repoRoot: fixture.repoRoot,
        stagedManifest: fixture.stagedManifest,
        mutationEnv,
      }),
      /reviewer WireGuard configuration or complete.*review notes/i,
    )
    assert.equal(readFileSync(fake.preflightLog, 'utf8'), '')
    assert.equal(uploadCount(fake.uploadLog), 0)
    assert.equal(existsSync(iosUploadReceiptPaths({
      repoRoot: fixture.repoRoot,
      mutationEnv,
    }).intent), false)
  }
})

test('publication accepts either both review notes or a shared reviewer configuration', () => {
  for (const config of [false, true]) {
    const fixture = createJournalFixture()
    const fake = installFakeAppleBoundary(fixture)
    const mutationEnv = { ...fake.mutationEnv }
    if (config) {
      delete mutationEnv.NVPN_TESTFLIGHT_REVIEW_NOTES
      delete mutationEnv.NVPN_APPSTORE_REVIEW_NOTES
      mutationEnv.NVPN_APPSTORE_REVIEW_WIREGUARD_CONFIG = '[Interface]\nAddress = 10.0.0.2/32'
    }
    const preflight = preflightIosPublication({
      repoRoot: fixture.repoRoot,
      stagedManifest: fixture.stagedManifest,
      mutationEnv,
    })
    assert.equal(preflight.uploadAction, 'create-intent')
    assert.equal(readFileSync(fake.preflightLog, 'utf8'), 'read\n')
    assert.equal(uploadCount(fake.uploadLog), 0)
  }
})

test('local upload validation fails before creating an immutable intent', () => {
  const fixture = createJournalFixture()
  const fake = installFakeAppleBoundary(fixture)
  const mutationEnv = {
    ...fake.mutationEnv,
    FAKE_UPLOAD_PREFLIGHT_MODE: 'fail',
  }
  const preflight = preflightIosPublication({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv,
  })
  assert.equal(preflight.uploadAction, 'create-intent')

  assert.throws(
    () =>
      publishExactIosDistribution({
        repoRoot: fixture.repoRoot,
        stagedManifest: fixture.stagedManifest,
        mutationEnv,
        preflight,
      }),
    /failed/i,
  )
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv,
  })
  assert.equal(existsSync(paths.intent), false)
  assert.equal(uploadCount(fake.uploadLog), 0)
})

test('accepted-before-return crash recovers from ASC without a duplicate upload', () => {
  const fixture = createJournalFixture()
  const fake = installFakeAppleBoundary(fixture)
  const mutationEnv = {
    ...fake.mutationEnv,
    FAKE_UPLOAD_MODE: 'accept-crash',
  }
  const preflight = preflightIosPublication({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv,
  })
  assert.equal(preflight.uploadAction, 'create-intent')
  assert.throws(
    () =>
      publishExactIosDistribution({
        repoRoot: fixture.repoRoot,
        stagedManifest: fixture.stagedManifest,
        mutationEnv,
        preflight,
      }),
    /failed/i,
  )
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv,
  })
  assert.equal(uploadCount(fake.uploadLog), 1)
  assert.ok(existsSync(paths.intent))
  assert.equal(existsSync(paths.pending), false)
  assert.equal(existsSync(paths.final), false)

  const retryEnv = { ...mutationEnv, FAKE_UPLOAD_MODE: 'success' }
  const retryPreflight = preflightIosPublication({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: retryEnv,
  })
  assert.equal(retryPreflight.uploadAction, 'recover-intent')
  const recovered = publishExactIosDistribution({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: retryEnv,
    preflight: retryPreflight,
  })
  assert.deepEqual(recovered, { submitted: true, verified: true })
  assert.equal(uploadCount(fake.uploadLog), 1)
  assert.ok(existsSync(paths.intent))
  assert.ok(existsSync(paths.pending))
  assert.ok(existsSync(paths.final))
})

test('intent creation failure cannot invoke upload', () => {
  const fixture = createJournalFixture()
  const fake = installFakeAppleBoundary(fixture)
  const preflight = preflightIosPublication({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv: fake.mutationEnv,
  })
  assert.equal(preflight.uploadAction, 'create-intent')
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv: fake.mutationEnv,
  })
  const outside = join(fixture.repoRoot, 'intent-symlink-target')
  writeFileSync(outside, 'must remain unchanged\n')
  symlinkSync(outside, paths.intent)

  assert.throws(
    () =>
      publishExactIosDistribution({
        repoRoot: fixture.repoRoot,
        stagedManifest: fixture.stagedManifest,
        mutationEnv: fake.mutationEnv,
        preflight,
      }),
    /regular non-symlink/i,
  )
  assert.equal(uploadCount(fake.uploadLog), 0)
  assert.equal(readFileSync(outside, 'utf8'), 'must remain unchanged\n')
})

test('pre-spawn crash state times out without changing intent or re-uploading', () => {
  const fixture = createJournalFixture()
  const fake = installFakeAppleBoundary(fixture)
  const intent = captureAndWriteIntent(fixture)
  const intentBeforeWait = exactStat(intent.path)
  const mutationEnv = {
    ...fake.mutationEnv,
    FAKE_WAIT_ATTEMPTS: '3',
  }
  const preflight = preflightIosPublication({
    repoRoot: fixture.repoRoot,
    stagedManifest: fixture.stagedManifest,
    mutationEnv,
  })
  assert.equal(preflight.uploadAction, 'wait-intent')

  assert.throws(
    () =>
      publishExactIosDistribution({
        repoRoot: fixture.repoRoot,
        stagedManifest: fixture.stagedManifest,
        mutationEnv,
        preflight,
      }),
    /failed/i,
  )
  assert.equal(uploadCount(fake.uploadLog), 0)
  assertExactStat(intent.path, intentBeforeWait)
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv,
  })
  assert.equal(existsSync(paths.pending), false)
  assert.equal(existsSync(paths.final), false)
})

function runWorker(path, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', reject)
    child.on('close', (status) => resolve({ status, stderr, stdout }))
  })
}

test('concurrent iOS publishers elect one intent winner and invoke upload once', async () => {
  const fixture = createJournalFixture()
  const fake = installFakeAppleBoundary(fixture)
  const worker = join(fixture.repoRoot, 'publisher-worker.mjs')
  const fixturePath = join(fixture.repoRoot, 'publisher-fixture.json')
  writeFileSync(
    fixturePath,
    `${JSON.stringify({
      mutationEnv: {
        ...fake.mutationEnv,
        FAKE_PREFLIGHT_BARRIER: 'true',
        FAKE_UPLOAD_DELAY: '0.25',
      },
      repoRoot: fixture.repoRoot,
      stagedManifest: fixture.stagedManifest,
    })}\n`,
  )
  writeFileSync(
    worker,
    `import { readFileSync } from 'node:fs'
import {
  preflightIosPublication,
  publishExactIosDistribution,
} from ${JSON.stringify(
      join(sourceRoot, 'scripts', 'ios-release-publication.mjs'),
    )}
const fixture = JSON.parse(readFileSync(process.env.FIXTURE_PATH, 'utf8'))
const preflight = preflightIosPublication({
  repoRoot: fixture.repoRoot,
  stagedManifest: fixture.stagedManifest,
  mutationEnv: fixture.mutationEnv,
})
publishExactIosDistribution({
  repoRoot: fixture.repoRoot,
  stagedManifest: fixture.stagedManifest,
  mutationEnv: fixture.mutationEnv,
  preflight,
})
`,
  )

  const workerEnv = { ...process.env, FIXTURE_PATH: fixturePath }
  const results = await Promise.all([
    runWorker(worker, workerEnv),
    runWorker(worker, workerEnv),
  ])
  for (const result of results) {
    assert.equal(
      result.status,
      0,
      `${result.stdout}\n${result.stderr}`,
    )
  }
  assert.equal(uploadCount(fake.uploadLog), 1)
  const paths = iosUploadReceiptPaths({
    repoRoot: fixture.repoRoot,
    mutationEnv: fake.mutationEnv,
  })
  assert.ok(existsSync(paths.intent))
  assert.ok(existsSync(paths.pending))
  assert.ok(existsSync(paths.final))
}
)
