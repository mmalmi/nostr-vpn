import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  collectReleaseGateReceipts,
} from './release-artifact-provenance-lib.mjs'
import {
  completeReleaseGateFromReceipts,
  unlinkIfSameFile,
} from './release-gate-resume.mjs'

const commit = 'a'.repeat(40)
const tree = 'b'.repeat(40)

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-release-gate-resume-'))
  const env = {
    ...process.env,
    NVPN_FLEET_GATE_FIXTURE_ROOT: root,
    NVPN_FLEET_GATE_APP_GIT_SHA: commit,
    NVPN_FLEET_GATE_APP_GIT_TREE: tree,
  }
  delete env.NODE_TEST_CONTEXT
  const generated = spawnSync(
    process.execPath,
    ['--test', '--test-name-pattern=^release receipt collection requires exact source and strict public UI gates$',
      join(process.cwd(), 'scripts/release-artifact-provenance-lib.test.mjs')],
    {
      encoding: 'utf8',
      env,
    },
  )
  assert.equal(generated.status, 0, generated.stderr)
  const request = JSON.parse(
    readFileSync(join(root, 'fleet-gate-fixture.json'), 'utf8'),
  ).request
  unlinkSync(request.receiptPaths.releaseGateSummary)
  return { root, ...request.receiptPaths }
}

test('resumed completion validates every concrete receipt before writing a bound summary', () => {
  const value = fixture()
  try {
    const result = completeReleaseGateFromReceipts({
      commit,
      tree,
      releaseGateSummaryPath: value.releaseGateSummary,
      platformReceiptPaths: value.platforms,
      targetSeconds: 1_800,
      monotonicSeconds: (() => {
        const values = [10, 12]
        return () => values.shift()
      })(),
    })

    assert.equal(result.created, true)
    const summary = JSON.parse(readFileSync(value.releaseGateSummary, 'utf8'))
    assert.deepEqual(summary, {
      receiptSchema: 2,
      completionMode: 'validated-existing-concrete-receipts',
      elapsedSeconds: 2,
      elapsedScope: 'receipt-validation-only',
      targetSeconds: 1_800,
      targetStatus: 'not-measured',
      appGitSha: commit,
      appGitTree: tree,
      validatorGitSha: commit,
      validatorGitTree: tree,
      platformGateReceipts: result.platformGateReceipts,
      platformSourceEquivalence: result.platformSourceEquivalence,
    })
    assert.deepEqual(
      collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: value.releaseGateSummary,
        platformReceiptPaths: value.platforms,
      }).platformGateReceipts,
      result.platformGateReceipts,
    )
    summary.validatorGitSha = 'c'.repeat(40)
    writeFileSync(value.releaseGateSummary, JSON.stringify(summary))
    assert.throws(
      () => collectReleaseGateReceipts({
        commit,
        tree,
        releaseGateSummaryPath: value.releaseGateSummary,
        platformReceiptPaths: value.platforms,
      }),
      /not bound to the exact candidate, validator, and concrete receipts/i,
    )
  } finally {
    rmSync(value.root, { recursive: true, force: true })
  }
})

test('cleanup never unlinks a replacement summary pathname', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-release-gate-cleanup-'))
  const path = join(root, 'summary.json')
  try {
    writeFileSync(path, 'original')
    const original = lstatSync(path)
    unlinkSync(path)
    writeFileSync(path, 'replacement')
    assert.equal(unlinkIfSameFile(path, original), false)
    assert.equal(readFileSync(path, 'utf8'), 'replacement')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('environment partial mode rejects resume before receipt validation or mutation', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-release-gate-partial-'))
  const logDir = join(root, 'gate')
  try {
    const result = spawnSync(
      process.execPath,
      [join(process.cwd(), 'scripts/local-release.mjs'), '--complete-gate-from-receipts'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          NVPN_RELEASE_ALLOW_PARTIAL: 'true',
          NVPN_RELEASE_GATE_LOG_DIR: logDir,
          NVPN_RELEASE_JOIN_RESULT_DIR: join(root, 'joins'),
        },
      },
    )
    assert.equal(result.status, 1)
    assert.match(result.stderr, /complete-gate-from-receipts cannot be combined/i)
    assert.equal(existsSync(join(logDir, 'release-gate-summary.json')), false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('resumed completion leaves no summary when a concrete receipt is missing', () => {
  const value = fixture()
  try {
    unlinkSync(value.platforms.windows.network)
    assert.throws(
      () => completeReleaseGateFromReceipts({
        commit,
        tree,
        releaseGateSummaryPath: value.releaseGateSummary,
        platformReceiptPaths: value.platforms,
      }),
      /Windows desktop network receipt is missing/i,
    )
    assert.equal(existsSync(value.releaseGateSummary), false)
  } finally {
    rmSync(value.root, { recursive: true, force: true })
  }
})

test('a pending iOS seal does not hide invalid completed desktop evidence', () => {
  const value = fixture()
  try {
    unlinkSync(value.platforms.ios.frozen_archive)
    const path = value.platforms.windows.installer
    const receipt = JSON.parse(readFileSync(path, 'utf8'))
    receipt.installerInstalledAndLaunched = false
    writeFileSync(path, JSON.stringify(receipt))
    assert.throws(
      () => completeReleaseGateFromReceipts({
        commit,
        tree,
        releaseGateSummaryPath: value.releaseGateSummary,
        platformReceiptPaths: value.platforms,
      }),
      /Windows exact installer gate receipt is incomplete/i,
    )
    assert.equal(existsSync(value.releaseGateSummary), false)
  } finally {
    rmSync(value.root, { recursive: true, force: true })
  }
})

test('resumed completion leaves no summary when an artifact identity is wrong', () => {
  const value = fixture()
  try {
    const path = value.platforms.android.physical
    const receipt = JSON.parse(readFileSync(path, 'utf8'))
    receipt.appGitSha = 'c'.repeat(40)
    writeFileSync(path, JSON.stringify(receipt))
    assert.throws(
      () => completeReleaseGateFromReceipts({
        commit,
        tree,
        releaseGateSummaryPath: value.releaseGateSummary,
        platformReceiptPaths: value.platforms,
      }),
      /Physical Android artifact receipt.*release candidate/i,
    )
    assert.equal(existsSync(value.releaseGateSummary), false)
  } finally {
    rmSync(value.root, { recursive: true, force: true })
  }
})

test('resumed completion is idempotent and never overwrites an existing summary', () => {
  const value = fixture()
  try {
    const first = completeReleaseGateFromReceipts({
      commit,
      tree,
      releaseGateSummaryPath: value.releaseGateSummary,
      platformReceiptPaths: value.platforms,
    })
    const bytes = readFileSync(value.releaseGateSummary)
    const second = completeReleaseGateFromReceipts({
      commit,
      tree,
      releaseGateSummaryPath: value.releaseGateSummary,
      platformReceiptPaths: value.platforms,
    })
    assert.equal(first.created, true)
    assert.equal(second.created, false)
    assert.deepEqual(readFileSync(value.releaseGateSummary), bytes)
  } finally {
    rmSync(value.root, { recursive: true, force: true })
  }
})
