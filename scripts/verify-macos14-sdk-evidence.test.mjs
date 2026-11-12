import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { validateMacos14SdkEvidence } from './verify-macos14-sdk-evidence.mjs'

function fixture() {
  return {
    files: Object.fromEntries([
      'macos/Sources/QRCodeScannerView.swift',
      'scripts/check-macos-swift-sdk-compat.sh',
    ].map((path) => [path, readFileSync(path)])),
    workflow: execFileSync('git', ['show', '5e8c0efd322c8ae3fdb18e212fbfd1b012046cd9:.github/workflows/release.yml']),
    job: {
      id: 126081888675, run_id: 41683170056,
      head_sha: '5e8c0efd322c8ae3fdb18e212fbfd1b012046cd9',
      name: 'macOS 14 SDK compatibility', conclusion: 'success',
      steps: [{ name: 'Compile-check macOS 14 SDK compatibility', conclusion: 'success' }],
    },
  }
}

test('unchanged complete SDK inputs reuse the successful older-SDK check', () => {
  assert.equal(validateMacos14SdkEvidence(fixture()).status, 'passed')
})

test('source, SDK command, historical workflow and successful job must all match', () => {
  for (const mutate of [
    (value) => { value.files['macos/Sources/QRCodeScannerView.swift'] = Buffer.from('changed') },
    (value) => { value.files['scripts/check-macos-swift-sdk-compat.sh'] = Buffer.from('changed') },
    (value) => { value.workflow = Buffer.from('changed') },
    (value) => { value.job.head_sha = 'a'.repeat(40) },
    (value) => { value.job.run_id += 1 },
    (value) => { value.job.id += 1 },
    (value) => { value.job.name = 'different check' },
    (value) => { value.job.conclusion = 'failure' },
    (value) => { value.job.steps[0].conclusion = 'skipped' },
    (value) => { value.job.steps = [] },
  ]) {
    const value = fixture()
    mutate(value)
    assert.throws(() => validateMacos14SdkEvidence(value))
  }
})
