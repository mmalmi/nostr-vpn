#!/usr/bin/env node
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

// GitHub retired macOS 14 runners. Preserve the successful Xcode 15.4 / SDK
// 14.5 check only while both of its complete source inputs remain identical.
const baseline = {
  commit: '5e8c0efd322c8ae3fdb18e212fbfd1b012046cd9',
  run: 41683170056,
  job: 126081888675,
  workflowSha256: '477c2b31b4f19c777226acfb2c8a6efb9b5a4140a3aae8f83dff03aa1cb3b8be',
  files: {
    'macos/Sources/QRCodeScannerView.swift': '97f4a395e71b89714c363e9fc2d5b57fe09ae407dc02238be74e26a9f9234976',
    'scripts/check-macos-swift-sdk-compat.sh': '023c5f10a16963587537327784a1e9f86324cf1f7716e98e0086d439412db788',
  },
}
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

export function validateMacos14SdkEvidence({ files, job, workflow }) {
  for (const [path, expected] of Object.entries(baseline.files)) {
    assert.equal(sha256(files[path]), expected,
      `macOS 14 SDK evidence does not cover changed ${path}; collect new older-SDK evidence`)
  }
  assert.equal(sha256(workflow), baseline.workflowSha256, 'Historical workflow differs')
  assert.equal(job.id, baseline.job)
  assert.equal(job.run_id, baseline.run)
  assert.equal(job.head_sha, baseline.commit)
  assert.equal(job.name, 'macOS 14 SDK compatibility')
  assert.equal(job.conclusion, 'success', 'Historical SDK job did not succeed')
  assert.equal(job.steps?.find((step) => step.name === 'Compile-check macOS 14 SDK compatibility')?.conclusion,
    'success', 'Historical older-SDK compile did not succeed')
  return { status: 'passed', sourceCommit: baseline.commit, runId: baseline.run, jobId: baseline.job }
}

function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const api = (path) => {
    const result = spawnSync('gh', ['api', `repos/mmalmi/nostr-vpn/${path}`], {
      encoding: 'utf8', timeout: 30_000,
    })
    if (result.status !== 0) throw new Error(result.stderr || 'Could not verify historical SDK evidence')
    return JSON.parse(result.stdout)
  }
  const job = api(`actions/jobs/${baseline.job}`)
  const source = api(`contents/.github/workflows/release.yml?ref=${baseline.commit}`)
  assert.equal(source.encoding, 'base64')
  const files = Object.fromEntries(Object.keys(baseline.files).map((path) => [path, readFileSync(resolve(root, path))]))
  console.log(JSON.stringify(validateMacos14SdkEvidence({
    files, job, workflow: Buffer.from(source.content, 'base64'),
  })))
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main()
