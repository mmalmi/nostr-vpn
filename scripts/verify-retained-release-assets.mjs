#!/usr/bin/env node
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

const release421 = {
  tag: 'v4.1.21',
  productCommit: '52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4',
  cid: 'nhash1qqs2j2rwpk5v66x9ky9jx0que2tfjfkwyw7vtae62up6kqcf2gnfw3s9yyqc2caveefuys0ctssvyzvjwmxdxxk48d9exsd3s2tef8k5ln9vj2cf0ekp6',
  verifierCommit: 'fe3e520e85cc6e667bf7d4c37ae495258ef2a174',
  runId: 43248941791,
  jobId: 131289161450,
}

const release422 = {
  tag: 'v4.1.22',
  productCommit: 'c09d4bf805779352bd7ccf9a6e7b7dc2477bbcfd',
  cid: 'nhash1qqs99497nqkr3jvgk3xyd5cdk0jckk8ek6ngf7qygvaz9ldsjngfhvg9yyqnzhlzwjen4q43kmx8hxwteqq3l4vkfu7xkf9twve966jvftzm7cgmluy0t',
  verifierCommit: 'bfd4db73733bee35ba9e70b5638ce3c2f1d92dfd',
  runId: 43763394581,
  jobId: 132962977589,
  macJobId: 132962977844,
}

function releaseEvidence(tag) {
  const baseline = [release421, release422].find((release) => release.tag === tag)
  assert.ok(baseline, 'No retained evidence for this release')
  return baseline
}

// This job independently downloaded and verified every immutable asset. A
// different job's failure does not invalidate that completed exact-input result.
export function validateRetainedReleaseAssets({ tag, commit, cid, run, job, macJob }) {
  const baseline = releaseEvidence(tag)
  assert.equal(commit, baseline.productCommit, 'Retained assets belong to another product commit')
  assert.equal(cid, baseline.cid, 'Retained assets belong to another immutable draft')
  assert.equal(run.id, baseline.runId)
  assert.equal(run.head_sha, baseline.verifierCommit)
  assert.equal(run.event, 'workflow_dispatch')
  assert.equal(run.display_title, `Release ${tag} @ ${commit} from ${cid}`)
  assert.equal(job.id, baseline.jobId)
  assert.equal(job.run_id, baseline.runId)
  assert.equal(job.head_sha, baseline.verifierCommit)
  assert.equal(job.name, 'Verify exact locally gated assets (no publication)')
  assert.equal(job.status, 'completed')
  assert.equal(job.conclusion, 'success')
  assert.equal(job.steps?.find((step) => step.name === 'Import and verify the immutable locally gated release')?.conclusion, 'success')
  if (baseline.macJobId) {
    assert.equal(macJob.id, baseline.macJobId)
    assert.equal(macJob.run_id, baseline.runId)
    assert.equal(macJob.head_sha, baseline.verifierCommit)
    assert.equal(macJob.name, 'macOS 14 SDK compatibility')
    assert.equal(macJob.status, 'completed')
    assert.equal(macJob.conclusion, 'success')
    for (const name of ['Verify unchanged macOS 14 SDK compatibility evidence', 'Verify iOS release artifact orchestration without devices']) {
      assert.equal(macJob.steps?.find((step) => step.name === name)?.conclusion, 'success')
    }
  }
  return { status: 'passed', tag, commit, cid, runId: baseline.runId, jobId: baseline.jobId, macJobId: baseline.macJobId }
}

function main() {
  const baseline = releaseEvidence(process.env.NVPN_RELEASE_TAG)
  const api = (path) => {
    const result = spawnSync('gh', ['api', `repos/mmalmi/nostr-vpn/${path}`], { encoding: 'utf8', timeout: 30_000 })
    if (result.status !== 0) throw new Error(result.stderr || 'Could not verify retained asset evidence')
    return JSON.parse(result.stdout)
  }
  console.log(JSON.stringify(validateRetainedReleaseAssets({
    tag: process.env.NVPN_RELEASE_TAG,
    commit: process.env.NVPN_RELEASE_COMMIT,
    cid: process.env.NVPN_RELEASE_CID,
    run: api(`actions/runs/${baseline.runId}`),
    job: api(`actions/jobs/${baseline.jobId}`),
    macJob: baseline.macJobId ? api(`actions/jobs/${baseline.macJobId}`) : undefined,
  })))
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main()
