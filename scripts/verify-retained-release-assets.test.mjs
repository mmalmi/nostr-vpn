import assert from 'node:assert/strict'
import test from 'node:test'
import { validateRetainedReleaseAssets } from './verify-retained-release-assets.mjs'

function fixture() {
  const tag = 'v4.1.21'
  const commit = '52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4'
  const cid = 'nhash1qqs2j2rwpk5v66x9ky9jx0que2tfjfkwyw7vtae62up6kqcf2gnfw3s9yyqc2caveefuys0ctssvyzvjwmxdxxk48d9exsd3s2tef8k5ln9vj2cf0ekp6'
  const head_sha = 'fe3e520e85cc6e667bf7d4c37ae495258ef2a174'
  return { tag, commit, cid,
    run: { id: 43248941791, head_sha, event: 'workflow_dispatch', display_title: `Release ${tag} @ ${commit} from ${cid}` },
    job: { id: 131289161450, run_id: 43248941791, head_sha,
      name: 'Verify exact locally gated assets (no publication)', status: 'completed', conclusion: 'success',
      steps: [{ name: 'Import and verify the immutable locally gated release', conclusion: 'success' }] },
  }
}

test('a successful exact-input asset job remains usable independently of other jobs', () => {
  const input = fixture()
  input.run.conclusion = 'failure'
  assert.equal(validateRetainedReleaseAssets(input).status, 'passed')
})

test('retained asset evidence rejects changed inputs, identity and skipped checks', () => {
  for (const [object, key] of [
    ['', 'tag'], ['', 'commit'], ['', 'cid'],
    ['run', 'id'], ['run', 'head_sha'], ['run', 'event'], ['run', 'display_title'],
    ['job', 'id'], ['job', 'run_id'], ['job', 'head_sha'], ['job', 'name'], ['job', 'status'], ['job', 'conclusion'],
  ]) {
    const input = fixture()
    const target = object ? input[object] : input
    target[key] = 'different'
    assert.throws(() => validateRetainedReleaseAssets(input), `${object}.${key}`)
  }
  const input = fixture()
  input.job.steps[0].conclusion = 'skipped'
  assert.throws(() => validateRetainedReleaseAssets(input))
})
