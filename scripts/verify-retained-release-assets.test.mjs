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

test('4.1.22 pins both current Mac steps and the complete asset import to the same exact run', () => {
  const input = fixture()
  input.tag = 'v4.1.22'
  input.commit = 'c09d4bf805779352bd7ccf9a6e7b7dc2477bbcfd'
  input.cid = 'nhash1qqs99497nqkr3jvgk3xyd5cdk0jckk8ek6ngf7qygvaz9ldsjngfhvg9yyqnzhlzwjen4q43kmx8hxwteqq3l4vkfu7xkf9twve966jvftzm7cgmluy0t'
  input.run.id = 43763394581
  input.run.head_sha = 'bfd4db73733bee35ba9e70b5638ce3c2f1d92dfd'
  input.run.display_title = `Release ${input.tag} @ ${input.commit} from ${input.cid}`
  Object.assign(input.job, { id: 132962977589, run_id: input.run.id, head_sha: input.run.head_sha })
  input.macJob = {
    ...input.job, id: 132962977844, name: 'macOS 14 SDK compatibility',
    steps: ['Verify unchanged macOS 14 SDK compatibility evidence', 'Verify iOS release artifact orchestration without devices']
      .map((name) => ({ name, conclusion: 'success' })),
  }
  assert.equal(validateRetainedReleaseAssets(input).macJobId, input.macJob.id)
  for (const key of ['id', 'run_id', 'head_sha', 'name', 'status', 'conclusion']) {
    assert.throws(() => validateRetainedReleaseAssets({ ...input, macJob: { ...input.macJob, [key]: 'changed' } }))
  }
  input.macJob.steps[1].conclusion = 'skipped'
  assert.throws(() => validateRetainedReleaseAssets(input))
})
