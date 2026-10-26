import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

import {
  publishReleaseRefs,
  releaseWorkflowRunTitle,
} from './publish-release-refs.mjs'

const commit = 'a'.repeat(40)
const tree = 'b'.repeat(40)
const previous = 'c'.repeat(40)
const tag = 'v4.1.5'
const cid = 'nhash1acdefghjklmnpqrstuvwxyz023456789'
const repository = 'example/nostr-vpn'

function options() {
  return {
    stageDir: '/private/release/stage',
    tag,
    cid,
    env: {},
  }
}

function successfulGate(events, { failAt = 0 } = {}) {
  let call = 0
  return (gateOptions) => {
    call += 1
    events.push({
      mutation: false,
      name: 'gate',
      requireTag: gateOptions.requireTag,
    })
    if (call === failAt) {
      throw new Error(`gate failure ${call}`)
    }
    return {
      appGitSha: commit,
      appGitTree: tree,
      status: 'passed',
      tag,
    }
  }
}

function fakePublication({
  githubMaster = previous,
  githubTag = '',
  htreeMaster = previous,
  htreeTag = '',
  localTag = false,
  workflow = 'none',
  conflictingCid = '',
  failDraft = false,
  driftBeforeWorkflowList = false,
  workflowHeadSha = commit,
  mismatchedPushUrl = '',
  multiplePushUrls = '',
  workflowAppearsOnList = 0,
  duplicateExactRuns = false,
} = {}) {
  const events = []
  const state = {
    githubMaster,
    githubTag,
    htreeMaster,
    htreeTag,
    localTag,
    workflow,
  }
  let workflowListCount = 0
  const workflowRow = (status = state.workflow) => {
    const completed = status === 'success' || status === 'failure'
    return {
      conclusion: completed ? status : '',
      databaseId: 415,
      displayTitle: releaseWorkflowRunTitle({ tag, commit, cid }),
      event: 'workflow_dispatch',
      headSha: workflowHeadSha,
      status: completed ? 'completed' : status,
    }
  }
  const result = (status = 0, stdout = '', stderr = '') => ({
    status,
    stdout,
    stderr,
  })
  const runCommand = (command, args) => {
    const name = `${command} ${args.join(' ')}`
    if (command === 'htree' && args[0] === 'get') {
      events.push({ mutation: false, name: 'htree-get' })
      return result()
    }
    if (
      command === process.execPath
      && args[0].endsWith('/verify-release-publication-bundle.mjs')
    ) {
      events.push({ mutation: false, name: 'verify-draft' })
      return failDraft
        ? result(1, '', 'draft mismatch')
        : result(0, '{"ok":true}')
    }
    if (command === 'git' && args[0] === 'remote') {
      const remoteName = args.at(-1)
      if (args.includes('--push') && mismatchedPushUrl === remoteName) {
        return result(0, 'ssh://unreviewed.invalid/nostr-vpn')
      }
      if (args.includes('--push') && multiplePushUrls === remoteName) {
        return result(
          0,
          'ssh://first.invalid/nostr-vpn\nssh://second.invalid/nostr-vpn',
        )
      }
      return result(
        0,
        remoteName === 'github'
          ? `git@github.com:${repository}.git`
          : 'htree://self/nostr-vpn',
      )
    }
    if (command === 'gh' && args[0] === 'auth') {
      return result()
    }
    if (command === 'gh' && args[0] === 'repo') {
      return result(0, repository)
    }
    if (command === 'git' && args[0] === 'ls-remote') {
      const remote = args[2]
      const reference = args[3]
      assert.equal(reference, `refs/tags/${tag}`)
      assert.ok(['github', 'origin'].includes(remote))
      const sha = state[remote === 'github' ? 'githubTag' : 'htreeTag']
      return sha
        ? result(0, `${sha}\t${reference}`)
        : result(2)
    }
    if (command === 'git' && args[0] === 'cat-file') {
      return state.localTag ? result(0, 'commit') : result(128)
    }
    if (command === 'git' && args[0] === 'tag') {
      events.push({ mutation: false, name: 'local-tag', args })
      state.localTag = true
      return result()
    }
    if (command === 'git' && args[0] === 'rev-parse') {
      return result(0, commit)
    }
    if (command === 'git' && args[0] === 'push') {
      if (args.includes('github')) {
        events.push({
          mutation: true,
          name: 'github-push',
          args,
        })
        state.githubTag = commit
      } else {
        events.push({
          mutation: true,
          name: 'htree-push',
          args,
        })
        state.htreeTag = commit
      }
      return result()
    }
    if (command === 'gh' && args[0] === 'run' && args[1] === 'list') {
      workflowListCount += 1
      if (
        workflowAppearsOnList > 0
        && workflowListCount >= workflowAppearsOnList
        && state.workflow === 'none'
      ) {
        state.workflow = 'queued'
      }
      if (driftBeforeWorkflowList) {
        state[driftBeforeWorkflowList === 'origin' ? 'htreeTag' : 'githubTag'] = ''
      }
      const rows = []
      if (conflictingCid) {
        rows.push({
          ...workflowRow('queued'),
          displayTitle: releaseWorkflowRunTitle({
            tag,
            commit,
            cid: conflictingCid,
          }),
        })
      }
      if (state.workflow !== 'none') {
        rows.push(workflowRow())
        if (duplicateExactRuns) {
          rows.push({ ...workflowRow(), databaseId: 416 })
        }
      }
      return result(0, JSON.stringify(rows))
    }
    if (
      command === 'gh'
      && args[0] === 'workflow'
      && args[1] === 'run'
    ) {
      events.push({
        mutation: true,
        name: 'workflow-dispatch',
        args,
      })
      state.workflow = 'queued'
      return result()
    }
    if (command === 'gh' && args[0] === 'run' && args[1] === 'watch') {
      events.push({ mutation: false, name: 'workflow-watch', args })
      state.workflow = 'success'
      return result()
    }
    if (command === 'gh' && args[0] === 'run' && args[1] === 'view') {
      return result(0, JSON.stringify(workflowRow()))
    }
    throw new Error(`unexpected fake command: ${name}`)
  }
  return { events, runCommand, state }
}

function mutationNames(events) {
  return events.filter((event) => event.mutation).map((event) => event.name)
}

test('exact ref publication gates every external phase and waits for exact CI', () => {
  const fake = fakePublication()
  const validateGate = successfulGate(fake.events)
  const published = publishReleaseRefs(options(), {
    runCommand: fake.runCommand,
    sleep: () => {},
    validateGate,
  })

  assert.deepEqual(published, {
    cid,
    commit,
    repository,
    runId: 415,
    status: 'passed',
    tag,
    tree,
  })
  assert.deepEqual(mutationNames(fake.events), [
    'github-push',
    'htree-push',
    'workflow-dispatch',
  ])
  assert.deepEqual(
    fake.events.filter((event) => event.name === 'gate')
      .map((event) => event.requireTag),
    [false, true, true, true],
  )
  const localTag = fake.events.find((event) => event.name === 'local-tag')
  assert.deepEqual(localTag.args, [
    'tag',
    '--no-sign',
    '--no-annotate',
    tag,
    commit,
  ])
  const github = fake.events.find((event) => event.name === 'github-push')
  assert.deepEqual(github.args, [
    'push',
    '--no-follow-tags',
    'github',
    `${commit}:refs/tags/${tag}`,
  ])
  const htree = fake.events.find((event) => event.name === 'htree-push')
  assert.deepEqual(htree.args, [
    'push',
    '--no-follow-tags',
    'origin',
    `${commit}:refs/tags/${tag}`,
  ])
  const dispatch = fake.events.find(
    (event) => event.name === 'workflow-dispatch',
  )
  assert.deepEqual(dispatch.args, [
    'workflow',
    'run',
    'release.yml',
    '--repo',
    repository,
    '--ref',
    tag,
    '-f',
    `tag=${tag}`,
    '-f',
    `locally_attested_commit=${commit}`,
    '-f',
    `locally_gated_release_cid=${cid}`,
  ])
})

test('exact successful retry performs no external mutation or duplicate dispatch', () => {
  const fake = fakePublication({
    githubMaster: commit,
    githubTag: commit,
    htreeTag: commit,
    localTag: true,
    workflow: 'success',
  })
  const validateGate = successfulGate(fake.events)
  publishReleaseRefs(options(), {
    runCommand: fake.runCommand,
    sleep: () => {},
    validateGate,
  })

  assert.deepEqual(mutationNames(fake.events), [])
  assert.deepEqual(
    fake.events.filter((event) => event.name === 'gate')
      .map((event) => event.requireTag),
    [false],
  )
})

test('bad immutable draft stops before tag or external mutation', () => {
  const fake = fakePublication({ failDraft: true })
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: successfulGate(fake.events),
    }),
    /draft mismatch/i,
  )
  assert.equal(
    fake.events.some((event) => event.name === 'local-tag'),
    false,
  )
  assert.deepEqual(mutationNames(fake.events), [])
})

test('initial mutation-gate rejection stops before any command or mutation', () => {
  const fake = fakePublication()
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: () => {
        throw new Error('exact staged source is invalid')
      },
    }),
    /exact staged source is invalid/i,
  )
  assert.deepEqual(fake.events, [])
})

test('non-root or malformed draft CID is rejected before any command', () => {
  for (const malformed of [
    'releases/nostr-vpn/v4.1.5',
    `${cid}/release.json`,
    'nhash1containsb',
  ]) {
    const fake = fakePublication()
    assert.throws(
      () => publishReleaseRefs(
        { ...options(), cid: malformed },
        {
          runCommand: fake.runCommand,
          sleep: () => {},
          validateGate: successfulGate(fake.events),
        },
      ),
      /exact root nhash CID/i,
    )
    assert.deepEqual(fake.events, [])
  }
})

test('conflicting release tags on either remote stop before any mutation', () => {
  for (const key of ['githubTag', 'htreeTag']) {
    const fake = fakePublication({ [key]: previous })
    assert.throws(
      () => publishReleaseRefs(options(), {
        runCommand: fake.runCommand,
        sleep: () => {},
        validateGate: successfulGate(fake.events),
      }),
      /tag .* conflicts/i,
    )
    assert.equal(fake.events.some((event) => event.name === 'local-tag'), false)
    assert.deepEqual(mutationNames(fake.events), [])
  }
})

test('different configured push URL stops before tag or external mutation', () => {
  for (const remote of ['github', 'origin']) {
    const fake = fakePublication({ mismatchedPushUrl: remote })
    assert.throws(
      () => publishReleaseRefs(options(), {
        runCommand: fake.runCommand,
        sleep: () => {},
        validateGate: successfulGate(fake.events),
      }),
      /push URL differs/i,
    )
    assert.equal(
      fake.events.some((event) => event.name === 'local-tag'),
      false,
    )
    assert.deepEqual(mutationNames(fake.events), [])
  }
})

test('multiple configured push URLs stop before external mutation', () => {
  for (const remote of ['github', 'origin']) {
    const fake = fakePublication({ multiplePushUrls: remote })
    assert.throws(
      () => publishReleaseRefs(options(), {
        runCommand: fake.runCommand,
        sleep: () => {},
        validateGate: successfulGate(fake.events),
      }),
      /exactly one configured push URL/i,
    )
    assert.deepEqual(mutationNames(fake.events), [])
  }
})

test('newer or divergent masters are preserved while only release tags publish', () => {
  const fake = fakePublication({ githubMaster: previous, htreeMaster: 'd'.repeat(40) })
  publishReleaseRefs(options(), {
    runCommand: fake.runCommand,
    sleep: () => {},
    validateGate: successfulGate(fake.events),
  })
  assert.equal(fake.state.githubMaster, previous)
  assert.equal(fake.state.htreeMaster, 'd'.repeat(40))
  assert.equal(fake.state.githubTag, commit)
  assert.equal(fake.state.htreeTag, commit)
  for (const event of fake.events.filter(({ name }) => name.endsWith('-push'))) {
    assert.deepEqual(event.args, [
      'push', '--no-follow-tags', event.name === 'github-push' ? 'github' : 'origin',
      `${commit}:refs/tags/${tag}`,
    ])
  }
})

test('tag conflicts arising during a gate replay stop the next push', () => {
  for (const key of ['githubTag', 'htreeTag']) {
    const fake = fakePublication()
    const gate = successfulGate(fake.events)
    assert.throws(() => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: (gateOptions) => {
        const result = gate(gateOptions)
        if (gateOptions.requireTag) fake.state[key] = previous
        return result
      },
    }), /tag .* conflicts/i)
    assert.deepEqual(mutationNames(fake.events), [])
  }
})

test('a rejected tag push stops publication without forcing or dispatching', () => {
  for (const remote of ['github', 'origin']) {
    const fake = fakePublication()
    assert.throws(() => publishReleaseRefs(options(), {
      runCommand: (command, args, commandOptions) => {
        if (command === 'git' && args[0] === 'push' && args.includes(remote)) {
          assert.deepEqual(args, ['push', '--no-follow-tags', remote, `${commit}:refs/tags/${tag}`])
          return { status: 1, stdout: '', stderr: 'tag already exists' }
        }
        return fake.runCommand(command, args, commandOptions)
      },
      sleep: () => {},
      validateGate: successfulGate(fake.events),
    }), /tag already exists/i)
    assert.deepEqual(mutationNames(fake.events), remote === 'github' ? [] : ['github-push'])
  }
})

test('gate failure after GitHub stops htree and workflow mutations', () => {
  const fake = fakePublication()
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: successfulGate(fake.events, { failAt: 3 }),
    }),
    /gate failure 3/,
  )
  assert.deepEqual(mutationNames(fake.events), ['github-push'])
})

test('different-CID workflow for exact tag and commit fails closed', () => {
  const fake = fakePublication({
    githubMaster: commit,
    githubTag: commit,
    htreeTag: commit,
    localTag: true,
    conflictingCid: 'nhash1acdefghjklmnpqrstuvwxyz023456780',
  })
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: successfulGate(fake.events),
    }),
    /different draft CID/i,
  )
  assert.deepEqual(mutationNames(fake.events), [])
})

test('workflow appearing after final gate is resumed without dispatch', () => {
  const fake = fakePublication({
    githubMaster: commit,
    githubTag: commit,
    htreeTag: commit,
    localTag: true,
    workflowAppearsOnList: 2,
  })
  publishReleaseRefs(options(), {
    runCommand: fake.runCommand,
    sleep: () => {},
    validateGate: successfulGate(fake.events),
  })
  assert.deepEqual(mutationNames(fake.events), [])
  assert.equal(
    fake.events.some((event) => event.name === 'workflow-watch'),
    true,
  )
})

test('duplicate identical workflow runs are rejected', () => {
  const fake = fakePublication({
    githubMaster: commit,
    githubTag: commit,
    htreeTag: commit,
    localTag: true,
    workflow: 'queued',
    duplicateExactRuns: true,
  })
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: successfulGate(fake.events),
    }),
    /multiple identical/i,
  )
  assert.deepEqual(mutationNames(fake.events), [])
})

test('tag loss before dispatch or after workflow resume fails closed on either remote', () => {
  for (const remote of ['github', 'origin']) {
    for (const workflow of ['none', 'success']) {
      const fake = fakePublication({
        githubTag: commit,
        htreeTag: commit,
        localTag: true,
        workflow,
        driftBeforeWorkflowList: remote,
      })
      assert.throws(() => publishReleaseRefs(options(), {
        runCommand: fake.runCommand,
        sleep: () => {},
        validateGate: successfulGate(fake.events),
      }), /release refs (do not all resolve|changed)/i)
      assert.deepEqual(mutationNames(fake.events), [])
    }
  }
})

test('same exact workflow inputs with a different event head fail closed', () => {
  const fake = fakePublication({
    githubMaster: commit,
    githubTag: commit,
    htreeTag: commit,
    localTag: true,
    workflow: 'success',
    workflowHeadSha: previous,
  })
  assert.throws(
    () => publishReleaseRefs(options(), {
      runCommand: fake.runCommand,
      sleep: () => {},
      validateGate: successfulGate(fake.events),
    }),
    /different Git head SHA/i,
  )
  assert.deepEqual(mutationNames(fake.events), [])
})

test('workflow title binds the exact dispatch inputs used for retry recovery', () => {
  const workflow = readFileSync(
    join(process.cwd(), '.github', 'workflows', 'release.yml'),
    'utf8',
  )
  assert.match(
    workflow,
    /run-name:\s*>-\s+Release \$\{\{ inputs\.tag \}\} @ \$\{\{ inputs\.locally_attested_commit \}\} from \$\{\{ inputs\.locally_gated_release_cid \}\}/,
  )
})
