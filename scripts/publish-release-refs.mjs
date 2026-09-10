#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdtempSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { githubRepositoryFromRemote } from './github-release-publication.mjs'
import { normalizeTag } from './local-release-lib.mjs'
import { validateReleaseMutationGate } from './release-mutation-gate.mjs'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const canonicalHtreeRemote = 'htree://self/nostr-vpn'
const workflowName = 'release.yml'

function fail(message) {
  throw new Error(`Release ref publication rejected: ${message}`)
}

function defaultCommand(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: 'utf8',
    env: options.env ?? process.env,
    stdio: options.stdio ?? 'pipe',
  })
}

function commandResult(runCommand, command, args, options = {}) {
  const result = runCommand(command, args, options)
  if (result?.error) {
    fail(result.error.message)
  }
  return {
    status: Number.isInteger(result?.status) ? result.status : 1,
    stderr: String(result?.stderr ?? '').trim(),
    stdout: String(result?.stdout ?? '').trim(),
  }
}

function run(runCommand, command, args, options = {}) {
  const result = commandResult(runCommand, command, args, options)
  if (result.status !== 0) {
    fail(
      result.stderr
      || `${command} ${args.join(' ')} exited ${result.status}`,
    )
  }
  return result.stdout
}

function exactJson(text, label) {
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    fail(`${label} is invalid JSON: ${error.message}`)
  }
  return value
}

function exactRemoteRef(runCommand, remote, reference) {
  const result = commandResult(
    runCommand,
    'git',
    ['ls-remote', '--exit-code', remote, reference],
    { cwd: repoRoot },
  )
  if (result.status === 2 && !result.stdout) {
    return ''
  }
  if (result.status !== 0) {
    fail(
      result.stderr
      || `could not inspect ${remote} ${reference}`,
    )
  }
  const rows = result.stdout.split('\n').filter(Boolean)
  if (rows.length !== 1) {
    fail(`${remote} ${reference} did not resolve exactly once`)
  }
  const [sha, returnedReference, ...extra] = rows[0].split(/\s+/)
  if (
    extra.length
    || returnedReference !== reference
    || !/^[0-9a-f]{40}$/.test(sha)
  ) {
    fail(`${remote} ${reference} returned an invalid exact ref`)
  }
  return sha
}

function requireAncestor(runCommand, ancestor, commit, label) {
  if (!ancestor || ancestor === commit) {
    return
  }
  const result = commandResult(
    runCommand,
    'git',
    ['merge-base', '--is-ancestor', ancestor, commit],
    { cwd: repoRoot },
  )
  if (result.status === 1) {
    fail(`${label} is not an ancestor of the staged commit`)
  }
  if (result.status !== 0) {
    fail(
      result.stderr
      || `could not prove ${label} is an ancestor of the staged commit`,
    )
  }
}

function inspectRemoteRefs(runCommand, tag, commit) {
  const githubMaster = exactRemoteRef(
    runCommand,
    'github',
    'refs/heads/master',
  )
  const githubTag = exactRemoteRef(
    runCommand,
    'github',
    `refs/tags/${tag}`,
  )
  const htreeMaster = exactRemoteRef(
    runCommand,
    'origin',
    'refs/heads/master',
  )
  requireAncestor(runCommand, githubMaster, commit, 'GitHub master')
  requireAncestor(runCommand, htreeMaster, commit, 'htree master')
  if (githubTag && githubTag !== commit) {
    fail(`GitHub tag ${tag} conflicts with the staged commit`)
  }
  return { githubMaster, githubTag, htreeMaster }
}

function assertPublishedRefsExact(refs, commit) {
  if (
    refs.githubMaster !== commit
    || refs.githubTag !== commit
    || refs.htreeMaster !== commit
  ) {
    fail('published release refs do not all resolve to the staged commit')
  }
}

function exactConfiguredRemoteUrl(runCommand, name, { push = false } = {}) {
  const args = ['remote', 'get-url']
  if (push) {
    args.push('--push')
  }
  args.push('--all', name)
  const urls = run(
    runCommand,
    'git',
    args,
    { cwd: repoRoot },
  ).split('\n').filter(Boolean)
  if (urls.length !== 1) {
    fail(`${name} must have exactly one configured ${push ? 'push' : 'fetch'} URL`)
  }
  return urls[0]
}

function assertRemotePins(runCommand) {
  const githubRemote = exactConfiguredRemoteUrl(runCommand, 'github')
  const githubPushRemote = exactConfiguredRemoteUrl(
    runCommand,
    'github',
    { push: true },
  )
  if (githubPushRemote !== githubRemote) {
    fail('github push URL differs from its validated fetch URL')
  }
  const repository = githubRepositoryFromRemote(githubRemote)
  const origin = exactConfiguredRemoteUrl(runCommand, 'origin')
  const originPush = exactConfiguredRemoteUrl(
    runCommand,
    'origin',
    { push: true },
  )
  if (originPush !== origin) {
    fail('origin push URL differs from its validated fetch URL')
  }
  if (origin !== canonicalHtreeRemote) {
    fail(`origin must remain ${canonicalHtreeRemote}`)
  }
  run(runCommand, 'gh', ['auth', 'status'], { cwd: repoRoot })
  const viewed = run(
    runCommand,
    'gh',
    [
      'repo',
      'view',
      repository,
      '--json',
      'nameWithOwner',
      '--jq',
      '.nameWithOwner',
    ],
    { cwd: repoRoot },
  )
  if (viewed !== repository) {
    fail('GitHub CLI repository differs from the exact github remote')
  }
  return repository
}

function assertLightweightTag(runCommand, tag, commit) {
  const type = commandResult(
    runCommand,
    'git',
    ['cat-file', '-t', `refs/tags/${tag}`],
    { cwd: repoRoot },
  )
  if (type.status !== 0) {
    fail(`local release tag ${tag} is missing`)
  }
  if (type.stdout !== 'commit') {
    fail(`local release tag ${tag} must be lightweight`)
  }
  const taggedCommit = run(
    runCommand,
    'git',
    ['rev-parse', `${tag}^{commit}`],
    { cwd: repoRoot },
  )
  if (taggedCommit !== commit) {
    fail(`local release tag ${tag} differs from the staged commit`)
  }
}

function ensureLightweightTag(runCommand, tag, commit) {
  const existing = commandResult(
    runCommand,
    'git',
    ['cat-file', '-t', `refs/tags/${tag}`],
    { cwd: repoRoot },
  )
  if (existing.status === 0) {
    assertLightweightTag(runCommand, tag, commit)
    return
  }
  run(
    runCommand,
    'git',
    ['tag', '--no-sign', '--no-annotate', tag, commit],
    { cwd: repoRoot },
  )
  assertLightweightTag(runCommand, tag, commit)
}

function verifyDraftCid({
  runCommand,
  tag,
  commit,
  tree,
  cid,
}) {
  const temporary = mkdtempSync(
    join(tmpdir(), 'nvpn-release-draft-'),
  )
  chmodSync(temporary, 0o700)
  const downloaded = join(temporary, 'draft')
  try {
    run(
      runCommand,
      'htree',
      ['get', cid, '--output', downloaded],
      { cwd: repoRoot },
    )
    run(
      runCommand,
      process.execPath,
      [
        join(repoRoot, 'scripts', 'verify-release-publication-bundle.mjs'),
        '--stage-dir',
        downloaded,
        '--tag',
        tag,
        '--commit',
        commit,
        '--tree',
        tree,
        '--require-draft',
      ],
      { cwd: repoRoot },
    )
  } finally {
    rmSync(temporary, { force: true, recursive: true })
  }
}

export function releaseWorkflowRunTitle({ tag, commit, cid }) {
  return `Release ${tag} @ ${commit} from ${cid}`
}

function listedWorkflowRuns(runCommand, repository, tag) {
  const text = run(
    runCommand,
    'gh',
    [
      'run',
      'list',
      '--repo',
      repository,
      '--workflow',
      workflowName,
      '--event',
      'workflow_dispatch',
      '--branch',
      tag,
      '--limit',
      '100',
      '--json',
      'databaseId,displayTitle,event,headSha,status,conclusion',
    ],
    { cwd: repoRoot },
  )
  const rows = exactJson(text || '[]', 'GitHub workflow run list')
  if (!Array.isArray(rows)) {
    fail('GitHub workflow run list must be an array')
  }
  return rows
}

function exactWorkflowRun({
  runCommand,
  repository,
  tag,
  commit,
  cid,
}) {
  const title = releaseWorkflowRunTitle({ tag, commit, cid })
  const prefix = `Release ${tag} @ ${commit} from `
  const rows = listedWorkflowRuns(runCommand, repository, tag)
  const wrongHead = rows.find(
    (row) =>
      row?.event === 'workflow_dispatch'
      && row?.displayTitle === title
      && row?.headSha !== commit,
  )
  if (wrongHead) {
    fail('the exact-input workflow run has a different Git head SHA')
  }
  const conflicting = rows.find(
    (row) =>
      row?.event === 'workflow_dispatch'
      && row?.headSha === commit
      && typeof row?.displayTitle === 'string'
      && row.displayTitle.startsWith(prefix)
      && row.displayTitle !== title,
  )
  if (conflicting) {
    fail('an exact-tag workflow run already binds a different draft CID')
  }
  const exact = rows.filter(
    (row) =>
      row?.event === 'workflow_dispatch'
      && row?.headSha === commit
      && row?.displayTitle === title,
  )
  if (exact.length > 1) {
    fail('multiple identical exact-input workflow runs exist')
  }
  const succeeded = exact.find(
    (row) => row.status === 'completed' && row.conclusion === 'success',
  )
  if (succeeded) {
    return succeeded
  }
  const active = exact.find((row) =>
    ['in_progress', 'pending', 'queued', 'requested', 'waiting']
      .includes(row.status),
  )
  if (active) {
    return active
  }
  if (exact.length) {
    fail('the exact release workflow run already completed unsuccessfully')
  }
  return null
}

function verifyWorkflowRun({
  runCommand,
  repository,
  runId,
  tag,
  commit,
  cid,
}) {
  const viewed = exactJson(
    run(
      runCommand,
      'gh',
      [
        'run',
        'view',
        String(runId),
        '--repo',
        repository,
        '--json',
        'databaseId,displayTitle,event,headSha,status,conclusion',
      ],
      { cwd: repoRoot },
    ),
    'GitHub workflow run',
  )
  if (
    viewed?.databaseId !== runId
    || viewed?.displayTitle
      !== releaseWorkflowRunTitle({ tag, commit, cid })
    || viewed?.event !== 'workflow_dispatch'
    || viewed?.headSha !== commit
    || viewed?.status !== 'completed'
    || viewed?.conclusion !== 'success'
  ) {
    fail('GitHub workflow did not complete successfully with exact inputs')
  }
  return viewed
}

function waitForExactWorkflowRun({
  runCommand,
  sleep,
  repository,
  tag,
  commit,
  cid,
}) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const found = exactWorkflowRun({
      runCommand,
      repository,
      tag,
      commit,
      cid,
    })
    if (found) {
      return found
    }
    sleep(1_000)
  }
  fail('exact GitHub workflow run did not appear within 30 seconds')
}

function defaultSleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds)
}

export function publishReleaseRefs(options, dependencies = {}) {
  const runCommand = dependencies.runCommand ?? defaultCommand
  const validateGate =
    dependencies.validateGate ?? validateReleaseMutationGate
  const sleep = dependencies.sleep ?? defaultSleep
  const tag = normalizeTag(options.tag)
  const cid = String(options.cid ?? '').trim()
  if (!/^nhash1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(cid)) {
    fail('immutable draft CID must be one exact root nhash CID')
  }
  if (!options.stageDir || !isAbsolute(options.stageDir)) {
    fail('stage directory requires an exact absolute path')
  }
  const gateOptions = {
    stageDir: options.stageDir,
    expectedTag: tag,
  }
  const initial = validateGate({
    ...gateOptions,
    requireTag: false,
  })
  const { appGitSha: commit, appGitTree: tree } = initial
  if (
    !/^[0-9a-f]{40}$/.test(commit)
    || !/^[0-9a-f]{40}$/.test(tree)
    || initial.tag !== tag
  ) {
    fail('canonical mutation gate returned an invalid exact source')
  }
  verifyDraftCid({
    runCommand,
    tag,
    commit,
    tree,
    cid,
  })
  const repository = assertRemotePins(runCommand)
  let refs = inspectRemoteRefs(runCommand, tag, commit)
  ensureLightweightTag(runCommand, tag, commit)

  const replayGate = () => {
    assertLightweightTag(runCommand, tag, commit)
    return validateGate({
      ...gateOptions,
      requireTag: true,
    })
  }

  if (refs.githubMaster !== commit || refs.githubTag !== commit) {
    replayGate()
    assertRemotePins(runCommand)
    inspectRemoteRefs(runCommand, tag, commit)
    run(
      runCommand,
      'git',
      [
        'push',
        '--atomic',
        '--no-follow-tags',
        'github',
        `${commit}:refs/heads/master`,
        `${commit}:refs/tags/${tag}`,
      ],
      { cwd: repoRoot },
    )
  }
  refs = inspectRemoteRefs(runCommand, tag, commit)
  if (refs.githubMaster !== commit || refs.githubTag !== commit) {
    fail('GitHub refs differ after exact publication')
  }

  if (refs.htreeMaster !== commit) {
    replayGate()
    assertRemotePins(runCommand)
    inspectRemoteRefs(runCommand, tag, commit)
    run(
      runCommand,
      'git',
      [
        'push',
        '--no-follow-tags',
        'origin',
        `${commit}:refs/heads/master`,
      ],
      { cwd: repoRoot },
    )
  }
  refs = inspectRemoteRefs(runCommand, tag, commit)
  assertPublishedRefsExact(refs, commit)

  let workflow = exactWorkflowRun({
    runCommand,
    repository,
    tag,
    commit,
    cid,
  })
  if (!workflow) {
    replayGate()
    assertRemotePins(runCommand)
    refs = inspectRemoteRefs(runCommand, tag, commit)
    if (
      refs.githubMaster !== commit
      || refs.githubTag !== commit
      || refs.htreeMaster !== commit
    ) {
      fail('release refs changed before workflow dispatch')
    }
    workflow = exactWorkflowRun({
      runCommand,
      repository,
      tag,
      commit,
      cid,
    })
    if (!workflow) {
      run(
        runCommand,
        'gh',
        [
          'workflow',
          'run',
          workflowName,
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
        ],
        { cwd: repoRoot },
      )
      workflow = waitForExactWorkflowRun({
        runCommand,
        sleep,
        repository,
        tag,
        commit,
        cid,
      })
    }
  }
  if (!(workflow.status === 'completed' && workflow.conclusion === 'success')) {
    const watched = commandResult(
      runCommand,
      'gh',
      [
        'run',
        'watch',
        String(workflow.databaseId),
        '--repo',
        repository,
        '--exit-status',
        '--interval',
        '30',
      ],
      // Long CI runs must not fill spawnSync's captured-output buffer.
      { cwd: repoRoot, stdio: 'inherit' },
    )
    if (watched.status !== 0) {
      fail(
        watched.stderr
        || 'exact GitHub workflow run did not succeed',
      )
    }
  }
  const verified = verifyWorkflowRun({
    runCommand,
    repository,
    runId: workflow.databaseId,
    tag,
    commit,
    cid,
  })
  assertPublishedRefsExact(
    inspectRemoteRefs(runCommand, tag, commit),
    commit,
  )
  return {
    cid,
    commit,
    repository,
    runId: verified.databaseId,
    status: 'passed',
    tag,
    tree,
  }
}

function parseArgs(argv) {
  const values = {
    stageDir: process.env.NVPN_RELEASE_STAGE_DIR || '',
    tag: process.env.NVPN_RELEASE_TAG || '',
    cid: process.env.NVPN_RELEASE_DRAFT_CID || '',
  }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    switch (argument) {
      case '--stage-dir':
        values.stageDir = argv[++index] ?? ''
        break
      case '--tag':
        values.tag = argv[++index] ?? ''
        break
      case '--draft-cid':
        values.cid = argv[++index] ?? ''
        break
      case '--help':
      case '-h':
        console.log(`Usage: node scripts/publish-release-refs.mjs [options]

Publishes the exact staged release refs without force, dispatches the
exact immutable-draft workflow, and waits for that workflow to succeed.

Options:
  --stage-dir DIR
  --tag TAG
  --draft-cid CID`)
        process.exit(0)
        break
      default:
        fail(`unknown argument ${argument}`)
    }
  }
  return values
}

function main() {
  console.log(JSON.stringify(publishReleaseRefs(parseArgs(
    process.argv.slice(2),
  ))))
}

if (
  process.argv[1]
  && pathToFileURL(process.argv[1]).href === import.meta.url
) {
  try {
    main()
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}
