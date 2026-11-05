#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  normalizeTag,
  resolveReleaseProductRoot,
  validatePromotableReleaseManifest,
  validateStagedReleaseTree,
} from './local-release-lib.mjs'

const repoRoot = resolveReleaseProductRoot(resolve(dirname(fileURLToPath(import.meta.url)), '..'))

function fail(message) {
  throw new Error(`Release mutation gate rejected: ${message}`)
}

function runGit(commandArgs) {
  const result = spawnSync('git', commandArgs, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  if (result.status !== 0) {
    fail(result.stderr.trim() || `git ${commandArgs.join(' ')} failed`)
  }
  return result.stdout.trim()
}

function exactJson(path, label) {
  if (!isAbsolute(path)) {
    fail(`${label} path must be absolute`)
  }
  const metadata = lstatSync(path)
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    fail(`${label} must be a regular non-symlink file`)
  }
  try {
    const value = JSON.parse(readFileSync(realpathSync(path), 'utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      fail(`${label} must be a JSON object`)
    }
    return value
  } catch (error) {
    fail(`${label} is invalid JSON: ${error.message}`)
  }
}

export function assertRealStageDirectory(stageDir) {
  if (!isAbsolute(stageDir)) {
    fail('stage directory path must be absolute')
  }
  const metadata = lstatSync(stageDir)
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    fail('stage directory must be a real non-symlink directory')
  }
}

export function validateExactStageSource({
  stageDir,
  expectedTag = '',
  requireTag = false,
}) {
  assertRealStageDirectory(stageDir)
  const release = exactJson(join(stageDir, 'release.json'), 'staged release')
  validatePromotableReleaseManifest(release)
  validateStagedReleaseTree(stageDir, release)
  const tag = normalizeTag(expectedTag || release.tag)
  if (release.tag !== tag) {
    fail(`staged release tag ${release.tag} differs from ${tag}`)
  }
  const status = runGit([
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
  ])
  if (status) {
    fail('release checkout is dirty')
  }
  const head = runGit(['rev-parse', 'HEAD'])
  const tree = runGit(['rev-parse', 'HEAD^{tree}'])
  if (
    head !== release.commit
    || tree !== release.release_gate_attestation?.app_git_tree
  ) {
    fail('staged release source differs from the exact clean checkout')
  }
  const tagResult = spawnSync(
    'git',
    ['rev-parse', '-q', '--verify', `${tag}^{commit}`],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: 'pipe',
    },
  )
  if (
    (requireTag && tagResult.status !== 0)
    || (tagResult.status === 0 && tagResult.stdout.trim() !== head)
  ) {
    fail(`release tag ${tag} does not resolve to the exact staged commit`)
  }
  return { head, release, tag, tree }
}

export function validateReleaseMutationGate({
  stageDir,
  expectedTag = '',
  requireTag = false,
}) {
  if (!stageDir || !isAbsolute(stageDir)) {
    fail('stage directory requires an exact absolute path')
  }
  const exact = validateExactStageSource({
    stageDir,
    expectedTag,
    requireTag,
  })
  return {
    appGitSha: exact.head,
    appGitTree: exact.tree,
    status: 'passed',
    tag: exact.tag,
  }
}

function parseArgs(argv) {
  const values = {
    stageDir: process.env.NVPN_RELEASE_STAGE_DIR || '',
    expectedTag: process.env.NVPN_RELEASE_TAG || '',
    requireTag: false,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    switch (argument) {
      case '--stage-dir':
        values.stageDir = argv[++index] ?? ''
        break
      case '--tag':
        values.expectedTag = argv[++index] ?? ''
        break
      case '--require-tag':
        values.requireTag = true
        break
      case '--help':
      case '-h':
        console.log(`Usage: node scripts/release-mutation-gate.mjs [options]

Requires a clean exact staged source before any external release mutation.

Options:
  --stage-dir DIR
  --tag TAG
  --require-tag`)
        process.exit(0)
        break
      default:
        fail(`unknown argument ${argument}`)
    }
  }
  return values
}

function main() {
  const result = validateReleaseMutationGate(parseArgs(process.argv.slice(2)))
  console.log(JSON.stringify(result))
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
