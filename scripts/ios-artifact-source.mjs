import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { requireReceiptSource } from './release-artifact-provenance-lib.mjs'

// Export and upload must validate against the same original artifact source.
// The caller's publication gate continues to bind the current release commit.
export function withIosArtifactSource({ repoRoot, receipt, commit, tree, env }, action) {
  const proof = requireReceiptSource(receipt, {
    commit, tree, candidateRoot: repoRoot, platform: 'ios',
    label: 'Frozen iOS artifact source',
  })
  const artifactEnv = {
    ...env,
    NVPN_RELEASE_GATE_LOG_DIR: env.NVPN_RELEASE_GATE_LOG_DIR
      || join(repoRoot, 'artifacts', 'release-gate-logs', `local-release-${env.NVPN_RELEASE_TAG}`),
    NVPN_RELEASE_JOIN_RESULT_DIR: env.NVPN_RELEASE_JOIN_RESULT_DIR
      || join(repoRoot, 'artifacts', 'mobile-release-join'),
    NVPN_BUILD_GIT_SHA: receipt.appGitSha,
    NVPN_IOS_RELEASE_SOURCE_ROOT: repoRoot,
  }
  if (!proof) return action({ cwd: repoRoot, env: artifactEnv })

  const temporaryRoot = mkdtempSync(join(tmpdir(), 'nvpn-ios-artifact-source-'))
  const sourceRoot = join(temporaryRoot, 'source')
  const git = (args) => {
    const result = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8' })
    if (result.status !== 0) throw new Error(result.stderr || 'iOS artifact worktree operation failed.')
  }
  let worktreeAdded = false
  try {
    git(['worktree', 'add', '--detach', sourceRoot, receipt.appGitSha])
    worktreeAdded = true
    for (const name of ['dist', 'artifacts']) {
      const externalRoot = join(repoRoot, name)
      if (!existsSync(externalRoot)) continue
      const linkRoot = join(sourceRoot, name)
      mkdirSync(linkRoot)
      for (const entry of readdirSync(externalRoot)) {
        symlinkSync(join(externalRoot, entry), join(linkRoot, entry))
      }
    }
    return action({
      cwd: sourceRoot,
      env: { ...artifactEnv, NVPN_IOS_RELEASE_SOURCE_ROOT: sourceRoot },
    })
  } finally {
    for (const name of ['dist', 'artifacts']) {
      rmSync(join(sourceRoot, name), { recursive: true, force: true })
    }
    if (worktreeAdded) git(['worktree', 'remove', sourceRoot])
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const env = process.env
  const repoRoot = process.cwd()
  if (process.argv[2] !== 'build-mobile-join' || env.NVPN_RELEASE_JOIN_BUILD_ONLY !== '1') {
    throw new Error('Expected a build-only mobile join invocation.')
  }
  const receipt = JSON.parse(readFileSync(env.NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT, 'utf8'))
  withIosArtifactSource({
    repoRoot, receipt, commit: env.NVPN_EXPECTED_APP_GIT_SHA,
    tree: env.NVPN_EXPECTED_APP_GIT_TREE, env,
  }, ({ cwd, env: scoped }) => {
    const result = spawnSync(join(repoRoot, 'scripts/mobile-release-join-e2e.sh'), ['--prepare-ios-variant'], {
      cwd, stdio: 'inherit', env: {
        ...scoped, NVPN_EXPECTED_APP_GIT_SHA: receipt.appGitSha,
        NVPN_EXPECTED_APP_GIT_TREE: receipt.appGitTree,
      },
    })
    if (result.status !== 0) throw new Error('Mobile join artifact preparation failed.')
  })
}
