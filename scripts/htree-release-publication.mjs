import { spawnSync } from 'node:child_process'

function run(command, commandArgs, { cwd, env } = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  if (result.status !== 0) {
    throw new Error(
      result.stderr.trim()
      || result.stdout.trim()
      || `${command} ${commandArgs.join(' ')} failed.`,
    )
  }
  return result.stdout.trim()
}

export function parseActiveHtreeIdentity(identities) {
  const lines = String(identities)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  const legacySelf = lines.filter((line) => line.endsWith('(self)'))
  const npub = legacySelf.length === 1
    ? legacySelf[0].match(/^(npub1[023456789acdefghjklmnpqrstuvwxyz]+)\s+\(self\)$/)?.[1]
    : legacySelf.length === 0
      ? lines[0]?.match(/^(npub1[023456789acdefghjklmnpqrstuvwxyz]+)$/)?.[1]
      : ''
  if (!npub) {
    throw new Error('htree must expose exactly one valid active identity.')
  }
  return npub
}

export function preflightHtreeRelease({ repoRoot, env, dryRun = false }) {
  if (dryRun) {
    return { identity: 'dry-run', verified: true }
  }
  const origin = run(
    'git',
    ['remote', 'get-url', 'origin'],
    { cwd: repoRoot, env },
  )
  if (!/^htree:\/\/self\/[^/\s]+$/.test(origin)) {
    throw new Error(
      'Release htree origin must use the active private identity via htree://self.',
    )
  }
  const identities = run('htree', ['user'], {
    cwd: repoRoot,
    env,
  })
  const npub = parseActiveHtreeIdentity(identities)
  const expected = String(env.NVPN_HTREE_PUBLISHER_NPUB || '').trim()
  if (!expected) {
    throw new Error(
      'NVPN_HTREE_PUBLISHER_NPUB must pin the expected htree release identity.',
    )
  }
  if (expected !== npub) {
    throw new Error('htree active identity differs from NVPN_HTREE_PUBLISHER_NPUB.')
  }
  run('htree', ['status'], { cwd: repoRoot, env })
  run('htree', ['release', 'publish', '--help'], {
    cwd: repoRoot,
    env,
  })
  return { identity: npub, verified: true }
}
