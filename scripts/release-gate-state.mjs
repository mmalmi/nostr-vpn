import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, readlinkSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { homedir } from 'node:os'
import { pathToFileURL } from 'node:url'

const hash = value => createHash('sha256').update(value).digest('hex')
const read = path => JSON.parse(readFileSync(path, 'utf8'))
function write(path, value) {
  const temporary = `${path}.${process.pid}.tmp`
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  renameSync(temporary, path)
}
function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim()
}
function source(root) {
  const untracked = git(root, 'ls-files', '--others', '--exclude-standard', '-z')
    .split('\0').filter(Boolean).map(path => {
      const full = join(root, path)
      return [path, hash(lstatSync(full).isSymbolicLink() ? readlinkSync(full) : readFileSync(full))]
    })
  return {
    untracked: hash(JSON.stringify(untracked)),
    commit: git(root, 'rev-parse', 'HEAD'),
    tree: git(root, 'rev-parse', 'HEAD^{tree}'),
    changes: hash(git(root, 'diff', '--binary', 'HEAD')),
  }
}
function environment() {
  // Store a digest only: release environments contain credentials and device IDs.
  const ignored = /^(?:_|SHLVL|PWD|OLDPWD|TMPDIR|TERM|TERM_SESSION_ID|NVPN_RELEASE_GATE_LOG_DIR|RELEASE_GATE_STATE_DIR)$/
  return hash(JSON.stringify(Object.entries(process.env)
    .filter(([key]) => !ignored.test(key)).sort(([a], [b]) => a.localeCompare(b))))
}
function toolchain() {
  return ['node', 'rustc', 'cargo', 'java', 'gradle'].map(tool => {
    const result = spawnSync(tool, [tool === 'java' ? '-version' : '--version'], {
      encoding: 'utf8', timeout: 15_000, killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return [tool, result.status === 0 ? `${result.stdout}${result.stderr}` : 'unavailable']
  })
}
function fileHash(path) { return existsSync(path) ? hash(readFileSync(path)) : null }
function configuration(root) {
  const cargo = process.env.CARGO_HOME || join(homedir(), '.cargo')
  const gradle = process.env.GRADLE_USER_HOME || join(homedir(), '.gradle')
  return [join(root, '.cargo/config.toml'), join(root, '.cargo/config'),
    join(cargo, 'config.toml'), join(cargo, 'config'), join(gradle, 'gradle.properties')].map(fileHash)
}
function binding(root) {
  const fips = process.env.NVPN_FIPS_REPO_PATH
  return {
    app: source(root),
    fips: fips ? source(fips) : null,
    config: configuration(root),
    environment: environment(),
  }
}
function phasePath(dir, label) { return join(dir, `phase-${hash(label)}.json`) }
function live(pid) {
  try { process.kill(pid, 0); return true } catch (e) { return e.code !== 'ESRCH' }
}

export function initialize(root, pid) {
  root = resolve(root)
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error('Invalid gate owner PID.')
  const dir = join(root, 'artifacts', 'release-gate-state')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const lock = join(dir, 'owner')
  try { mkdirSync(lock) } catch (error) {
    if (error.code !== 'EEXIST') throw error
    const ownerPath = join(lock, 'pid.json')
    if (!existsSync(ownerPath) || live(read(ownerPath).pid)) {
      throw new Error('A release gate already owns this checkout; do not start another attempt.')
    }
    throw new Error('Previous gate owner exited without cleanup. Record the corrected condition with release-gate-state.mjs retry before restarting.')
  }
  write(join(lock, 'pid.json'), { pid })
  try {
    const inputs = binding(root)
    const tools = hash(JSON.stringify(toolchain()))
    const key = hash(JSON.stringify({ inputs, tools }))
    const path = join(dir, 'run.json')
    const previous = existsSync(path) ? read(path) : null
    const failures = previous?.key === key
      ? (previous.failures ?? 0) + (previous.status === 'running' ? 1 : 0) : 0
    if (failures >= 2) {
      throw new Error('Two release attempts failed with unchanged inputs. Diagnose the failing phase; after fixing an external condition, record it with: node scripts/release-gate-state.mjs retry "what changed"')
    }
    write(path, {
      schema: 1, key, candidate: inputs.app.commit, tree: inputs.app.tree,
      root, inputs, tools,
      failures, recovery: previous?.recovery, status: 'running', startedAt: Date.now(), owner: pid,
    })
    return dir
  } catch (error) {
    rmSync(lock, { recursive: true })
    throw error
  }
}

export function phase(dir, label, status, exitStatus = 0) {
  const path = phasePath(dir, label)
  const prior = existsSync(path) ? read(path) : {}
  const run = read(join(dir, 'run.json'))
  write(path, {
    label, candidate: run.candidate, runStartedAt: run.startedAt,
    startedAt: status === 'running' || prior.runStartedAt !== run.startedAt
      ? Date.now() : prior.startedAt ?? Date.now(),
    finishedAt: status === 'running' ? null : Date.now(), status, exitStatus,
  })
}

export function checkpoint(dir, label, operation) {
  // Only checks with no required output or device state may be resumed here.
  const allowed = ['Source quality', 'Rust regression checks', 'Android static checks']
  if (!allowed.includes(label)) throw new Error(`Phase is not resumable: ${label}`)
  const run = read(join(dir, 'run.json'))
  const inputs = binding(run.root)
  // Runtime exports include random Cargo-wrapper and generated receipt paths.
  // Their policy is determined by the frozen source and initial environment.
  inputs.environment = run.inputs.environment
  if (inputs.app.commit !== run.candidate || inputs.app.tree !== run.tree) {
    throw new Error('Release candidate changed during the gate. Start a new candidate explicitly.')
  }
  const key = hash(JSON.stringify({ inputs, tools: run.tools }))
  const path = join(dir, `check-${hash(label)}.json`)
  if (operation === 'begin') {
    if (existsSync(path)) {
      const saved = read(path)
      if (saved.key === key && saved.status === 'passed'
        && saved.finishedAt <= Date.now()
        && Date.now() - saved.finishedAt < 24 * 60 * 60 * 1000) {
        phase(dir, label, 'reused')
        return 'reuse'
      }
    }
    write(path, { key, status: 'running' })
    phase(dir, label, 'running')
    return 'run'
  }
  const saved = read(path)
  if (saved.key !== key || saved.status !== 'running') {
    throw new Error('Check inputs changed while validation was running; refusing its checkpoint.')
  }
  write(path, { key, status: 'passed', finishedAt: Date.now() })
  phase(dir, label, 'passed')
  return 'passed'
}

export function finish(dir, exitStatus) {
  const path = join(dir, 'run.json')
  const run = read(path)
  for (const entry of readdirSync(dir).filter(name => name.startsWith('phase-'))) {
    const value = read(join(dir, entry))
    if (value.runStartedAt === run.startedAt && value.status === 'running') {
      phase(dir, value.label, 'interrupted', exitStatus || 1)
    }
  }
  const candidateChanged = JSON.stringify(source(run.root)) !== JSON.stringify(run.inputs.app)
    || (run.inputs.fips && JSON.stringify(source(process.env.NVPN_FIPS_REPO_PATH)) !== JSON.stringify(run.inputs.fips))
    || JSON.stringify(configuration(run.root)) !== JSON.stringify(run.inputs.config)
  if (candidateChanged) exitStatus = exitStatus || 1
  write(path, { ...run, status: exitStatus ? 'failed' : 'passed',
    exitStatus, finishedAt: Date.now(), failures: exitStatus ? run.failures + 1 : 0 })
  rmSync(join(dir, 'owner'), { recursive: true })
  if (candidateChanged) throw new Error('Release checkout changed during the gate; completion refused.')
}

export function retry(root, reason) {
  if (!reason || reason.trim().length < 12) throw new Error('Describe the corrected external condition (at least 12 characters).')
  const dir = join(resolve(root), 'artifacts', 'release-gate-state')
  const lock = join(dir, 'owner')
  const ownerPath = join(lock, 'pid.json')
  if (existsSync(lock) && (!existsSync(ownerPath) || live(read(ownerPath).pid))) {
    throw new Error('Cannot reset retry budget while a gate owns the checkout.')
  }
  const path = join(dir, 'run.json')
  const run = existsSync(path) ? read(path) : {}
  if (run.recovery?.reason === reason.trim()) {
    throw new Error('That recovery was already tried; diagnose and record new evidence.')
  }
  // Write recovery before releasing a stale owner, so the next gate sees it.
  write(path, { ...run, status: 'failed', failures: 1,
    recovery: { reason: reason.trim(), recordedAt: Date.now() } })
  if (existsSync(lock)) rmSync(lock, { recursive: true })
}

export function status(root) {
  const dir = join(resolve(root), 'artifacts', 'release-gate-state')
  const run = read(join(dir, 'run.json'))
  return {
    candidate: run.candidate, status: run.status === 'running' && !live(run.owner) ? 'interrupted' : run.status,
    ownerAlive: live(run.owner), elapsedSeconds: Math.floor(((run.finishedAt ?? Date.now()) - run.startedAt) / 1000),
    consecutiveFailures: run.failures,
    phases: readdirSync(dir).filter(name => name.startsWith('phase-'))
      .map(name => read(join(dir, name)))
      .filter(value => value.runStartedAt === run.startedAt)
      .sort((a, b) => a.startedAt - b.startedAt),
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [command, ...args] = process.argv.slice(2)
    if (command === 'init') console.log(initialize(args[0], Number(args[1])))
    else if (command === 'phase') phase(args[0], args[1], args[2], Number(args[3] ?? 0))
    else if (command === 'checkpoint') console.log(checkpoint(...args))
    else if (command === 'finish') finish(args[0], Number(args[1]))
    else if (command === 'retry') retry(process.cwd(), args[0])
    else if (command === 'status') console.log(JSON.stringify(status(process.cwd()), null, 2))
    else throw new Error('Usage: release-gate-state.mjs status | retry "what changed"')
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
