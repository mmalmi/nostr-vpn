import assert from 'node:assert/strict'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { proveUnchangedPlatformInputs } from './release-component-source.mjs'

const script = (name) => new URL(name, import.meta.url)

test('actual Windows caller prepares the fixture before the bounded UI task', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-windows-preparation-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'scripts'))
  mkdirSync(join(root, 'bin'))
  const caller = join(root, 'scripts/windows-vm-manual-join-e2e.sh')
  copyFileSync(script('windows-vm-manual-join-e2e.sh'), caller)
  writeFileSync(join(root, 'scripts/windows-vm-wake-display.sh'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  const captured = join(root, 'commands.jsonl')
  writeFileSync(join(root, 'bin/ssh'), `#!${process.execPath}
import fs from 'node:fs';
const command = Buffer.from(process.argv.at(-1), 'base64').toString('utf16le');
fs.appendFileSync(process.env.CAPTURED_POWERSHELL, JSON.stringify(command) + '\\n');
`, { mode: 0o755 })
  const result = spawnSync('bash', [caller], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`,
      CAPTURED_POWERSHELL: captured, NVPN_WINDOWS_SKIP_GIT_SYNC: '1',
      NVPN_WINDOWS_SSH_HOST: 'fixture.invalid', NVPN_WINDOWS_SSH_JUMP: '',
      NVPN_WINDOWS_SSH_PROXY_COMMAND: '' },
  })
  assert.equal(result.status, 0, result.stderr)
  const commands = readFileSync(captured, 'utf8').trim().split('\n').map(JSON.parse)
  assert.equal(commands.length, 2)
  const [prepare, run] = commands
  const beforeInteractiveWrapper = prepare.slice(0, prepare.indexOf("@'"))
  assert.match(beforeInteractiveWrapper, /cargo build --locked --release -p nostr-vpn-core --example desktop_manual_join_e2e_fixture/)
  assert.match(beforeInteractiveWrapper, /windows-smoke-cargo/)
  assert.doesNotMatch(prepare, /windows-ui-e2e-cargo/)
  assert.doesNotMatch(prepare.slice(prepare.indexOf("@'")), /cargo build/)
  assert.match(run, /-TimeoutSeconds 180/)
})

test('the timed GUI helper requires an already built fixture', () => {
  const helper = readFileSync(script('e2e-windows-manual-join-ui.ps1'), 'utf8')
  assert.doesNotMatch(helper, /cargo build/)
  assert.match(helper, /cargo metadata --locked --no-deps/)
  assert.match(helper, /Test-Path -LiteralPath \$Fixture -PathType Leaf/)
})

test('the exact scheduled task is stopped before its ownership record is removed', () => {
  const helper = readFileSync(script('run-windows-interactive-e2e.ps1'), 'utf8')
  const cleanup = helper.slice(helper.lastIndexOf('} finally {'))
  const stop = cleanup.indexOf('Stop-ScheduledTask -TaskName $TaskName')
  const remove = cleanup.indexOf('Unregister-ScheduledTask -TaskName $TaskName')
  assert.ok(stop >= 0 && stop < remove)
  const treeStop = cleanup.indexOf('taskkill.exe /PID $_.ProcessId /T /F')
  assert.ok(treeStop >= 0 && treeStop < stop)
  assert.match(cleanup.slice(0, treeStop), /\$_.CommandLine.Contains\(\$RunnerPath\)/)
})

test('fixture-only harness changes preserve native product identity, app changes do not', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-windows-source-proof-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  git('init', '-q')
  git('config', 'user.name', 'Fixture')
  git('config', 'user.email', 'fixture@example.invalid')
  mkdirSync(join(root, 'scripts'))
  mkdirSync(join(root, 'windows'))
  const paths = ['windows-vm-manual-join-e2e.sh', 'e2e-windows-manual-join-ui.ps1', 'run-windows-interactive-e2e.ps1']
  for (const name of paths) writeFileSync(join(root, 'scripts', name), 'before\n')
  writeFileSync(join(root, 'windows/App.cs'), 'before\n')
  git('add', '.')
  git('commit', '-qm', 'before')
  const receiptCommit = git('rev-parse', 'HEAD')
  const receiptTree = git('rev-parse', 'HEAD^{tree}')
  for (const name of paths) writeFileSync(join(root, 'scripts', name), 'after\n')
  git('commit', '-qam', 'harness')
  const request = { candidateRoot: root, receiptCommit, receiptTree,
    candidateCommit: git('rev-parse', 'HEAD'), candidateTree: git('rev-parse', 'HEAD^{tree}') }
  for (const platform of ['android', 'ios', 'linux', 'macos', 'windows']) {
    assert.equal(proveUnchangedPlatformInputs({ ...request, platform }).platform, platform)
  }
  writeFileSync(join(root, 'windows/App.cs'), 'after\n')
  git('commit', '-qam', 'product')
  assert.throws(() => proveUnchangedPlatformInputs({ ...request, platform: 'windows',
    candidateCommit: git('rev-parse', 'HEAD'), candidateTree: git('rev-parse', 'HEAD^{tree}') }), /changed product\/build input windows\/App.cs/)
})
