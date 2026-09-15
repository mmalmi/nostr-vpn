import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

test('version synchronization leaves the workspace usable by locked Cargo commands', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-version-sync-'))
  try {
    const source = readFileSync('scripts/sync-versions.mjs', 'utf8')
    const paths = [...source.matchAll(/makeTarget\('([^']+)'/g)].map(match => match[1])
    for (const path of [...paths, 'ios/app-store-build-number', 'scripts/sync-versions.mjs']) {
      mkdirSync(dirname(join(root, path)), { recursive: true })
      copyFileSync(path, join(root, path))
    }
    symlinkSync(resolve('scripts/local-release-lib.mjs'), join(root, 'scripts/local-release-lib.mjs'))
    const packages = ['nostr-vpn-app-core', 'nostr-vpn-core', 'nostr-vpn-sim', 'nostr-vpn-web', 'nostr-vpn-wintun', 'nvpn']
    for (const name of packages) {
      mkdirSync(join(root, name, 'src'), { recursive: true })
      writeFileSync(join(root, name, 'src/lib.rs'), '')
      writeFileSync(join(root, name, 'Cargo.toml'), `[package]\nname = "${name}"\nversion.workspace = true\nedition = "2021"\n`)
    }
    const manifest = version => `[workspace]\nmembers = ${JSON.stringify(packages)}\nresolver = "2"\n[workspace.package]\nversion = "${version}"\n`
    const run = (command, args) => spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 15_000 })
    const passed = result => {
      assert.ifError(result.error)
      assert.equal(result.status, 0, result.stderr)
    }
    writeFileSync(join(root, 'Cargo.toml'), manifest('4.1.10'))
    passed(run('cargo', ['generate-lockfile', '--offline']))
    writeFileSync(join(root, 'Cargo.toml'), manifest('4.1.11'))
    passed(run(process.execPath, ['scripts/sync-versions.mjs']))
    passed(run(process.execPath, ['scripts/sync-versions.mjs', '--check']))
    passed(run('cargo', ['metadata', '--offline', '--locked', '--format-version=1']))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
