import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { publishExactGithubRelease, renderGithubReleaseNotes } from './github-release-publication.mjs'

test('GitHub notes link to attached downloads without changing canonical notes', () => {
  const notes = '# Fixed\n\n[Linux](assets/nvpn-linux.tar.gz)\n[Other](https://example.com/help)\n[Unknown](assets/not-published.zip)\n'
  const rendered = renderGithubReleaseNotes({ notes, repository: 'owner/repo', tag: 'v4.1.10',
    assets: [{ name: 'nvpn-linux.tar.gz' }] })
  assert.equal(rendered, '# Fixed\n\n[Linux](https://github.com/owner/repo/releases/download/v4.1.10/nvpn-linux.tar.gz)\n[Other](https://example.com/help)\n[Unknown](assets/not-published.zip)\n')
  assert.ok(notes.includes('[Linux](assets/nvpn-linux.tar.gz)'))
  assert.equal(renderGithubReleaseNotes({ notes: rendered, repository: 'owner/repo', tag: 'v4.1.10',
    assets: [{ name: 'nvpn-linux.tar.gz' }] }), rendered)
})

test('publication creates and repairs download links while preserving staged notes and assets', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-github-links-'))
  const originalPath = process.env.PATH
  try {
    const bin = join(root, 'bin')
    const stageDir = join(root, 'stage')
    mkdirSync(bin)
    mkdirSync(join(stageDir, 'assets'), { recursive: true })
    execFileSync('git', ['init', '-q', root])
    execFileSync('git', ['remote', 'add', 'github', 'https://github.com/example/nvpn.git'], { cwd: root })
    const tag = 'v4.1.10'
    const commit = 'a'.repeat(40)
    const name = 'nvpn linux.tar.gz'
    const bytes = Buffer.from('exact staged release bytes')
    const notes = `[Linux](assets/${encodeURIComponent(name)})\n`
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    const asset = { path: `assets/${name}`, size: bytes.length, sha256 }
    writeFileSync(join(stageDir, asset.path), bytes)
    writeFileSync(join(stageDir, 'notes.md'), notes)
    // Exercise the production publisher with only the external GitHub boundary
    // replaced. The stub rejects unexpected commands and serves exact asset bytes.
    const gh = join(bin, 'gh')
    writeFileSync(gh, `#!${process.execPath}
const fs = require('node:fs')
const path = require('node:path')
const args = process.argv.slice(2)
const option = name => args[args.indexOf(name) + 1]
const state = path.join(process.cwd(), 'remote.json')
if (args[0] !== 'release' || option('--repo') !== 'example/nvpn') process.exit(2)
if (args[1] === 'view') {
  if (!fs.existsSync(state)) { process.stderr.write('HTTP 404: not found'); process.exit(1) }
  process.stdout.write(fs.readFileSync(state))
} else if (args[1] === 'create' || args[1] === 'edit') {
  if (!args.includes('--notes') || args.includes('--notes-file')) process.exit(3)
  fs.writeFileSync(state, JSON.stringify({
    tagName: args[2], name: option('--title'), targetCommitish: option('--target'),
    isDraft: false, isPrerelease: false, body: option('--notes'),
    assets: [{ name: ${JSON.stringify(name)}, size: ${bytes.length}, digest: 'sha256:${sha256}' }],
  }))
  fs.appendFileSync(path.join(process.cwd(), 'mutations.log'), args[1] + '\\n')
} else if (args[1] === 'download') {
  fs.copyFileSync(${JSON.stringify(join(stageDir, asset.path))}, path.join(option('--dir'), ${JSON.stringify(name)}))
} else { process.exit(4) }
`)
    chmodSync(gh, 0o755)
    process.env.PATH = `${bin}:${originalPath}`
    let mutations = 0
    const publish = () => publishExactGithubRelease({
      repoRoot: root, stageDir, manifest: { assets: [asset] }, tag, commit,
      repository: 'example/nvpn', beforeMutation: () => { mutations += 1 },
    })
    assert.deepEqual(publish(), { created: true, verified: true })
    const expected = `[Linux](https://github.com/example/nvpn/releases/download/${tag}/nvpn%20linux.tar.gz)\n`
    const remote = JSON.parse(readFileSync(join(root, 'remote.json'), 'utf8'))
    assert.equal(remote.body, expected)
    writeFileSync(join(root, 'remote.json'), JSON.stringify({ ...remote, body: notes }))
    assert.deepEqual(publish(), { created: false, verified: true })
    assert.equal(JSON.parse(readFileSync(join(root, 'remote.json'), 'utf8')).body, expected)
    assert.deepEqual(publish(), { created: false, verified: true })
    assert.equal(mutations, 2)
    assert.equal(readFileSync(join(root, 'mutations.log'), 'utf8'), 'create\nedit\n')
    assert.equal(readFileSync(join(stageDir, 'notes.md'), 'utf8'), notes)
    assert.deepEqual(readFileSync(join(stageDir, asset.path)), bytes)
  } finally {
    process.env.PATH = originalPath
    rmSync(root, { recursive: true, force: true })
  }
})
