import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { inspectReleaseTagRefs, preflightGithubRelease, publishExactGithubRelease, renderGithubReleaseNotes } from './github-release-publication.mjs'

function installGitBoundary({ root, bin, tag, commit }) {
  const statePath = join(root, 'refs.json')
  const exact = { githubTag: commit, htreeTag: commit, localTag: commit, localType: 'commit' }
  const setRefs = (overrides = {}) => writeFileSync(statePath, JSON.stringify({ ...exact, ...overrides }))
  setRefs()
  const git = join(bin, 'git')
  writeFileSync(git, `#!${process.execPath}
const fs = require('node:fs')
const args = process.argv.slice(2)
const refs = JSON.parse(fs.readFileSync(${JSON.stringify(statePath)}, 'utf8'))
const reference = ${JSON.stringify(`refs/tags/${tag}`)}
if (JSON.stringify(args) === JSON.stringify(['remote', 'get-url', 'github'])) {
  process.stdout.write('https://github.com/example/nvpn.git')
} else if (JSON.stringify(args) === JSON.stringify(['cat-file', '-t', reference])) {
  process.stdout.write(refs.localType)
} else if (JSON.stringify(args) === JSON.stringify(['rev-parse', '-q', '--verify', reference + '^{commit}'])) {
  process.stdout.write(refs.localTag)
} else if (args[0] === 'ls-remote' && args[1] === '--exit-code' && args[3] === reference && args.length === 4 && ['github', 'origin'].includes(args[2])) {
  const sha = refs[args[2] === 'github' ? 'githubTag' : 'htreeTag']
  if (!sha) process.exit(2)
  process.stdout.write(sha + '\\t' + reference)
} else { throw new Error('Unexpected git command: ' + args.join(' ')) }
`)
  chmodSync(git, 0o755)
  return setRefs
}

test('exact release refs reject missing, stale, malformed and mismatched advertisements', () => {
  const tag = 'v4.1.10'
  const commit = 'a'.repeat(40)
  const reference = `refs/tags/${tag}`
  const exact = { status: 0, stdout: `${commit}\t${reference}\n` }
  const inspect = (remote, response, requirePublished = true) => inspectReleaseTagRefs({
    repoRoot: '.', tag, commit, requirePublished,
    runCommand: (command, args) => {
      assert.equal(command, 'git')
      assert.deepEqual(args.slice(0, 2), ['ls-remote', '--exit-code'])
      assert.equal(args[3], reference)
      return args[2] === remote ? response : exact
    },
  })
  for (const remote of ['github', 'origin']) {
    for (const response of [
      { status: 2, stdout: '' },
      { status: 0, stdout: `${'b'.repeat(40)}\t${reference}` },
      { status: 0, stdout: `${commit}\trefs/tags/another-release` },
      { status: 0, stdout: `${exact.stdout}${exact.stdout}` },
      { status: 0, stdout: `${exact.stdout}${commit}\t${reference}^{}` },
      { status: 0, stdout: `${commit}\t${reference} extra` },
      { status: 0, stdout: `not-a-sha\t${reference}` },
      { status: 0, stdout: '' },
      { status: 1, stdout: exact.stdout },
      { status: 2, stdout: exact.stdout },
      { error: new Error('unavailable'), status: null, stdout: '' },
    ]) {
      assert.throws(() => inspect(remote, response), /release refs|conflicts|invalid exact ref|could not inspect/i)
    }
    const absent = inspect(remote, { status: 2, stdout: '' }, false)
    assert.equal(absent[remote === 'github' ? 'githubTag' : 'htreeTag'], '')
    assert.deepEqual(inspect(remote, exact), { githubTag: commit, htreeTag: commit })
  }
})

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
    const tag = 'v4.1.10'
    const commit = 'a'.repeat(40)
    const setRefs = installGitBoundary({ root, bin, tag, commit })
    const name = 'nvpn linux.tar.gz'
    const bytes = Buffer.from('exact staged release bytes')
    const notes = `[Linux](assets/${encodeURIComponent(name)})\n`
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    const asset = { path: `assets/${name}`, size: bytes.length, sha256 }
    writeFileSync(join(stageDir, asset.path), bytes)
    writeFileSync(join(stageDir, 'notes.md'), notes)
    // Exercise production preflight and promotion through strict external command
    // boundaries; no branch inspection or mutation is accepted by the git stub.
    const gh = join(bin, 'gh')
    writeFileSync(gh, `#!${process.execPath}
const fs = require('node:fs')
const path = require('node:path')
const args = process.argv.slice(2)
const option = name => args[args.indexOf(name) + 1]
const state = path.join(process.cwd(), 'remote.json')
if (args[0] === 'auth' && args[1] === 'status') process.exit(0)
if (args[0] === 'repo' && args[1] === 'view' && args[2] === 'example/nvpn') {
  process.stdout.write('example/nvpn'); process.exit(0)
}
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
  const drift = path.join(process.cwd(), 'download-drift.json')
  if (fs.existsSync(drift)) fs.copyFileSync(drift, path.join(process.cwd(), 'refs.json'))
} else { process.exit(4) }
`)
    chmodSync(gh, 0o755)
    process.env.PATH = `${bin}:${originalPath}`
    let mutations = 0
    let duringMutation = () => {}
    const publish = () => publishExactGithubRelease({
      repoRoot: root, stageDir, manifest: { assets: [asset] }, tag, commit,
      repository: 'example/nvpn', beforeMutation: () => { mutations += 1; duringMutation() },
    })
    const preflight = () => preflightGithubRelease({ repoRoot: root, tag, commit })
    assert.deepEqual(preflight(), { repository: 'example/nvpn' })
    for (const changed of [
      { githubTag: '' }, { htreeTag: '' },
      { githubTag: 'b'.repeat(40) }, { htreeTag: 'b'.repeat(40) },
      { localTag: 'b'.repeat(40) }, { localType: 'tag' },
    ]) {
      setRefs(changed)
      assert.throws(preflight, /release refs|conflicts|lightweight tag/i)
      assert.throws(publish, /release refs|conflicts|lightweight tag/i)
    }
    assert.equal(mutations, 0)
    setRefs()
    duringMutation = () => setRefs({ htreeTag: '' })
    assert.throws(publish, /release refs do not all resolve/i)
    assert.equal(mutations, 1)
    mutations = 0
    duringMutation = () => {}
    setRefs()
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
    writeFileSync(join(root, 'remote.json'), JSON.stringify({ ...remote, body: notes }))
    duringMutation = () => setRefs({ githubTag: 'b'.repeat(40) })
    assert.throws(publish, /tag .* conflicts/i)
    assert.equal(readFileSync(join(root, 'mutations.log'), 'utf8'), 'create\nedit\n')
    setRefs()
    writeFileSync(join(root, 'remote.json'), JSON.stringify({ ...remote, assets: [] }))
    duringMutation = () => setRefs({ htreeTag: 'b'.repeat(40) })
    assert.throws(publish, /tag .* conflicts/i)
    assert.equal(readFileSync(join(root, 'mutations.log'), 'utf8'), 'create\nedit\n')
    setRefs({ htreeTag: '' })
    writeFileSync(join(root, 'download-drift.json'), readFileSync(join(root, 'refs.json')))
    setRefs()
    writeFileSync(join(root, 'remote.json'), JSON.stringify(remote))
    duringMutation = () => { throw new Error('exact retry must not mutate') }
    assert.throws(publish, /release refs do not all resolve/i)
    assert.equal(readFileSync(join(root, 'mutations.log'), 'utf8'), 'create\nedit\n')
  } finally {
    process.env.PATH = originalPath
    rmSync(root, { recursive: true, force: true })
  }
})
