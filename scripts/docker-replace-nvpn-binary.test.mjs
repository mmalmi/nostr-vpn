import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const utility = fileURLToPath(new URL('./docker-replace-nvpn-binary', import.meta.url))
const configurations = {
  'command only': { Cmd: ['/bin/sh', '-c', 'printf "%s" "$VALUE"'], Entrypoint: null },
  'entrypoint with arguments': { Cmd: ['--config', '/path with spaces/config.toml'], Entrypoint: ['nvpn-web'] },
  'entrypoint only': { Cmd: null, Entrypoint: ['nvpn-web'] },
  'no launch defaults': { Cmd: null, Entrypoint: null },
}

for (const [name, config] of Object.entries(configurations)) {
  test(`binary replacement ${config.Cmd || config.Entrypoint ? 'preserves' : 'accepts'} ${name}`, () => {
    const root = mkdtempSync(join(tmpdir(), 'nvpn-image-command-'))
    const state = join(root, 'state.json')
    const binary = join(root, 'nvpn')
    writeFileSync(state, JSON.stringify({ base: config }))
    writeFileSync(binary, 'replacement binary', { mode: 0o755 })
    writeFileSync(join(root, 'file'), '#!/bin/sh\nprintf "%s\\n" "ELF 64-bit LSB executable, ARM aarch64"\n', { mode: 0o755 })
    // Model Docker's launch configuration, while executing the real utility.
    writeFileSync(join(root, 'docker'), `#!/usr/bin/env node
const fs = require('node:fs')
const args = process.argv.slice(2)
const path = process.env.IMAGE_TEST_STATE
const state = JSON.parse(fs.readFileSync(path, 'utf8'))
switch (args[0]) {
  case 'image':
    if (args[1] !== 'inspect') throw Error('unexpected image command')
    console.log(args.at(-1).includes('Architecture') ? 'arm64' : JSON.stringify(state.base.Cmd))
    break
  case 'create':
    state.container = { ...state.base }
    if (args.length > 2) state.container.Cmd = args.slice(2)
    if (!state.container.Cmd?.length && !state.container.Entrypoint?.length) {
      throw Error('no command specified')
    }
    console.log('fixture-container')
    break
  case 'cp':
    state.binary = fs.readFileSync(args[1], 'utf8')
    break
  case 'commit':
    state.target = { ...state.container }
    if (args[1] === '--change') {
      if (!args[2].startsWith('CMD ')) throw Error('unexpected configuration change')
      const cmd = JSON.parse(args[2].slice(4))
      state.target.Cmd = cmd.length || state.target.Entrypoint?.length ? cmd : state.container.Cmd
    }
    console.log('sha256:fixture')
    break
  case 'rm':
    delete state.container
    break
  default: throw Error('unexpected Docker command: ' + args)
}
fs.writeFileSync(path, JSON.stringify(state))
`, { mode: 0o755 })
    try {
      const result = spawnSync('/bin/bash', [utility, 'base', 'target', binary], {
        encoding: 'utf8',
        env: { ...process.env, PATH: `${root}:${process.env.PATH}`, IMAGE_TEST_STATE: state },
      })
      assert.equal(result.status, 0, result.stderr)
      const actual = JSON.parse(readFileSync(state, 'utf8'))
      assert.deepEqual(actual.target.Entrypoint, config.Entrypoint)
      assert.deepEqual(actual.target.Cmd ?? [], config.Cmd ?? (config.Entrypoint ? [] : ['true']))
      assert.equal(actual.binary, 'replacement binary')
      assert.equal(actual.container, undefined)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
}
