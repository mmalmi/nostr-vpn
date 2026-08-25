#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  createReadStream,
  mkdirSync,
  readFileSync,
  rmSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  normalizeTag,
  parseReleaseRevision,
  readWorkspaceVersionTag,
  semverFromTag,
} from './local-release-lib.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '..')
const cargoTomlPath = join(repoRoot, 'Cargo.toml')
const startosVersionPath = join(repoRoot, 'startos', 'versions', 'current.ts')
const startosCliVersion = '1.1.0'

const targetAliases = new Map([
  ['x86', { arch: 'x86_64', makeTarget: 'x86' }],
  ['x86_64', { arch: 'x86_64', makeTarget: 'x86' }],
  ['arm', { arch: 'aarch64', makeTarget: 'arm' }],
  ['arm64', { arch: 'aarch64', makeTarget: 'arm' }],
  ['aarch64', { arch: 'aarch64', makeTarget: 'arm' }],
])

function usage() {
  console.log(`Usage: node scripts/startos-release.mjs [options]

Build and validate versioned StartOS release packages.

Options:
  --tag <tag>           Release tag (defaults to workspace version)
  --revision <0-99>     Corrected-release revision (defaults to source version)
  --target <target>     Build target: x86 or arm (repeatable; defaults to both)
  --output-dir <path>   Artifact directory (default: dist)
  --dry-run             Print the build plan without writing artifacts
  --help                Show this help`)
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    outputDir: null,
    revision: null,
    tag: null,
    targets: [],
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    switch (arg) {
      case '--help':
      case '-h':
        usage()
        process.exit(0)
      case '--dry-run':
        options.dryRun = true
        break
      case '--output-dir':
        options.outputDir = argv[++index] ?? ''
        break
      case '--tag':
        options.tag = normalizeTag(argv[++index] ?? '')
        break
      case '--revision':
        options.revision = argv[++index] ?? ''
        break
      case '--target':
        options.targets.push(argv[++index] ?? '')
        break
      default:
        throw new Error(`Unknown argument: ${arg}`)
    }
  }

  return options
}

function quote(arg) {
  const value = String(arg)
  return /[^\w./:@=-]/.test(value) ? JSON.stringify(value) : value
}

function run(
  command,
  args,
  { capture = false, dryRun = false, quiet = false } = {},
) {
  if (!quiet) {
    console.log(`$ ${[command, ...args].map(quote).join(' ')}`)
  }
  if (dryRun) {
    return ''
  }

  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  })
  if (result.status !== 0) {
    const stderr = capture ? result.stderr.trim() : ''
    throw new Error(stderr || `${command} exited with status ${result.status ?? 'unknown'}`)
  }
  return capture ? result.stdout.trim() : ''
}

export function validateStartosCliVersion(output) {
  const actual = String(output ?? '').trim()
  const expected = `start-cli ${startosCliVersion}`
  if (actual !== expected) {
    throw new Error(`StartOS package builder is ${actual || '<missing>'}, expected ${expected}`)
  }
  return actual
}

export function resolveStartosTarget(value) {
  const normalized = String(value ?? '').trim().toLowerCase()
  const target = targetAliases.get(normalized)
  if (!target) {
    throw new Error(`Unsupported StartOS target: ${value || '<empty>'}`)
  }
  return { ...target }
}

export function startosReleaseAssetName(tag, arch) {
  const target = resolveStartosTarget(arch)
  return `nostr-vpn-${normalizeTag(tag)}-startos-${target.arch}.s9pk`
}

export function readStartosSourceVersion(text) {
  const match = String(text).match(/^\s*version:\s*'([^'\n]+)'/m)
  if (!match) {
    throw new Error('Could not find StartOS version in startos/versions/current.ts')
  }
  return match[1]
}

export function expectedStartosVersion(tag, revision = 0) {
  return `${semverFromTag(tag)}:${parseReleaseRevision(revision, { platform: 'StartOS' })}`
}

export function resolveStartosRevision(explicitRevision, sourceVersion, tag) {
  if (String(explicitRevision ?? '').trim() !== '') {
    return parseReleaseRevision(explicitRevision, { platform: 'StartOS' })
  }

  const match = String(sourceVersion).match(/^(\d+\.\d+\.\d+):(\d+)$/)
  if (!match) {
    throw new Error(`Could not parse StartOS source version "${sourceVersion}"`)
  }
  const marketingVersion = semverFromTag(tag)
  if (match[1] !== marketingVersion) {
    throw new Error(
      `StartOS source marketing version ${match[1]} does not match release ${normalizeTag(tag)} (${marketingVersion})`,
    )
  }
  return parseReleaseRevision(match[2], { platform: 'StartOS' })
}

export function validateStartosManifest(manifest, { arch, tag, revision = 0 }) {
  const target = resolveStartosTarget(arch)
  if (manifest?.id !== 'nostr-vpn') {
    throw new Error(`StartOS package id is ${manifest?.id ?? '<missing>'}, expected nostr-vpn`)
  }
  if (manifest.virtualNetworking !== true) {
    throw new Error(
      `StartOS package virtualNetworking is ${manifest.virtualNetworking ?? '<missing>'}, expected true for tunnel access`,
    )
  }

  const expectedVersion = expectedStartosVersion(tag, revision)
  if (manifest.version !== expectedVersion) {
    throw new Error(
      `StartOS package version ${manifest.version ?? '<missing>'} does not match release ${normalizeTag(tag)} (${expectedVersion})`,
    )
  }

  const images = Array.isArray(manifest.images)
    ? manifest.images
    : Object.values(manifest.images ?? {})
  const arches = new Set(
    images.flatMap((image) =>
      Array.isArray(image?.arch) ? image.arch : image?.arch ? [image.arch] : [],
    ),
  )
  if (!arches.has(target.arch)) {
    throw new Error(
      `StartOS package does not contain ${target.arch}; found ${[...arches].join(', ') || 'no image architectures'}`,
    )
  }

  return manifest
}

export function inspectStartosReleasePackage({
  packagePath,
  arch,
  tag,
  revision,
  quiet = false,
}) {
  const sourceVersion = readStartosSourceVersion(
    readFileSync(startosVersionPath, 'utf8'),
  )
  const resolvedRevision = resolveStartosRevision(
    revision ?? process.env.NVPN_STARTOS_REVISION,
    sourceVersion,
    tag,
  )
  const manifestText = run(
    'start-cli',
    ['s9pk', 'inspect', packagePath, 'manifest'],
    { capture: true, quiet },
  )
  let manifest
  try {
    manifest = JSON.parse(manifestText)
  } catch (error) {
    throw new Error(`Could not parse StartOS manifest JSON: ${error.message}`)
  }
  validateStartosManifest(manifest, {
    arch,
    revision: resolvedRevision,
    tag,
  })
  return {
    manifest,
    manifestSha256: createHash('sha256')
      .update(canonicalJson(manifest))
      .digest('hex'),
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

async function sha256(path) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk)
  }
  return hash.digest('hex')
}

async function buildTarget({ dryRun, outputDir, revision, tag, target }) {
  const { arch, makeTarget } = resolveStartosTarget(target)
  const packagePath = join(repoRoot, `nostr-vpn_${arch}.s9pk`)
  const outputPath = join(outputDir, startosReleaseAssetName(tag, arch))

  if (!dryRun) {
    rmSync(packagePath, { force: true })
  }
  run('make', [makeTarget], { dryRun })

  if (dryRun) {
    console.log(`Would validate ${packagePath} and write ${outputPath}`)
    return outputPath
  }

  inspectStartosReleasePackage({
    packagePath,
    arch,
    revision,
    tag,
  })

  mkdirSync(outputDir, { recursive: true })
  copyFileSync(packagePath, outputPath)
  inspectStartosReleasePackage({
    packagePath: outputPath,
    arch,
    revision,
    tag,
  })
  console.log(`Wrote ${outputPath}`)
  console.log(`SHA256 ${await sha256(outputPath)}  ${outputPath}`)
  return outputPath
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv)
  const tag = options.tag || readWorkspaceVersionTag(readFileSync(cargoTomlPath, 'utf8'))
  const sourceVersion = readStartosSourceVersion(readFileSync(startosVersionPath, 'utf8'))
  const revision = resolveStartosRevision(
    options.revision ?? process.env.NVPN_STARTOS_REVISION,
    sourceVersion,
    tag,
  )
  const expectedVersion = expectedStartosVersion(tag, revision)
  if (sourceVersion !== expectedVersion) {
    throw new Error(
      `StartOS source version ${sourceVersion} does not match release ${tag} (${expectedVersion}); run node scripts/sync-versions.mjs`,
    )
  }

  if (!options.dryRun) {
    validateStartosCliVersion(
      run('start-cli', ['--version'], { capture: true }),
    )
  }

  const outputDir = resolve(repoRoot, options.outputDir || 'dist')
  const targets = options.targets.length > 0 ? options.targets : ['x86', 'arm']
  const uniqueTargets = [
    ...new Map(targets.map((target) => {
      const resolved = resolveStartosTarget(target)
      return [resolved.arch, resolved]
    })).values(),
  ]

  for (const target of uniqueTargets) {
    await buildTarget({
      dryRun: options.dryRun,
      outputDir,
      revision,
      tag,
      target: target.makeTarget,
    })
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
  })
}
