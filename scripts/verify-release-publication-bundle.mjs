#!/usr/bin/env node

import {
  lstatSync,
  readFileSync,
  readdirSync,
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  normalizeTag,
  resolveReleaseProductRoot,
  validatePromotableReleaseManifest,
  validateStagedReleaseTree,
} from './local-release-lib.mjs'
import { inspectStartosReleasePackage } from './startos-release.mjs'

const repoRoot = resolveReleaseProductRoot(resolve(dirname(fileURLToPath(import.meta.url)), '..'))

function fail(message) {
  throw new Error(`Release publication bundle rejected: ${message}`)
}

function parseArgs(argv) {
  const values = {
    stageDir: '',
    tag: '',
    commit: '',
    tree: '',
    requireDraft: false,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    switch (argument) {
      case '--stage-dir':
        values.stageDir = argv[++index] ?? ''
        break
      case '--tag':
        values.tag = argv[++index] ?? ''
        break
      case '--commit':
        values.commit = argv[++index] ?? ''
        break
      case '--tree':
        values.tree = argv[++index] ?? ''
        break
      case '--require-draft':
        values.requireDraft = true
        break
      case '--help':
      case '-h':
        console.log(
          'usage: verify-release-publication-bundle.mjs '
            + '--stage-dir DIR --tag TAG --commit SHA --tree SHA '
            + '[--require-draft]',
        )
        process.exit(0)
        break
      default:
        fail(`unknown argument ${argument}`)
    }
  }
  if (!values.stageDir || !values.tag || !values.commit || !values.tree) {
    fail('stage directory, tag, commit, and tree are required')
  }
  return values
}

function regularFile(path, label) {
  let metadata
  try {
    metadata = lstatSync(path)
  } catch {
    fail(`${label} is missing`)
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    fail(`${label} is not a regular non-symlink file`)
  }
}

function readManifest(stageDir) {
  const releasePath = join(stageDir, 'release.json')
  const legacyPath = join(stageDir, 'manifest.json')
  regularFile(releasePath, 'release.json')
  regularFile(legacyPath, 'manifest.json')
  const releaseText = readFileSync(releasePath, 'utf8')
  if (releaseText !== readFileSync(legacyPath, 'utf8')) {
    fail('release.json and manifest.json differ')
  }
  try {
    return JSON.parse(releaseText)
  } catch {
    fail('release.json is not valid JSON')
  }
}

function validateExactTree(stageDir, manifest) {
  const expectedRoot = new Set([
    'assets',
    'manifest.json',
    'notes.md',
    'release.json',
  ])
  const rootEntries = readdirSync(stageDir).sort()
  if (
    rootEntries.length !== expectedRoot.size
    || rootEntries.some((entry) => !expectedRoot.has(entry))
  ) {
    fail(`unexpected staged root entries: ${rootEntries.join(', ')}`)
  }
  regularFile(join(stageDir, 'notes.md'), 'notes.md')
  const assetsDir = join(stageDir, 'assets')
  const assetsMetadata = lstatSync(assetsDir)
  if (assetsMetadata.isSymbolicLink() || !assetsMetadata.isDirectory()) {
    fail('assets is not a real directory')
  }
  const expectedAssets = manifest.assets
    .map((asset) => basename(asset.path))
    .sort()
  const actualAssets = readdirSync(assetsDir).sort()
  if (
    actualAssets.length !== expectedAssets.length
    || actualAssets.some((asset, index) => asset !== expectedAssets[index])
  ) {
    fail('staged asset directory differs from the manifest')
  }
}

function validateExactStartosPackages(stageDir, manifest) {
  for (const asset of manifest.assets) {
    const match = asset.name.match(/-startos-(x86_64|aarch64)\.s9pk$/)
    if (!match) {
      continue
    }
    const inspection = inspectStartosReleasePackage({
      packagePath: join(stageDir, asset.path),
      arch: match[1],
      tag: manifest.tag,
      quiet: true,
    })
    const sealedManifestSha256 =
      manifest.release_gate_attestation?.asset_proofs?.[asset.path]
        ?.payloads?.manifest_json
    if (inspection.manifestSha256 !== sealedManifestSha256) {
      fail(
        `${asset.name} manifest differs from its local exact-package validation`,
      )
    }
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2))
  const stageDir = resolve(repoRoot, options.stageDir)
  let metadata
  try {
    metadata = lstatSync(stageDir)
  } catch {
    fail(`stage directory is missing: ${stageDir}`)
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    fail('stage directory is not a real directory')
  }
  const expectedTag = normalizeTag(options.tag)
  const expectedCommit = options.commit.trim()
  const expectedTree = options.tree.trim()
  if (!/^[0-9a-f]{40}$/.test(expectedCommit)) {
    fail('expected commit is not an exact Git SHA')
  }
  if (!/^[0-9a-f]{40}$/.test(expectedTree)) {
    fail('expected tree is not an exact Git tree')
  }

  const manifest = readManifest(stageDir)
  if (
    manifest.id !== expectedTag
    || manifest.title !== expectedTag
    || manifest.tag !== expectedTag
  ) {
    fail('manifest tag identity differs from the requested release')
  }
  if (manifest.commit !== expectedCommit) {
    fail('manifest commit differs from the exact locally gated commit')
  }
  if (
    manifest.release_gate_attestation?.app_git_tree !== expectedTree
  ) {
    fail('manifest tree differs from the exact locally gated tree')
  }
  if (options.requireDraft && manifest.draft !== true) {
    fail('GitHub import requires the immutable locally staged draft')
  }

  validateStagedReleaseTree(stageDir, manifest)
  validatePromotableReleaseManifest(manifest)
  validateExactTree(stageDir, manifest)
  validateExactStartosPackages(stageDir, manifest)
  console.log(JSON.stringify({
    ok: true,
    tag: expectedTag,
    commit: expectedCommit,
    tree: expectedTree,
    assetSetSha256:
      manifest.release_gate_attestation.asset_set_sha256,
    assetCount: manifest.assets.length,
  }))
}

try {
  main()
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
