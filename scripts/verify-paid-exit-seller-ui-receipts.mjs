#!/usr/bin/env node
// Validate shipped-UI paid-exit seller receipts using the canonical source proof.
import { createHash } from 'node:crypto'
import { lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual, parseArgs } from 'node:util'
import { proveUnchangedPlatformInputs } from './release-component-source.mjs'

const EXPECTED_PLATFORMS = ['linux', 'macos']
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: Object.fromEntries(
    ['candidate-root', 'app-git-sha', 'app-git-tree', 'output'].map((name) => [name, { type: 'string' }]),
  ),
})
const candidateRoot = resolve(values['candidate-root'] ?? fileURLToPath(new URL('..', import.meta.url)))
const candidateCommit = values['app-git-sha'] ?? ''
const candidateTree = values['app-git-tree'] ?? ''
if (!/^[0-9a-f]{40}$/.test(candidateCommit) || !/^[0-9a-f]{40}$/.test(candidateTree) || !values.output) {
  throw new Error('Exact --app-git-sha, --app-git-tree and --output are required.')
}
const paths = new Map()
for (const raw of positionals) {
  const separator = raw.indexOf('=')
  const platform = raw.slice(0, separator)
  if (separator < 0 || !EXPECTED_PLATFORMS.includes(platform) || paths.has(platform)) {
    throw new Error(`Invalid or duplicate platform=receipt: ${raw}`)
  }
  paths.set(platform, raw.slice(separator + 1))
}
if (!isDeepStrictEqual([...paths.keys()].sort(), EXPECTED_PLATFORMS)) {
  throw new Error('Expected receipts for linux and macos.')
}

const sellerContract = {
  priceMsatPerGb: 1_000_000,
  countryCode: 'FI',
  acceptedMints: ['http://cashu-mint:3338'],
}
const platforms = {}
const platformSourceEquivalence = {}
for (const platform of EXPECTED_PLATFORMS) {
  const path = paths.get(platform)
  if (!lstatSync(path).isFile()) throw new Error(`${platform} receipt must be a regular file.`)
  const bytes = readFileSync(path)
  const value = JSON.parse(bytes)
  const expected = {
    receiptSchema: 1, platform, case: 'paid-exit-seller',
    evidenceSource: 'shipped-ui-restart-readback', releaseBlackbox: true,
    savedViaShippedUi: true, enabledViaShippedUi: true, uiRestartReadback: true,
    privateStateRead: false, paidExitEnabled: true,
    paidExitPriceMsatPerGb: sellerContract.priceMsatPerGb,
    paidExitCountryCode: sellerContract.countryCode,
    paidExitAcceptedMints: sellerContract.acceptedMints,
  }
  for (const [field, wanted] of Object.entries(expected)) {
    if (!isDeepStrictEqual(value[field], wanted)) throw new Error(`${platform} receipt ${field} differs from the seller UI contract.`)
  }
  // Always resolve both trees, including exact-source receipts. Never rewrite
  // old evidence with the new commit: retain its digest and record the proof.
  const proof = proveUnchangedPlatformInputs({
    candidateRoot, platform, candidateCommit, candidateTree,
    receiptCommit: value.appGitSha, receiptTree: value.appGitTree,
  })
  if (value.appGitSha !== candidateCommit) platformSourceEquivalence[platform] = proof
  platforms[platform] = createHash('sha256').update(bytes).digest('hex')
}
const output = resolve(values.output)
mkdirSync(dirname(output), { recursive: true })
const temporary = `${output}.tmp.${process.pid}`
writeFileSync(temporary, `${JSON.stringify({
  receiptSchema: 1,
  gate: 'supported-platform paid-exit seller shipped UI',
  platforms, platformSourceEquivalence,
  allSupportedPlatformsSavedEnabledAndRestartRead: true,
  sellerContract, appGitSha: candidateCommit, appGitTree: candidateTree,
}, null, 2)}\n`, { flag: 'wx' })
renameSync(temporary, output)
