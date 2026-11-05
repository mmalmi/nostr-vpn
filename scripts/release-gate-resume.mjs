import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname } from 'node:path'

import {
  collectConcreteReleaseGateReceipts,
  collectReleaseGateReceipts,
} from './release-artifact-provenance-lib.mjs'

export function unlinkIfSameFile(path, expected) {
  if (!existsSync(path)) return false
  const current = lstatSync(path)
  if (
    current.isSymbolicLink()
    || current.dev !== expected.dev
    || current.ino !== expected.ino
  ) return false
  unlinkSync(path)
  return true
}

export function completeReleaseGateFromReceipts({
  commit,
  tree,
  validatorSource = { commit, tree },
  candidateRoot,
  releaseGateSummaryPath,
  platformReceiptPaths,
  targetSeconds = 1_800,
  monotonicSeconds = () => performance.now() / 1_000,
}) {
  if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) {
    throw new Error('Release candidate lacks exact Git identities.')
  }
  if (!Number.isSafeInteger(targetSeconds) || targetSeconds <= 0) {
    throw new Error('Release-gate target seconds must be a positive integer.')
  }
  const args = {
    commit,
    tree,
    validatorSource,
    candidateRoot,
    releaseGateSummaryPath,
    platformReceiptPaths,
  }
  if (existsSync(releaseGateSummaryPath)) {
    if (lstatSync(releaseGateSummaryPath).isSymbolicLink()) {
      throw new Error('Release-gate completion receipt must not be a symlink.')
    }
    return { created: false, ...collectReleaseGateReceipts(args) }
  }

  const started = monotonicSeconds()
  const concrete = collectConcreteReleaseGateReceipts(args)
  const summary = {
    receiptSchema: 2,
    completionMode: 'validated-existing-concrete-receipts',
    elapsedSeconds: Math.max(1, Math.ceil(monotonicSeconds() - started)),
    elapsedScope: 'receipt-validation-only',
    targetSeconds,
    targetStatus: 'not-measured',
    appGitSha: commit,
    appGitTree: tree,
    validatorGitSha: validatorSource.commit,
    validatorGitTree: validatorSource.tree,
    platformGateReceipts: concrete.platformGateReceipts,
    platformSourceEquivalence: concrete.platformSourceEquivalence,
  }

  mkdirSync(dirname(releaseGateSummaryPath), { recursive: true })
  const temporary = `${releaseGateSummaryPath}.tmp.${process.pid}`
  writeFileSync(temporary, `${JSON.stringify(summary, null, 2)}\n`, {
    flag: 'wx',
  })
  const temporaryIdentity = lstatSync(temporary)
  let linked = false
  try {
    collectReleaseGateReceipts({
      ...args,
      releaseGateSummaryPath: temporary,
    })
    linkSync(temporary, releaseGateSummaryPath)
    linked = true
    return { created: true, ...collectReleaseGateReceipts(args) }
  } catch (error) {
    if (linked) unlinkIfSameFile(releaseGateSummaryPath, temporaryIdentity)
    throw error
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary)
  }
}
