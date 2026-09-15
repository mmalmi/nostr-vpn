#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import {
  constants,
  cpSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  androidReleaseAssetName,
  buildReleaseManifest,
  buildReleaseManifestFiles,
  bumpAndroidGradleVersion,
  bumpCargoPackageVersion,
  bumpPbxprojMarketingVersion,
  deterministicBuildEnv,
  linuxReleaseTargetsForDockerPlatform,
  normalizeTag,
  parseEnvFile,
  readWorkspaceVersionTag,
  replaceWithExactFileCopy,
  semverFromTag,
  sha256FileSync,
  splitCsv,
  validateAndroidBundleRelationship,
  validateAndroidReleaseGateReceipt,
  validateCleanReleaseSource,
  validateMacosGateSigningIdentity,
  validatePromotableReleaseManifest,
  validatePromotableReleaseSource,
  validateReleaseAssetSet,
  validateStagedReleaseTree,
  zapstorePublicationRequired,
} from './local-release-lib.mjs'
import {
  androidRuntimePayloads,
  archiveMemberSha256 as commandOutputSha256,
  buildReleaseGateAttestation,
  collectReleaseGateReceipts,
  exactArtifactProof,
  mergeArtifactProofs,
  readRequiredJson,
  requireReceiptSource,
  startosExactPackageValidator,
  validateLinuxArm64CliReceipt,
  validateWindowsInstallerGateReceipt,
  validateExactZipMembers,
} from './release-artifact-provenance-lib.mjs'
import { inspectStartosReleasePackage, preflightStartosRelease } from './startos-release.mjs'
import {
  preflightGithubRelease,
  publishExactGithubRelease,
} from './github-release-publication.mjs'
import { preflightHtreeRelease } from './htree-release-publication.mjs'
import {
  preflightIosPublication,
  publishExactIosDistribution,
} from './ios-release-publication.mjs'
import {
  preflightUmbrelPublication,
  publishVerifiedUmbrelRelease,
} from './umbrel-release.mjs'
import { validateReleaseMutationGate } from './release-mutation-gate.mjs'
import {
  preflightRequiredZapstorePublication as preflightExactZapstorePublication,
  publishExactZapstoreRelease,
} from './zapstore-release-publication.mjs'
import {
  exactFipsPublicationCandidate,
  linuxPublicationVerificationPlan,
  validateWindowsPublicationFipsReceipts,
} from './release-source-verification.mjs'
import { completeReleaseGateFromReceipts } from './release-gate-resume.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '..')
const rootCargoToml = join(repoRoot, 'Cargo.toml')
const changelogPath = join(repoRoot, 'CHANGELOG.md')
const distDir = join(repoRoot, 'dist')
const defaultEnvFiles = [join(repoRoot, '.env.release.local'), join(repoRoot, '.env.zapstore.local')]
const versionlessCliAssets = new Map([
  ['nvpn-aarch64-apple-darwin.tar.gz', 'nvpn-{tag}-aarch64-apple-darwin.tar.gz'],
  ['nvpn-x86_64-unknown-linux-musl.tar.gz', 'nvpn-{tag}-x86_64-unknown-linux-musl.tar.gz'],
  ['nvpn-aarch64-unknown-linux-musl.tar.gz', 'nvpn-{tag}-aarch64-unknown-linux-musl.tar.gz'],
])

class SkipStepError extends Error {}

function usage() {
  console.log(`Usage: node scripts/local-release.mjs [options]

Build local Rust/native release artifacts, stage a hashtree release directory,
and optionally publish it.

Options:
  --publish                 Disabled direct publication mode; stage, then
                            publish the exact staged draft
  --final                   Disabled direct final mode; use --promote-draft
                            with exact staged release evidence
  --draft                   Disabled alias for --publish
  --promote-draft           Promote an existing staged draft directory for
                            this tag to final/latest without rebuilding
  --publish-staged-draft    Publish an existing complete staged draft without
                            rebuilding, rerunning gates, or shipping elsewhere
  --cargo-publish           Publish Rust crates during an exact staged
                            --promote-draft operation
  --skip-cargo-publish      With --promote-draft, don't push Rust crates
  --skip-zapstore           With --promote-draft, skip Android Zapstore
                            publication
  --skip-umbrel             With --promote-draft, skip the required multi-arch
                            Umbrel image publication and public readback
  --require-zapstore        With --promote-draft, require a signed APK, zsp,
                            signing configuration, successful publication,
                            and post-publish Zapstore verification
  --dry-run                 Print the plan without running build or publish commands
  --skip-verify            Skip fmt/clippy/test verification
  --reuse-gate-receipts    Validate and reuse the complete existing gate receipt set
                            instead of executing the platform gate again
  --complete-gate-from-receipts
                            Validate canonical receipts and write the completion summary
  --tag <tag>              Release tag (defaults to workspace version, for example v4.0.0)
  --release-tree <name>    htree release tree name (default: releases/nostr-vpn)
  --stage-dir <path>       Directory used for staged release metadata
  --env-file <path>        Extra dotenv file to load (repeatable)
  --only <csv>             Limit steps to platform-versions,verify,startos,macos,ios,linux,windows,android
  --skip <csv>             Skip steps by name
  --allow-partial          Stage even if a selected platform build fails
  --help                   Show this help

The script auto-loads .env.release.local and .env.zapstore.local when present.
Shell environment variables override values from those files.
NVPN_RELEASE_REQUIRE_ZAPSTORE=true is equivalent to --require-zapstore.`)
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    publish: false,
    draft: true,
    promoteDraft: false,
    publishStagedDraft: false,
    cargoPublish: false,
    skipCargoPublish: false,
    skipZapstore: false,
    skipUmbrel: false,
    requireZapstore: false,
    skipVerify: false,
    reuseGateReceipts: false,
    completeGateFromReceipts: false,
    releaseTree: null,
    stageDir: null,
    tag: null,
    envFiles: [],
    only: null,
    skip: new Set(),
    allowPartial: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    switch (arg) {
      case '--help':
      case '-h':
        usage()
        process.exit(0)
      case '--publish':
        options.publish = true
        break
      case '--final':
      case '--publish-final':
        options.publish = true
        options.draft = false
        break
      case '--draft':
        options.publish = true
        options.draft = true
        break
      case '--promote-draft':
        options.publish = true
        options.draft = false
        options.promoteDraft = true
        break
      case '--publish-staged-draft':
        options.publishStagedDraft = true
        break
      case '--cargo-publish':
        options.cargoPublish = true
        break
      case '--skip-cargo-publish':
        options.skipCargoPublish = true
        break
      case '--skip-zapstore':
        options.skipZapstore = true
        break
      case '--skip-umbrel':
        options.skipUmbrel = true
        break
      case '--require-zapstore':
        options.requireZapstore = true
        break
      case '--dry-run':
        options.dryRun = true
        break
      case '--skip-verify':
        options.skipVerify = true
        break
      case '--reuse-gate-receipts':
        options.reuseGateReceipts = true
        break
      case '--complete-gate-from-receipts':
        options.completeGateFromReceipts = true
        break
      case '--tag':
        options.tag = normalizeTag(argv[++index] ?? '')
        break
      case '--release-tree':
        options.releaseTree = argv[++index] ?? ''
        break
      case '--stage-dir':
        options.stageDir = argv[++index] ?? ''
        break
      case '--env-file':
        options.envFiles.push(resolve(repoRoot, argv[++index] ?? ''))
        break
      case '--only':
        options.only = new Set(splitCsv(argv[++index] ?? ''))
        break
      case '--skip':
        for (const value of splitCsv(argv[++index] ?? '')) {
          options.skip.add(value)
        }
        break
      case '--allow-partial':
        options.allowPartial = true
        break
      default:
        throw new Error(`Unknown argument: ${arg}`)
    }
  }

  return options
}

function readOptionalEnvFiles(envFiles) {
  const loaded = {}
  const loadedPaths = []

  for (const envFile of envFiles) {
    if (!existsSync(envFile)) {
      continue
    }
    Object.assign(loaded, parseEnvFile(readFileSync(envFile, 'utf8')))
    loadedPaths.push(envFile)
  }

  return { loaded, loadedPaths }
}

function commandExists(command) {
  const result =
    process.platform === 'win32'
      ? spawnSync('where', [command], { stdio: 'ignore' })
      : spawnSync('sh', ['-lc', `command -v "${command}"`], { stdio: 'ignore' })

  return result.status === 0
}

function gitHeadEpoch() {
  const result = spawnSync('git', ['log', '-1', '--format=%ct', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  return result.status === 0 ? result.stdout.trim() : ''
}

function assertCleanReleaseSource(tag, expectedCommit = '') {
  const status = run(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { capture: true },
  )
  const headCommit = run('git', ['rev-parse', 'HEAD'], { capture: true })
  const taggedResult = spawnSync(
    'git',
    ['rev-parse', '-q', '--verify', `${normalizeTag(tag)}^{commit}`],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: 'pipe',
    },
  )
  const taggedCommit = taggedResult.status === 0 ? taggedResult.stdout.trim() : ''
  const candidate = validateCleanReleaseSource({
    status,
    headCommit,
    taggedCommit,
    tag,
  })
  if (expectedCommit && candidate !== expectedCommit) {
    throw new Error(
      `Release source changed during the build: started at ${expectedCommit}, now ${candidate}.`,
    )
  }
  return candidate
}

function gitTree(commit = 'HEAD') {
  return run('git', ['rev-parse', `${commit}^{tree}`], { capture: true })
}

function stagedDraftSourceContext(tag, manifest) {
  const status = run(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { capture: true },
  )
  const headCommit = run('git', ['rev-parse', 'HEAD'], { capture: true })
  const taggedResult = spawnSync(
    'git',
    ['rev-parse', '-q', '--verify', `${normalizeTag(tag)}^{commit}`],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: 'pipe',
    },
  )
  return {
    manifest,
    requestedTag: tag,
    workspaceTag: readWorkspaceVersionTag(readFileSync(rootCargoToml, 'utf8')),
    status,
    headCommit,
    taggedCommit: taggedResult.status === 0 ? taggedResult.stdout.trim() : '',
  }
}

function assertPublishableStagedDraftSource(tag, manifest) {
  const context = stagedDraftSourceContext(tag, manifest)
  return validatePromotableReleaseSource({
    ...context,
    // Draft publication deliberately precedes tag creation. Reuse the full
    // promotion validator while still rejecting a pre-existing mismatched tag.
    taggedCommit: context.taggedCommit || String(manifest.commit ?? '').trim(),
  })
}

function assertPromotableDraftSource(tag, manifest) {
  return validatePromotableReleaseSource(
    stagedDraftSourceContext(tag, manifest),
  )
}

function verifyStagedPublicationBundle({
  stageDir,
  tag,
  commit,
  tree,
}) {
  run(process.execPath, [
    join(repoRoot, 'scripts', 'verify-release-publication-bundle.mjs'),
    '--stage-dir',
    stageDir,
    '--tag',
    tag,
    '--commit',
    commit,
    '--tree',
    tree,
    '--require-draft',
  ])
}

function quote(arg) {
  const value = String(arg)
  return /[^\w./:-]/.test(value) ? JSON.stringify(value) : value
}

function envFlagEnabled(value) {
  return /^(1|true|yes|on)$/i.test(String(value ?? '').trim())
}

function macosCargoTargetDir(env = process.env) {
  const configured = String(env.NVPN_MACOS_CARGO_TARGET_DIR ?? '').trim()
  if (configured.length === 0) {
    return join(repoRoot, 'macos', '.build', 'cargo-target')
  }
  return resolve(repoRoot, configured)
}

function findFirstFile(root, matcher) {
  if (!existsSync(root)) {
    return null
  }

  const entries = readdirSync(root).sort()
  const match = entries.find((entry) => matcher(entry))
  return match ? join(root, match) : null
}

function run(
  command,
  args,
  {
    cwd = repoRoot,
    env = process.env,
    capture = false,
    input,
    dryRun = false,
  } = {},
) {
  const rendered = [command, ...args].map(quote).join(' ')
  console.log(`$ ${rendered}`)
  if (dryRun) {
    return ''
  }

  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    input,
    stdio: capture ? 'pipe' : 'inherit',
  })
  if (result.status !== 0) {
    const stderr = capture ? result.stderr.trim() : ''
    throw new Error(stderr || `${command} exited with status ${result.status ?? 'unknown'}`)
  }
  return capture ? result.stdout.trim() : ''
}

function resolveMacosSigningCertificateSha256(identitySha1) {
  const certificates = run(
    'security',
    ['find-certificate', '-a', '-p'],
    { capture: true },
  ).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []
  const matches = certificates.flatMap((certificate) => {
    const parsed = new X509Certificate(certificate)
    const sha1 = createHash('sha1').update(parsed.raw).digest('hex')
    return sha1 === identitySha1.toLowerCase()
      ? [createHash('sha256').update(parsed.raw).digest('hex')]
      : []
  })
  if (matches.length !== 1) {
    throw new Error(
      'macOS gate signing identity does not resolve to exactly one keychain certificate.',
    )
  }
  return matches[0]
}

const htreeReleaseMetadataPaths = [
  'release.json',
  'manifest.json',
  'notes.md',
]

function exactRegularFile(path, label) {
  const metadata = lstatSync(path)
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file.`)
  }
}

function exactContentBinding(bytes) {
  return {
    size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  }
}

function readValidatedReleaseStage(
  stageDir,
  { bindHtreeMetadata = false } = {},
) {
  const releaseJsonPath = join(stageDir, 'release.json')
  const manifestJsonPath = join(stageDir, 'manifest.json')
  if (!existsSync(releaseJsonPath) || !existsSync(manifestJsonPath)) {
    throw new Error(`No staged release manifest found at ${stageDir}. Run the draft release first or pass --stage-dir.`)
  }

  exactRegularFile(releaseJsonPath, 'Staged release.json')
  exactRegularFile(manifestJsonPath, 'Staged manifest.json')
  const releaseBytes = readFileSync(releaseJsonPath)
  const manifestBytes = readFileSync(manifestJsonPath)
  if (!releaseBytes.equals(manifestBytes)) {
    throw new Error('release.json and manifest.json differ in the staged release tree.')
  }

  const manifest = JSON.parse(releaseBytes.toString('utf8'))
  validateStagedReleaseTree(stageDir, manifest)
  if (!bindHtreeMetadata) {
    return { manifest, metadataBindings: null }
  }

  const notesPath = join(stageDir, 'notes.md')
  exactRegularFile(notesPath, 'Staged notes.md')
  return {
    manifest,
    metadataBindings: {
      'release.json': exactContentBinding(releaseBytes),
      'manifest.json': exactContentBinding(manifestBytes),
      'notes.md': exactContentBinding(readFileSync(notesPath)),
    },
  }
}

function readReleaseManifest(stageDir) {
  return readValidatedReleaseStage(stageDir).manifest
}

function verifyHtreeReleaseCid({
  cid,
  manifest,
  metadataBindings,
  dryRun,
}) {
  if (dryRun) {
    console.log(`Would verify ${manifest.assets.length} htree asset(s) from ${cid}`)
    return
  }

  for (const path of htreeReleaseMetadataPaths) {
    const binding = metadataBindings?.[path]
    if (
      !binding
      || !Number.isSafeInteger(binding.size)
      || binding.size < 0
      || !/^[0-9a-f]{64}$/.test(binding.sha256)
    ) {
      throw new Error(
        `No exact staged htree metadata binding exists for ${path}.`,
      )
    }
  }

  const paths = [
    ...htreeReleaseMetadataPaths,
    ...manifest.assets.map((asset) => asset.path),
  ]
  for (const path of paths) {
    const result = spawnSync('htree', ['cat', `${cid}/${path}`], {
      cwd: repoRoot,
      env: process.env,
      encoding: 'buffer',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 512 * 1024 * 1024,
    })
    if (result.status !== 0) {
      const stderr = result.stderr ? result.stderr.toString('utf8').trim() : ''
      throw new Error(`Published htree CID does not contain ${path}${stderr ? `: ${stderr}` : ''}`)
    }

    const metadata = metadataBindings?.[path]
    if (metadata && result.stdout.length !== metadata.size) {
      throw new Error(
        `Published htree CID size mismatch for ${path}: staged ${metadata.size} bytes, htree cat returned ${result.stdout.length} bytes.`,
      )
    }
    if (
      metadata
      && createHash('sha256').update(result.stdout).digest('hex')
        !== metadata.sha256
    ) {
      throw new Error(`Published htree CID SHA-256 mismatch for ${path}.`)
    }

    const asset = manifest.assets.find((candidate) => candidate.path === path)
    if (asset && result.stdout.length !== asset.size) {
      throw new Error(
        `Published htree CID size mismatch for ${path}: manifest ${asset.size} bytes, htree cat returned ${result.stdout.length} bytes.`,
      )
    }
    if (
      asset
      && createHash('sha256').update(result.stdout).digest('hex') !== asset.sha256
    ) {
      throw new Error(`Published htree CID SHA-256 mismatch for ${path}.`)
    }
  }
}

function writeUnixInstallScript(path) {
  writeFileSync(
    path,
    `#!/bin/bash
set -e

path_contains() {
  case ":\${PATH}:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

default_install_dir() {
  if [ "$(uname -s)" = "Darwin" ] && { [ -d /opt/homebrew/bin ] || path_contains /opt/homebrew/bin; }; then
    printf '%s\\n' /opt/homebrew/bin
  else
    printf '%s\\n' /usr/local/bin
  fi
}

INSTALL_DIR="\${1:-$(default_install_dir)}"
install -d "\${INSTALL_DIR}"
install -m 755 nvpn "\${INSTALL_DIR}/"
`,
  )
}

function writeUnixReadme(path) {
  writeFileSync(
    path,
    `nvpn - FIPS private mesh CLI
============================

Binary included:
  nvpn  - CLI control plane

Quick install:
  ./install.sh
  ./install.sh ~/.local/bin
`,
  )
}

function setTreeMtime(root, epochSeconds) {
  const epoch = Number(epochSeconds)
  if (!Number.isFinite(epoch)) {
    return
  }
  const when = new Date(epoch * 1000)
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name)
    if (entry.isDirectory()) {
      setTreeMtime(path, epochSeconds)
    }
    utimesSync(path, when, when)
  }
  utimesSync(root, when, when)
}

function packageUnixCliTarball({ binaryPath, targetTriple, tag, dryRun }) {
  const bundleDir = join(distDir, 'nvpn')
  if (!dryRun) {
    rmSync(bundleDir, { recursive: true, force: true })
    mkdirSync(bundleDir, { recursive: true })
    copyFileSync(binaryPath, join(bundleDir, 'nvpn'))
    writeUnixInstallScript(join(bundleDir, 'install.sh'))
    writeUnixReadme(join(bundleDir, 'README.txt'))
    setTreeMtime(bundleDir, process.env.SOURCE_DATE_EPOCH)
  }

  run('chmod', ['+x', join(bundleDir, 'install.sh')], { dryRun })

  const unversioned = join(distDir, `nvpn-${targetTriple}.tar.gz`)
  const versioned = join(distDir, `nvpn-${tag}-${targetTriple}.tar.gz`)
  const tarPath = unversioned.replace(/\.gz$/, '')
  run('tar', ['--no-xattrs', '-cf', tarPath, '-C', distDir, 'nvpn/README.txt', 'nvpn/install.sh', 'nvpn/nvpn'], {
    dryRun,
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  })
  run('gzip', ['-n', '-f', tarPath], { dryRun })
  if (!dryRun) {
    copyFileSync(unversioned, versioned)
  }
  return [unversioned, versioned]
}

function buildWindowsArtifacts({
  env,
  tag,
  dryRun,
  builtLines,
  candidateCommit,
  candidateTree,
  gateReceiptPath,
  installerReceiptPath,
  installerArtifactPath,
}) {
  const targets = splitCsv(
    env.NVPN_WINDOWS_CLI_TARGETS || 'x86_64-pc-windows-msvc',
  )
  if (
    targets.length !== 1
    || targets[0] !== 'x86_64-pc-windows-msvc'
  ) {
    throw new Error(
      'Windows publication only supports the x64 CLI payload exercised by the real Windows gate.',
    )
  }
  const guiTargets = splitCsv(env.NVPN_WINDOWS_GUI_TARGETS || 'x86_64-pc-windows-msvc')
  if (
    guiTargets.length !== 1
    || guiTargets[0] !== 'x86_64-pc-windows-msvc'
  ) {
    throw new Error(
      'Windows publication only supports the x64 installer exercised by the real Windows gate.',
    )
  }

  const installerName = `nostr-vpn-${tag}-windows-x64-setup.exe`
  const archiveName = `nvpn-${tag}-x86_64-pc-windows-msvc.zip`
  const retainedArchivePath = resolve(
    env.NVPN_WINDOWS_RELEASE_ARCHIVE_PATH
      || join(dirname(installerArtifactPath), archiveName),
  )
  if (dryRun) {
    builtLines.push('Reused the exact Windows installer and CLI payload exercised by the Windows VM gate.')
    return {}
  }

  const receipt = readRequiredJson(
    gateReceiptPath,
    'Windows exact-artifact gate receipt',
  )
  requireReceiptSource(receipt, {
    commit: candidateCommit,
    tree: candidateTree,
    candidateRoot: repoRoot,
    platform: 'windows',
    label: 'Windows exact-artifact gate receipt',
  })
  const installerReceipt = readRequiredJson(
    installerReceiptPath,
    'Windows exact installer gate receipt',
  )
  const exactWindowsFips = exactFipsPublicationCandidate({
    env,
    candidateRoot: repoRoot,
    label: 'Windows publication',
  })
  validateWindowsPublicationFipsReceipts({
    artifactReceipt: receipt,
    installerReceipt,
    expectedFips: exactWindowsFips,
  })
  const sealedInstaller = validateWindowsInstallerGateReceipt({
    receipt: installerReceipt,
    artifactReceipt: receipt,
    commit: receipt.appGitSha,
    tree: receipt.appGitTree,
    expectedTag: tag,
  })
  if (
    !existsSync(installerArtifactPath)
    || basename(installerArtifactPath) !== sealedInstaller.installerName
    || sha256FileSync(installerArtifactPath)
      !== sealedInstaller.installerSha256
    || statSync(installerArtifactPath).size
      !== sealedInstaller.installerSize
  ) {
    throw new Error(
      'Windows publication installer is not the exact locally retained installer exercised by the real gate.',
    )
  }
  const expected = sealedInstaller.payloads
  const installerPath = join(distDir, installerName)
  const archivePath = join(distDir, archiveName)
  exactRegularFile(retainedArchivePath, 'Windows exact CLI archive')
  const retainedArchiveSha256 = sha256FileSync(retainedArchivePath)
  mkdirSync(distDir, { recursive: true })
  copyFileSync(retainedArchivePath, archivePath)
  copyFileSync(installerArtifactPath, installerPath)
  if (
    sha256FileSync(archivePath) !== retainedArchiveSha256
    || sha256FileSync(installerPath) !== sealedInstaller.installerSha256
    || statSync(installerPath).size !== sealedInstaller.installerSize
  ) {
    throw new Error(
      'Windows exact retained artifacts changed while copying them into the publication directory.',
    )
  }
  validateExactZipMembers(
    archivePath,
    ['nvpn.exe', 'binaries/wintun.dll'],
  )
  if (
    commandOutputSha256('unzip', ['-p', archivePath, 'nvpn.exe'])
      !== expected.cli
    || commandOutputSha256(
      'unzip',
      ['-p', archivePath, 'binaries/wintun.dll'],
    ) !== expected.wintun
  ) {
    throw new Error(
      'Windows CLI archive differs from the exact Windows VM gate payload.',
    )
  }
  builtLines.push('Reused the exact Windows installer and CLI payload exercised by the Windows VM gate.')
  return {
    [installerName]: exactArtifactProof({
      artifactPath: installerPath,
      platform: 'windows',
      gateReceiptPath: installerReceiptPath,
      payloads: {
        app: expected.app,
        app_core: expected.appCore,
        cli: expected.cli,
        wintun: expected.wintun,
      },
    }),
    [archiveName]: exactArtifactProof({
      artifactPath: archivePath,
      platform: 'windows',
      gateReceiptPath,
      payloads: {
        cli: expected.cli,
        wintun: expected.wintun,
      },
    }),
  }
}

function buildLinuxArtifacts({
  env,
  tag,
  dryRun,
  builtLines,
  candidateCommit,
  candidateTree,
  testedReceiptPath,
  testedPackageInstallReceiptPath,
  gatedBundlePathReceipt,
  arm64CliArchivePath,
  arm64CliReceiptPath,
}) {
  const platform = env.NVPN_LINUX_DOCKER_PLATFORM || 'linux/amd64'
  const { linuxArchSuffix, muslTriple } = linuxReleaseTargetsForDockerPlatform(platform)
  if (platform !== 'linux/amd64') {
    throw new Error(
      'Public Linux artifacts require the exact x86_64 host bundle exercised by the Ubuntu VM gate.',
    )
  }
  const linuxDebName = `nostr-vpn-${tag}-linux-${linuxArchSuffix}.deb`

  let gatedBundle = ''
  let gateReceiptPath = ''
  let gateReceipt = null
  let packageInstallReceipt = null
  let bundleReceiptPath = ''
  let bundleReceiptSha256 = ''
  if (!dryRun) {
    if (!existsSync(gatedBundlePathReceipt)) {
      throw new Error(
        `Linux exact host-bundle path receipt is missing: ${gatedBundlePathReceipt}`,
      )
    }
    const bundleLines = readFileSync(gatedBundlePathReceipt, 'utf8')
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
    if (bundleLines.length !== 1) {
      throw new Error(
        'Linux exact host-bundle path receipt must contain one path.',
      )
    }
    gatedBundle = bundleLines[0]
    if (
      resolve(gatedBundle) !== gatedBundle
      || !existsSync(gatedBundle)
      || lstatSync(gatedBundle).isSymbolicLink()
      || !statSync(gatedBundle).isDirectory()
    ) {
      throw new Error(
        'Linux exact host-bundle path receipt points to an invalid directory.',
      )
    }
    bundleReceiptPath = join(gatedBundle, 'receipt.json')
    bundleReceiptSha256 = sha256FileSync(bundleReceiptPath)
    if (
      bundleReceiptSha256
      !== sha256FileSync(testedReceiptPath)
    ) {
      throw new Error(
        'Linux host bundle receipt differs from the exact bundle imported by the Ubuntu VM gate.',
      )
    }
    gateReceiptPath = testedReceiptPath
    gateReceipt = readRequiredJson(
      gateReceiptPath,
      'Linux exact-artifact gate receipt',
    )
    requireReceiptSource(gateReceipt, {
      commit: candidateCommit,
      tree: candidateTree,
      candidateRoot: repoRoot,
      platform: 'linux',
      label: 'Linux exact-artifact gate receipt',
    })
    packageInstallReceipt = readRequiredJson(
      testedPackageInstallReceiptPath,
      'Linux exact Debian package install receipt',
    )
    const expectedBundleReceiptSha256 = bundleReceiptSha256
    if (
      packageInstallReceipt.appGitSha !== gateReceipt.appGitSha
      || packageInstallReceipt.appGitTree !== gateReceipt.appGitTree
      || packageInstallReceipt.packageInstalledByDpkg !== true
      || packageInstallReceipt.installedStatus !== 'installed'
      || packageInstallReceipt.bundleReceiptSha256
        !== expectedBundleReceiptSha256
    ) {
      throw new Error(
        'Linux Debian package install receipt differs from the exact release candidate.',
      )
    }

  }

  if (dryRun) {
    builtLines.push('Reused exact-gated Linux x64 and native-smoked ARM64 artifacts.')
    return {}
  }

  const debPath = join(distDir, linuxDebName)
  const cliAssets = [
    join(distDir, `nvpn-${muslTriple}.tar.gz`),
    join(distDir, `nvpn-${tag}-${muslTriple}.tar.gz`),
  ]
  const expectedApp = gateReceipt.artifacts?.app?.sha256
  const expectedCli = gateReceipt.artifacts?.cli?.sha256
  const expectedDeb = gateReceipt.artifacts?.debianPackage?.sha256
  const expectedDebSize = gateReceipt.artifacts?.debianPackage?.size
  const expectedMuslCli = gateReceipt.artifacts?.muslCli?.sha256
  const expectedMuslArchive = gateReceipt.artifacts?.muslCliArchive?.sha256
  const expectedMuslArchiveSize = gateReceipt.artifacts?.muslCliArchive?.size
  for (const [name, digest] of Object.entries({
    app: expectedApp,
    cli: expectedCli,
    debian_package: expectedDeb,
    musl_cli: expectedMuslCli,
    musl_archive: expectedMuslArchive,
  })) {
    if (!/^[0-9a-f]{64}$/.test(String(digest ?? ''))) {
      throw new Error(`Linux gate receipt lacks the ${name} payload hash.`)
    }
  }
  if (
    packageInstallReceipt.debSha256 !== expectedDeb
    || packageInstallReceipt.debSize !== expectedDebSize
    || packageInstallReceipt.muslCliSha256 !== expectedMuslCli
    || packageInstallReceipt.muslArchiveSha256 !== expectedMuslArchive
  ) {
    throw new Error(
      'Linux exact package-install receipt does not match the sealed host bundle.',
    )
  }
  const gatedDebPath = join(gatedBundle, 'nostr-vpn.deb')
  const gatedMuslArchivePath = join(
    gatedBundle,
    'nvpn-x86_64-unknown-linux-musl.tar.gz',
  )
  const verificationPlan = linuxPublicationVerificationPlan({
    env,
    tag,
    candidateCommit,
    candidateTree,
    gateReceipt,
    packageInstallReceipt,
    bundlePath: gatedBundle,
    bundleReceiptPath,
    bundleReceiptSha256,
  })
  run(
    'python3',
    [verificationPlan.verifierPath, ...verificationPlan.verifierArgs],
    {
      cwd: verificationPlan.candidateRoot,
      env,
    },
  )
  if (
    sha256FileSync(bundleReceiptPath) !== bundleReceiptSha256
    || sha256FileSync(testedReceiptPath) !== bundleReceiptSha256
    || packageInstallReceipt.bundleReceiptSha256 !== bundleReceiptSha256
    || sha256FileSync(gatedDebPath) !== expectedDeb
    || statSync(gatedDebPath).size !== expectedDebSize
    || sha256FileSync(gatedMuslArchivePath) !== expectedMuslArchive
    || statSync(gatedMuslArchivePath).size !== expectedMuslArchiveSize
  ) {
    throw new Error(
      'Linux sealed publication artifacts changed after their Ubuntu VM gate.',
    )
  }
  mkdirSync(distDir, { recursive: true })
  replaceWithExactFileCopy(gatedDebPath, debPath)
  for (const cliAsset of cliAssets) {
    replaceWithExactFileCopy(gatedMuslArchivePath, cliAsset)
  }
  if (
    sha256FileSync(debPath) !== expectedDeb
    || statSync(debPath).size !== expectedDebSize
    || cliAssets.some(
      (path) =>
        sha256FileSync(path) !== expectedMuslArchive
        || statSync(path).size !== expectedMuslArchiveSize,
    )
  ) {
    throw new Error(
      'Linux publication copy differs from the exact Ubuntu VM-gated artifacts.',
    )
  }
  const proofs = {
    [basename(debPath)]: exactArtifactProof({
      artifactPath: debPath,
      platform: 'linux',
      gateReceiptPath: testedPackageInstallReceiptPath,
      payloads: {
        debian_package: expectedDeb,
        nostr_vpn: expectedApp,
        nvpn: expectedCli,
      },
    }),
  }
  for (const cliAsset of cliAssets) {
    proofs[basename(cliAsset)] = exactArtifactProof({
      artifactPath: cliAsset,
      platform: 'linux',
      gateReceiptPath,
      payloads: {
        musl_archive: expectedMuslArchive,
        nvpn_musl: expectedMuslCli,
      },
    })
  }
  const arm64Receipt = readRequiredJson(arm64CliReceiptPath, 'Linux ARM64 CLI receipt')
  const arm64 = validateLinuxArm64CliReceipt({
    receipt: arm64Receipt,
    archivePath: arm64CliArchivePath,
    candidateRoot: repoRoot,
    commit: candidateCommit,
    tree: candidateTree,
    expectedVersion: tag.replace(/^v/, '').split('+')[0],
  })
  if (
    arm64Receipt.appGitSha !== gateReceipt.appGitSha
    || arm64Receipt.appGitTree !== gateReceipt.appGitTree
  ) {
    throw new Error('Linux x64 and ARM64 artifacts have different product sources.')
  }
  for (const name of [
    'nvpn-aarch64-unknown-linux-musl.tar.gz',
    `nvpn-${tag}-aarch64-unknown-linux-musl.tar.gz`,
  ]) {
    const asset = join(distDir, name)
    replaceWithExactFileCopy(arm64CliArchivePath, asset)
    if (sha256FileSync(asset) !== arm64.archiveSha256) {
      throw new Error('Linux ARM64 publication copy changed.')
    }
    proofs[name] = exactArtifactProof({
      artifactPath: asset,
      platform: 'linux',
      gateReceiptPath: arm64CliReceiptPath,
      payloads: { musl_archive: arm64.archiveSha256, nvpn_musl: arm64.cliSha256 },
    })
  }
  builtLines.push('Reused exact-gated Linux x64 and native-smoked ARM64 artifacts.')
  return proofs
}

function ensureAndroidSdkEnv(env) {
  const updated = { ...env }
  if (!updated.ANDROID_SDK_ROOT) {
    const candidate = join(os.homedir(), 'Library', 'Android', 'sdk')
    if (existsSync(candidate)) {
      updated.ANDROID_SDK_ROOT = candidate
    }
  }
  if (!updated.ANDROID_HOME && updated.ANDROID_SDK_ROOT) {
    updated.ANDROID_HOME = updated.ANDROID_SDK_ROOT
  }
  if (!updated.ANDROID_NDK_HOME && updated.ANDROID_HOME) {
    const ndkRoot = join(updated.ANDROID_HOME, 'ndk')
    if (existsSync(ndkRoot)) {
      const versions = readdirSync(ndkRoot).sort((left, right) =>
        left.localeCompare(right, undefined, { numeric: true }),
      )
      const latest = versions.at(-1)
      if (latest) {
        updated.ANDROID_NDK_HOME = join(ndkRoot, latest)
      }
    }
  }
  if (!updated.NDK_HOME && updated.ANDROID_NDK_HOME) {
    updated.NDK_HOME = updated.ANDROID_NDK_HOME
  }
  return updated
}

function findAndroidBuildTool(env, toolName) {
  const sdkRoot = env.ANDROID_SDK_ROOT || env.ANDROID_HOME
  if (!sdkRoot) {
    return null
  }
  const buildToolsRoot = join(sdkRoot, 'build-tools')
  if (!existsSync(buildToolsRoot)) {
    return null
  }
  const versions = readdirSync(buildToolsRoot).sort((left, right) =>
    left.localeCompare(right, undefined, { numeric: true }),
  )
  for (const version of versions.reverse()) {
    const candidate = join(buildToolsRoot, version, toolName)
    if (existsSync(candidate)) {
      return candidate
    }
  }
  return null
}

function androidSigningIsComplete(env) {
  return Boolean(
    env.ANDROID_KEYSTORE_PATH &&
      env.ANDROID_KEYSTORE_PASSWORD &&
      env.ANDROID_KEY_ALIAS &&
      env.ANDROID_KEY_PASSWORD,
  )
}

function buildAndroidArtifacts({
  env,
  tag,
  dryRun,
  builtLines,
  gateReceiptPath,
  candidateCommit,
  candidateTree,
}) {
  const androidEnv = ensureAndroidSdkEnv(env)
  const sdkRoot = androidEnv.ANDROID_SDK_ROOT || androidEnv.ANDROID_HOME
  if (!sdkRoot) {
    throw new SkipStepError('Skipping Android artifacts because ANDROID_SDK_ROOT/ANDROID_HOME is not configured.')
  }
  if (!commandExists('cargo-ndk')) {
    throw new SkipStepError('Skipping Android artifacts because cargo-ndk is not on PATH.')
  }

  const installedTargets = run('rustup', ['target', 'list', '--installed'], {
    capture: true,
    dryRun,
  })
  if (!installedTargets.includes('aarch64-linux-android')) {
    run('rustup', ['target', 'add', 'aarch64-linux-android'], { dryRun })
  }

  const tempRoot = dryRun ? null : mkdtempSync(join(os.tmpdir(), 'nvpn-android-release-'))
  let wroteTempKeystore = false
  try {
    if (!androidEnv.ANDROID_KEYSTORE_PATH && androidEnv.ANDROID_KEYSTORE_B64 && tempRoot) {
      androidEnv.ANDROID_KEYSTORE_PATH = join(tempRoot, 'upload-keystore.jks')
      writeFileSync(androidEnv.ANDROID_KEYSTORE_PATH, Buffer.from(androidEnv.ANDROID_KEYSTORE_B64, 'base64'))
      wroteTempKeystore = true
    }

    const signed = androidSigningIsComplete(androidEnv)
    if (!signed && !envFlagEnabled(androidEnv.NVPN_ALLOW_UNSIGNED_ANDROID)) {
      throw new Error(
        'Android release signing is not configured. Set ANDROID_KEYSTORE_PATH, ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS, and ANDROID_KEY_PASSWORD, or set NVPN_ALLOW_UNSIGNED_ANDROID=1 for an explicitly unsigned dev artifact.',
      )
    }

    // The release gate built the Play AAB first, derived the installable APK
    // from it with pinned bundletool, and physically exercised that APK.
    // Reuse both sealed artifacts; rebuilding either here would break the
    // relationship proven on the Pixel.
    const testedApkPath = join(
      repoRoot,
      'android',
      'app',
      'build',
      'outputs',
      'apk',
      'release',
      'app-release.apk',
    )
    const bundleReceiptPath = join(
      repoRoot,
      'android',
      'app',
      'build',
      'outputs',
      'bundle',
      'release',
      'physical-gate-artifact.json',
    )
    const aabPath = findFirstFile(
      join(repoRoot, 'android', 'app', 'build', 'outputs', 'bundle', 'release'),
      (entry) => entry.endsWith('.aab'),
    )
    if (
      !dryRun
      && (
        !existsSync(testedApkPath)
        || !aabPath
        || !existsSync(bundleReceiptPath)
      )
    ) {
      throw new Error(
        'Expected gate-tested AAB-derived Android APK and signed AAB were not produced.',
      )
    }

    const apkDest = join(distDir, androidReleaseAssetName(tag, { extension: 'apk', signed }))
    const aabDest = join(distDir, androidReleaseAssetName(tag, { extension: 'aab', signed }))
    let gate
    if (!dryRun) {
      if (!gateReceiptPath || !existsSync(gateReceiptPath)) {
        throw new Error(
          'Physical Android release-gate receipt is missing; refusing to publish an untested APK.',
        )
      }
      for (const [path, label] of [
        [gateReceiptPath, 'Physical Android release-gate receipt'],
        [bundleReceiptPath, 'Android AAB-derived APK receipt'],
        [testedApkPath, 'Gate-tested Android APK'],
        [aabPath, 'Signed Android AAB'],
      ]) exactRegularFile(path, label)
      let receipt
      try {
        receipt = JSON.parse(readFileSync(gateReceiptPath, 'utf8'))
      } catch {
        throw new Error('Physical Android release-gate receipt is not valid JSON.')
      }
      let bundleReceipt
      try {
        bundleReceipt = JSON.parse(readFileSync(bundleReceiptPath, 'utf8'))
      } catch {
        throw new Error('Android AAB-derived APK receipt is not valid JSON.')
      }
      const aabSha256 = sha256FileSync(aabPath)
      const apkSha256 = sha256FileSync(testedApkPath)
      const sourceEquivalence = requireReceiptSource(receipt, {
        commit: candidateCommit,
        tree: candidateTree,
        candidateRoot: repoRoot,
        platform: 'android',
        label: 'Physical Android release-gate receipt',
      })
      validateAndroidBundleRelationship(bundleReceipt, {
        receipt,
        receiptSha256: sha256FileSync(bundleReceiptPath),
        apkSha256,
        aabSha256,
      })
      gate = validateAndroidReleaseGateReceipt(receipt, {
        apkSha256,
        aabSha256,
        expectedAppGitSha: receipt.appGitSha,
        expectedAppGitTree: receipt.appGitTree,
        expectedPackage:
          String(androidEnv.NVPN_ANDROID_PACKAGE_ID || '').trim()
          || 'fi.siriusbusiness.nvpn',
      })
      if (sourceEquivalence) {
        gate.sourceEquivalence = sourceEquivalence
      }
      mkdirSync(distDir, { recursive: true })
      copyFileSync(testedApkPath, apkDest)
      copyFileSync(aabPath, aabDest)
      if (sha256FileSync(apkDest) !== gate.apkSha256) {
        throw new Error('Copied Android release APK differs from the physical-gate artifact.')
      }
      if (sha256FileSync(aabDest) !== gate.aabSha256) {
        throw new Error('Copied Android Play AAB differs from the physical-gate artifact.')
      }
    }

    if (signed) {
      const apksigner = findAndroidBuildTool(androidEnv, 'apksigner')
      if (apksigner) {
        run(apksigner, ['verify', '--verbose', apkDest], { dryRun })
      }
    }

    builtLines.push(
      signed
        ? 'Reused the signed Play AAB and its physical-gate-sealed bundletool-derived APK.'
        : 'Reused the Play AAB and its physical-gate-sealed bundletool-derived APK.',
    )
    if (dryRun) {
      return { gate: null, proofs: {} }
    }
    const runtimePayloads = androidRuntimePayloads(apkDest, aabDest)
    return {
      gate,
      proofs: {
        [basename(apkDest)]: exactArtifactProof({
          artifactPath: apkDest,
          platform: 'android',
          gateReceiptPath,
          payloads: runtimePayloads,
        }),
        [basename(aabDest)]: exactArtifactProof({
          artifactPath: aabDest,
          platform: 'android',
          gateReceiptPath,
          payloads: runtimePayloads,
        }),
      },
    }
  } finally {
    if (wroteTempKeystore && androidEnv.ANDROID_KEYSTORE_PATH) {
      rmSync(androidEnv.ANDROID_KEYSTORE_PATH, { force: true })
    }
    if (tempRoot) {
      rmSync(tempRoot, { recursive: true, force: true })
    }
  }
}

function buildMacosArtifacts({
  tag,
  dryRun,
  builtLines,
  candidateCommit,
  candidateTree,
  gateReceiptPath,
  gatedAppPath,
}) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new SkipStepError('Skipping macOS artifacts because the host is not Apple Silicon macOS.')
  }

  const env = {
    ...process.env,
    NVPN_MACOS_CARGO_TARGET_DIR: macosCargoTargetDir(process.env),
    NVPN_MACOS_RUST_PROFILE: 'release',
    NVPN_MACOS_XCODE_CONFIGURATION: 'Release',
    NVPN_MACOS_RUST_TARGETS: 'aarch64-apple-darwin',
    NVPN_RELEASE_TAG: tag,
    NVPN_MACOS_REQUIRE_SIGNING: '1',
    NVPN_MACOS_REQUIRE_NOTARIZATION: '1',
  }
  let gateSource = { commit: candidateCommit, tree: candidateTree }
  if (!dryRun) {
    const gateReceipt = readRequiredJson(
      gateReceiptPath,
      'macOS exact-artifact gate receipt',
    )
    requireReceiptSource(gateReceipt, {
      commit: candidateCommit,
      tree: candidateTree,
      candidateRoot: repoRoot,
      platform: 'macos',
      label: 'macOS exact-artifact gate receipt',
    })
    const gateSigning = validateMacosGateSigningIdentity({
      receipt: gateReceipt,
      codesigningIdentities: run(
        'security',
        ['find-identity', '-v', '-p', 'codesigning'],
        { capture: true },
      ),
      resolvedCertificateSha256: resolveMacosSigningCertificateSha256(
        String(gateReceipt.signingIdentitySha1 ?? '').trim(),
      ),
    })
    env.MACOS_SIGNING_IDENTITY = gateSigning.identitySha1
    gateSource = {
      commit: gateReceipt.appGitSha,
      tree: gateReceipt.appGitTree,
    }
    rmSync(join(distDir, `nostr-vpn-${tag}-macos-arm64.zip`), { force: true })
    if (!existsSync(gatedAppPath)) {
      throw new Error(
        `Gate-tested macOS Release app is missing: ${gatedAppPath}`,
      )
    }
    const releaseApp = join(distDir, 'macos', 'Nostr VPN.app')
    rmSync(releaseApp, { recursive: true, force: true })
    mkdirSync(dirname(releaseApp), { recursive: true })
    run('ditto', [gatedAppPath, releaseApp])
    run(
      'python3',
      [
        join(repoRoot, 'scripts', 'macos_release_join_artifact.py'),
        'validate-published-app',
        '--receipt',
        gateReceiptPath,
        '--app',
        releaseApp,
        '--expected-app-head',
        gateSource.commit,
        '--expected-app-tree',
        gateSource.tree,
        '--require-gate-bundle-tree',
      ],
    )
  }
  run(
    'bash',
    [join(repoRoot, 'scripts', 'macos-build'), 'macos-release-artifacts'],
    {
      env: {
        ...env,
        NVPN_MACOS_FORCE_REBUILD_APP: '0',
      },
      dryRun,
    },
  )

  const gatedCli = join(
    gatedAppPath,
    'Contents',
    'Resources',
    'nvpn',
  )
  const cliAssets = packageUnixCliTarball({
    binaryPath: gatedCli,
    targetTriple: 'aarch64-apple-darwin',
    tag,
    dryRun,
  })
  if (dryRun) {
    builtLines.push('Reused the gate-tested Apple Silicon CLI.')
    builtLines.push('Packaged the gate-tested signed macOS app for notarized distribution.')
    return {}
  }

  const receipt = readRequiredJson(
    gateReceiptPath,
    'macOS exact-artifact gate receipt',
  )
  const releaseApp = join(distDir, 'macos', 'Nostr VPN.app')
  const updater = join(
    distDir,
    `nostr-vpn-${tag}-macos-arm64.app.tar.gz`,
  )
  const dmg = join(distDir, `nostr-vpn-${tag}-macos-arm64.dmg`)
  run(
    'bash',
    [
      join(repoRoot, 'scripts', 'verify-macos-release-publication-artifacts.sh'),
      gateReceiptPath,
      releaseApp,
      updater,
      dmg,
      gateSource.commit,
      gateSource.tree,
      join(repoRoot, 'scripts', 'macos_release_join_artifact.py'),
    ],
  )

  const appPayload = {
    app_executable: receipt.appExecutableSha256,
  }
  const cliPayloadSha256 = sha256FileSync(gatedCli)
  const proofs = {
    [basename(dmg)]: exactArtifactProof({
      artifactPath: dmg,
      platform: 'macos',
      gateReceiptPath,
      payloads: appPayload,
    }),
    [basename(updater)]: exactArtifactProof({
      artifactPath: updater,
      platform: 'macos',
      gateReceiptPath,
      payloads: appPayload,
    }),
  }
  for (const cliAsset of cliAssets) {
    const packagedCliSha256 = commandOutputSha256(
      'tar',
      ['-xOf', cliAsset, 'nvpn/nvpn'],
    )
    if (packagedCliSha256 !== cliPayloadSha256) {
      throw new Error(
        `macOS CLI archive ${basename(cliAsset)} differs from the gate-tested app payload.`,
      )
    }
    proofs[basename(cliAsset)] = exactArtifactProof({
      artifactPath: cliAsset,
      platform: 'macos',
      gateReceiptPath,
      payloads: { nvpn: cliPayloadSha256 },
    })
  }
  builtLines.push('Built Apple Silicon CLI locally.')
  builtLines.push('Packaged the gate-tested signed and notarized Apple Silicon app.')
  return proofs
}

function buildIosArtifacts({
  tag,
  dryRun,
  builtLines,
  releaseGateLogDir,
  candidateCommit,
  candidateTree,
}) {
  if (process.platform !== 'darwin') {
    throw new SkipStepError('Skipping iOS artifacts because the host is not macOS.')
  }
  if (dryRun) {
    run('bash', [join(repoRoot, 'scripts', 'ios-build'), 'ios-export'], {
      env: {
        ...process.env,
        NVPN_RELEASE_TAG: tag,
        NVPN_IOS_INTERNAL_ONLY: 'false',
        NVPN_RELEASE_IOS_FROZEN_ARCHIVE: '1',
        NVPN_RELEASE_GATE_LOG_DIR: releaseGateLogDir,
      },
      dryRun: true,
    })
    builtLines.push(`Verified and exported iOS ${tag} without uploading it.`)
    return null
  }
  const archiveReceipt = readRequiredJson(
    join(repoRoot, 'dist', 'ios', 'frozen', 'archive-receipt.json'),
    'Frozen iOS archive receipt',
  )
  const sourceEquivalence = requireReceiptSource(archiveReceipt, {
    commit: candidateCommit,
    tree: candidateTree,
    label: 'Frozen iOS archive receipt',
    candidateRoot: repoRoot,
    platform: 'ios',
  })
  const env = {
    ...process.env,
    NVPN_RELEASE_TAG: tag,
    NVPN_IOS_INTERNAL_ONLY: 'false',
    NVPN_RELEASE_IOS_FROZEN_ARCHIVE: '1',
    NVPN_RELEASE_GATE_LOG_DIR: releaseGateLogDir,
  }
  // Ordinary staging is local-only. It verifies the physically tested frozen
  // archive and exports its exact App Store IPA without contacting Apple.
  // Upload/attach/submission entry points require the exact-source mutation gate.
  if (sourceEquivalence) {
    const temporaryRoot = mkdtempSync(join(os.tmpdir(), 'nvpn-ios-export-source-'))
    const sourceRoot = join(temporaryRoot, 'source')
    let worktreeAdded = false
    try {
      run('git', [
        'worktree', 'add', '--detach', sourceRoot, archiveReceipt.appGitSha,
      ])
      worktreeAdded = true
      for (const name of ['dist', 'artifacts']) {
        const externalRoot = join(repoRoot, name)
        if (!existsSync(externalRoot)) continue
        const linkRoot = join(sourceRoot, name)
        mkdirSync(linkRoot)
        for (const entry of readdirSync(externalRoot)) {
          symlinkSync(
            join(externalRoot, entry),
            join(linkRoot, entry),
          )
        }
      }
      run('bash', [join(repoRoot, 'scripts', 'ios-build'), 'ios-export'], {
        cwd: sourceRoot,
        env: {
          ...env,
          NVPN_BUILD_GIT_SHA: archiveReceipt.appGitSha,
          NVPN_IOS_RELEASE_SOURCE_ROOT: sourceRoot,
        },
      })
    } finally {
      for (const name of ['dist', 'artifacts']) {
        rmSync(join(sourceRoot, name), { recursive: true, force: true })
      }
      if (worktreeAdded) {
        run('git', ['worktree', 'remove', sourceRoot], { capture: true })
      }
      rmSync(temporaryRoot, { recursive: true, force: true })
    }
  } else {
    run('bash', [join(repoRoot, 'scripts', 'ios-build'), 'ios-export'], { env })
  }
  builtLines.push(`Verified and exported iOS ${tag} without uploading it.`)

  const exportDir = join(repoRoot, 'dist', 'ios', 'export')
  const ipaNames = readdirSync(exportDir)
    .filter((name) => name.endsWith('.ipa'))
    .sort()
  if (ipaNames.length !== 1) {
    throw new Error(
      `Expected exactly one frozen App Store IPA; found ${ipaNames.length}.`,
    )
  }
  const ipaPath = join(exportDir, ipaNames[0])
  const receiptPath = join(
    repoRoot,
    'dist',
    'ios',
    'frozen',
    'app-store-receipt.json',
  )
  const receipt = readRequiredJson(
    receiptPath,
    'Frozen iOS App Store export receipt',
  )
  const identity = receipt.identity ?? {}
  const signing = receipt.signing ?? {}
  const expectedVersion = semverFromTag(tag)
  if (
    receipt.receiptSchema !== 1
    || receipt.artifactType !== 'iOS export from frozen xcarchive'
    || receipt.distribution !== 'app-store-connect'
    || receipt.appGitSha !== archiveReceipt.appGitSha
    || receipt.appGitTree !== archiveReceipt.appGitTree
    || identity.appBuildGitSha !== archiveReceipt.appGitSha
    || identity.packetTunnelBuildGitSha !== archiveReceipt.appGitSha
    || identity.appBundleIdentifier !== 'fi.siriusbusiness.nvpn'
    || identity.marketingVersion !== expectedVersion
    || !/^[1-9][0-9]*$/.test(String(identity.buildNumber ?? ''))
    || !/^[A-Z0-9]{10}$/.test(
      String(signing.signingTeamIdentifier ?? ''),
    )
    || !/^[0-9a-f]{64}$/.test(
      String(signing.signerCertificateSha256 ?? ''),
    )
    || !/^[0-9a-f]{64}$/.test(String(receipt.ipaSha256 ?? ''))
    || receipt.ipaSha256 !== sha256FileSync(ipaPath)
  ) {
    throw new Error(
      'Frozen iOS App Store export is not exact production release evidence.',
    )
  }
  return {
    receipt_schema: receipt.receiptSchema,
    app_git_sha: receipt.appGitSha,
    app_git_tree: receipt.appGitTree,
    bundle_id: identity.appBundleIdentifier,
    marketing_version: identity.marketingVersion,
    build_number: String(identity.buildNumber),
    ipa_sha256: receipt.ipaSha256,
    ipa_size: statSync(ipaPath).size,
    export_receipt_sha256: sha256FileSync(receiptPath),
    signing_team_id: signing.signingTeamIdentifier,
    signer_certificate_sha256: signing.signerCertificateSha256,
    source_equivalence: sourceEquivalence,
  }
}

/**
 * Sync platform-native version metadata (xcodeproj MARKETING_VERSION, Android
 * versionName/versionCode, linux crate's [package].version) to the Cargo
 * workspace version. The GUIs themselves read versions through the FFI's
 * CARGO_PKG_VERSION fallback, but the OS-level metadata (Finder Get Info,
 * About panel, Play Store) needs these bumped before each release.
 */
function syncPlatformVersions({ env, tag, dryRun, builtLines }) {
  const targets = [
    { path: join(repoRoot, 'macos', 'NostrVpnMac.xcodeproj', 'project.pbxproj'), bump: bumpPbxprojMarketingVersion },
    { path: join(repoRoot, 'ios', 'NostrVpnIos.xcodeproj', 'project.pbxproj'), bump: bumpPbxprojMarketingVersion },
    {
      path: join(repoRoot, 'android', 'app', 'build.gradle.kts'),
      bump: (text, version) =>
        bumpAndroidGradleVersion(text, version, {
          versionCode: env.NVPN_ANDROID_VERSION_CODE,
        }),
    },
    { path: join(repoRoot, 'linux', 'Cargo.toml'), bump: bumpCargoPackageVersion },
  ]
  const updated = []
  for (const { path, bump } of targets) {
    if (!existsSync(path)) {
      continue
    }
    const original = readFileSync(path, 'utf8')
    const next = bump(original, tag)
    if (next === original) {
      continue
    }
    if (!dryRun) {
      writeFileSync(path, next)
    }
    updated.push(path.replace(`${repoRoot}/`, ''))
  }
  if (updated.length > 0) {
    builtLines.push(`Synced platform versions to ${tag}: ${updated.join(', ')}.`)
  } else {
    builtLines.push(`Platform versions already at ${tag}.`)
  }
}

function runVerify({ dryRun, builtLines, releaseGateLogDir, tag }) {
  const env = {
    ...process.env,
    NVPN_RELEASE_GATE_LOG_DIR: releaseGateLogDir,
    NVPN_RELEASE_GATE_REQUIRE_COMPLETE: '1',
    NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E: '1',
    NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E: '1',
    NVPN_RELEASE_GATE_MOBILE_JOIN_E2E: '1',
    NVPN_RELEASE_GATE_ANDROID_LEGACY_REPLACEMENT_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE: '1',
    NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E: '1',
    NVPN_RELEASE_GATE_WINDOWS_MOBILE_JOIN_E2E: '1',
    NVPN_WINDOWS_APP_SMOKE_TAG: tag,
    NVPN_RELEASE_GATE_MACOS_MANUAL_JOIN_UI_E2E: '1',
    NVPN_RELEASE_GATE_MACOS_DNS_UI_E2E: '1',
    NVPN_RELEASE_GATE_MACOS_SERVICE_TOGGLE_E2E: '1',
    NVPN_RELEASE_GATE_MACOS_GUI_SMOKE: '1',
    NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU: '1',
    NVPN_RELEASE_GATE_LINUX_MANUAL_JOIN_UI_E2E: '1',
    NVPN_RELEASE_GATE_LINUX_DNS_UI_E2E: '1',
    NVPN_RELEASE_GATE_LINUX_SERVICE_TOGGLE_E2E: '1',
    NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E: '1',
    NVPN_RELEASE_GATE_LINUX_MOBILE_JOIN_E2E: '1',
    NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E: '1',
    NVPN_RELEASE_IOS_FROZEN_ARCHIVE: '1',
  }
  run('./scripts/release-gate.sh', [], { env, dryRun })
  builtLines.push('Ran release gate: sync-versions, fmt, clippy, tests, FIPS Docker e2e, WireGuard exit Docker/platform e2e, real Android/iOS physical underlay changes, real Windows/Linux desktop underlay changes, isolated macOS VM network/service proofs, and desktop launch smokes.')
}

function buildStartosArtifacts({
  env,
  tag,
  dryRun,
  builtLines,
  releaseGateSummaryPath,
}) {
  const prebuiltArtifactDir = String(
    env.NVPN_RELEASE_STARTOS_ARTIFACT_DIR ?? '',
  ).trim()
  let prebuiltPackages = null
  if (!prebuiltArtifactDir) {
    run(
      'node',
      [
        join(repoRoot, 'scripts', 'startos-release.mjs'),
        '--tag',
        tag,
        '--output-dir',
        distDir,
      ],
      { dryRun },
    )
    builtLines.push('Built signed StartOS packages for x86_64 and aarch64.')
  } else if (dryRun) {
    builtLines.push('Would reuse inspected prebuilt StartOS packages for x86_64 and aarch64.')
  } else {
    const sourceDir = realpathSync(prebuiltArtifactDir)
    prebuiltPackages = ['x86_64', 'aarch64'].map((arch) => {
      const sourcePath = join(
        sourceDir,
        `nostr-vpn-${tag}-startos-${arch}.s9pk`,
      )
      if (!existsSync(sourcePath) || !lstatSync(sourcePath).isFile()) {
        throw new Error(`Prebuilt StartOS ${arch} package is missing or invalid.`)
      }
      return {
        arch,
        sourcePath,
        digest: sha256FileSync(sourcePath),
        inspection: inspectStartosReleasePackage({ packagePath: sourcePath, arch, tag }),
      }
    })
  }
  if (dryRun) {
    return {}
  }
  if (prebuiltPackages) {
    mkdirSync(distDir, { recursive: true })
    builtLines.push('Reused inspected prebuilt StartOS packages for x86_64 and aarch64.')
  }
  const proofs = {}
  for (const arch of ['x86_64', 'aarch64']) {
    const prebuilt = prebuiltPackages?.find((entry) => entry.arch === arch)
    const path = join(
      distDir,
      `nostr-vpn-${tag}-startos-${arch}.s9pk`,
    )
    if (prebuilt) copyFileSync(prebuilt.sourcePath, path)
    const digest = sha256FileSync(path)
    const inspection = inspectStartosReleasePackage({
      packagePath: path,
      arch,
      tag,
    })
    if (
      prebuilt
      && (
        digest !== prebuilt.digest
        || inspection.manifestSha256 !== prebuilt.inspection.manifestSha256
      )
    ) {
      throw new Error(`Prebuilt StartOS ${arch} package changed while staging.`)
    }
    proofs[basename(path)] = exactArtifactProof({
      artifactPath: path,
      platform: 'startos',
      gateReceiptPath: releaseGateSummaryPath,
      verification: 'post-build-exact-package-gate',
      postBuildValidator: startosExactPackageValidator,
      payloads: {
        manifest_json: inspection.manifestSha256,
        package: digest,
      },
    })
  }
  return proofs
}

function shouldRunStep(step, options) {
  if (options.skipVerify && step === 'verify') {
    return false
  }
  if (options.only && !options.only.has(step)) {
    return false
  }
  return !options.skip.has(step)
}

function collectReleaseAssetPaths(tag) {
  if (!existsSync(distDir)) {
    return []
  }

  const versionedNames = new Set(
    readdirSync(distDir).filter((entry) => entry.includes(`-${tag}-`) || entry.includes(`${tag}-`)),
  )
  const paths = []

  for (const entry of readdirSync(distDir).sort()) {
    if (entry === `nostr-vpn-${tag}-macos-arm64.zip`) {
      continue
    }
    const fullPath = join(distDir, entry)
    if (!statSync(fullPath).isFile()) {
      continue
    }
    if (entry.includes(tag)) {
      paths.push(fullPath)
      continue
    }
    const companionPattern = versionlessCliAssets.get(entry)
    if (companionPattern && versionedNames.has(companionPattern.replace('{tag}', tag))) {
      paths.push(fullPath)
    }
  }

  return paths
}

function writeReleaseNotes({ tag, stageDir, dryRun }) {
  const args = [
    join(repoRoot, 'scripts', 'render-release-notes.mjs'),
    '--tag',
    tag,
    '--asset-dir',
    join(stageDir, 'assets'),
    '--changelog',
    changelogPath,
    '--out',
    join(stageDir, 'notes.md'),
  ]

  run('node', args, { dryRun })
}

function stageRelease({
  tag,
  commit,
  tree,
  stageDir,
  builtLines,
  skippedLines,
  dryRun,
  requireCompleteAppRelease,
  draft,
  androidReleaseGate,
  iosAppStoreGate,
  releaseGateEvidence,
  artifactProofs,
}) {
  const assetPaths = collectReleaseAssetPaths(tag)
  const assetNames = assetPaths.map((assetPath) => basename(assetPath))
  validateReleaseAssetSet(assetNames, { requireCompleteAppRelease })

  if (dryRun) {
    console.log(`Would stage ${assetPaths.length} currently visible asset(s) into ${stageDir}`)
    return {
      assetPaths,
      stageDir,
      stagedAndroidApkPath: join(
        stageDir,
        'assets',
        androidReleaseAssetName(tag),
      ),
    }
  }

  if (assetPaths.length === 0) {
    throw new Error(`No dist assets found for ${tag}.`)
  }

  rmSync(stageDir, { recursive: true, force: true })
  mkdirSync(join(stageDir, 'assets'), { recursive: true })

  const stagedAssetPaths = []
  for (const assetPath of assetPaths) {
    const stagedPath = join(stageDir, 'assets', basename(assetPath))
    copyFileSync(assetPath, stagedPath, constants.COPYFILE_FICLONE)
    stagedAssetPaths.push(stagedPath)
  }

  let androidGateManifest = null
  let stagedAndroidApkPath = null
  if (androidReleaseGate) {
    const apkName = androidReleaseAssetName(tag)
    stagedAndroidApkPath = join(stageDir, 'assets', apkName)
    if (!existsSync(stagedAndroidApkPath)) {
      throw new Error(`Physical-gate Android APK is missing from the staged release: ${apkName}`)
    }
    if (
      sha256FileSync(stagedAndroidApkPath) !== androidReleaseGate.apkSha256
    ) {
      throw new Error('Physical Android gate provenance does not match the staged APK.')
    }
    androidGateManifest = {
      receipt_schema: androidReleaseGate.receiptSchema,
      apk_path: `assets/${apkName}`,
      apk_sha256: androidReleaseGate.apkSha256,
      app_git_sha: androidReleaseGate.appGitSha,
      app_git_tree: androidReleaseGate.appGitTree,
      package: androidReleaseGate.package,
      signer_certificate_sha256: androidReleaseGate.signerCertificateSha256,
      ...(androidReleaseGate.sourceEquivalence
        ? { source_equivalence: androidReleaseGate.sourceEquivalence }
        : {}),
    }
  } else if (requireCompleteAppRelease) {
    throw new Error(
      'Complete release staging requires physical Android gate provenance.',
    )
  }

  const createdAt = Math.floor(Date.now() / 1000)
  const manifest = buildReleaseManifest({
    tag,
    commit,
    createdAt,
    assetPaths: stagedAssetPaths,
    draft,
    androidReleaseGate: androidGateManifest,
  })
  if (iosAppStoreGate) {
    manifest.ios_app_store_gate = iosAppStoreGate
  } else if (requireCompleteAppRelease) {
    throw new Error(
      'Complete release staging requires a frozen iOS App Store export.',
    )
  }
  if (requireCompleteAppRelease) {
    if (!releaseGateEvidence) {
      throw new Error(
        'Complete release staging requires the real platform-gate evidence.',
      )
    }
    manifest.release_gate_attestation = buildReleaseGateAttestation({
      commit,
      tree,
      assets: manifest.assets,
      assetProofs: Object.fromEntries(
        manifest.assets.map((asset) => {
          const proof = artifactProofs?.[asset.name]
          if (!proof) {
            throw new Error(
              `Release asset ${asset.name} has no exact platform-gate proof.`,
            )
          }
          return [asset.path, proof]
        }),
      ),
      ...releaseGateEvidence,
    })
  }

  for (const [fileName, text] of buildReleaseManifestFiles(manifest)) {
    writeFileSync(join(stageDir, fileName), text)
  }
  writeReleaseNotes({ tag, stageDir, dryRun })
  validateStagedReleaseTree(stageDir, manifest)

  return { assetPaths, stageDir, stagedAndroidApkPath }
}

function publishRelease({
  stageDir,
  releaseTree,
  tag,
  draft,
  dryRun,
  beforeMutation = () => {},
}) {
  if (dryRun) {
    console.log(`Would publish ${tag} from ${stageDir} into ${releaseTree}`)
    return 'dry-run'
  }

  const {
    manifest,
    metadataBindings,
  } = readValidatedReleaseStage(stageDir, {
    bindHtreeMetadata: true,
  })
  if (!draft) {
    validatePromotableReleaseManifest(manifest)
  }
  const addOutput = run('htree', ['add', stageDir], { capture: true, dryRun })
  const match = addOutput.match(/^\s*url:\s*(\S+)/m)
  if (!match) {
    throw new Error('Could not parse htree add output for release CID.')
  }

  const cid = match[1]
  beforeMutation()
  run('htree', ['push', '--force', cid], { dryRun })
  verifyHtreeReleaseCid({
    cid,
    manifest,
    metadataBindings,
    dryRun,
  })
  const args = ['release', 'publish', releaseTree, tag, cid]
  if (draft) {
    args.push('--draft')
  }
  beforeMutation()
  run('htree', args, { dryRun })
  return cid
}

function promoteStagedDraft({
  stageDir,
  releaseTree,
  tag,
  dryRun,
  beforeMutation = () => {},
}) {
  if (dryRun) {
    console.log(`Would promote staged draft ${tag} from ${stageDir} into ${releaseTree}`)
    return {
      cid: 'dry-run',
      stagedAndroidApkPath: join(
        stageDir,
        'assets',
        androidReleaseAssetName(tag),
      ),
    }
  }

  const stagedManifest = readReleaseManifest(stageDir)
  validatePromotableReleaseManifest(stagedManifest)
  assertPromotableDraftSource(tag, stagedManifest)
  const stagedAndroidApkPath = join(
    stageDir,
    stagedManifest.android_release_gate.apk_path,
  )

  const finalStageParent = mkdtempSync(
    join(os.tmpdir(), 'nvpn-final-release-stage-'),
  )
  const finalStageDir = join(finalStageParent, 'stage')
  try {
    cpSync(stageDir, finalStageDir, {
      // Independent copies can share storage on filesystems with reflinks.
      mode: constants.COPYFILE_FICLONE,
      recursive: true,
      errorOnExist: true,
      force: false,
    })
    for (const name of ['release.json', 'manifest.json']) {
      const path = join(finalStageDir, name)
      const manifest = JSON.parse(readFileSync(path, 'utf8'))
      manifest.draft = false
      writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`)
    }
    const finalManifest = readReleaseManifest(finalStageDir)
    return {
      cid: publishRelease({
        stageDir: finalStageDir,
        releaseTree,
        tag,
        draft: false,
        dryRun,
        beforeMutation,
      }),
      finalManifest,
      stagedAndroidApkPath,
    }
  } finally {
    rmSync(finalStageParent, { recursive: true, force: true })
  }
}

function releaseMutationEnvironment({
  env,
  stageDir,
  stagedManifest,
}) {
  return {
    ...process.env,
    ...env,
    NVPN_RELEASE_STAGE_DIR: resolve(stageDir),
    NVPN_RELEASE_TAG: stagedManifest.tag,
  }
}

function replayCanonicalMutationGate({
  stageDir,
  tag,
  env,
  requireTag,
}) {
  return validateReleaseMutationGate({
    stageDir: resolve(stageDir),
    expectedTag: tag,
    requireTag,
    env,
  })
}

function publishRustCrates({
  dryRun,
  env,
  stageDir,
  stagedManifest,
}) {
  const script = join(repoRoot, 'scripts', 'publish.sh')
  assertPromotableDraftSource(stagedManifest.tag, stagedManifest)
  const mutationEnv = releaseMutationEnvironment({
    env,
    stageDir,
    stagedManifest,
  })
  run(
    'bash',
    dryRun
      ? [script, '--dry-run', '--no-allow-dirty']
      : [script, '--no-allow-dirty'],
    {
      dryRun,
      env: mutationEnv,
    },
  )
}

function preflightRustCrates({
  dryRun,
  env,
  stageDir,
  stagedManifest,
}) {
  if (dryRun) {
    return
  }
  const mutationEnv = releaseMutationEnvironment({
    env,
    stageDir,
    stagedManifest,
  })
  run(
    'bash',
    [join(repoRoot, 'scripts', 'publish.sh'), '--preflight', '--no-allow-dirty'],
    { env: mutationEnv },
  )
}

function resolveReleaseCommit(tag, { dryRun = false } = {}) {
  const normalizedTag = normalizeTag(tag)
  if (dryRun) {
    return normalizedTag
  }

  const taggedResult = spawnSync('git', ['rev-parse', '-q', '--verify', `${normalizedTag}^{commit}`], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  if (taggedResult.status === 0) {
    const taggedCommit = taggedResult.stdout.trim()
    if (taggedCommit) {
      return taggedCommit
    }
  }

  return run('git', ['rev-parse', 'HEAD'], { capture: true, dryRun }) || 'HEAD'
}

function main() {
  const options = parseArgs(process.argv.slice(2))
  const { loaded, loadedPaths } = readOptionalEnvFiles([...defaultEnvFiles, ...options.envFiles])
  const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH || loaded.SOURCE_DATE_EPOCH || gitHeadEpoch() || '0'
  const env = deterministicBuildEnv({ ...loaded, ...process.env }, { sourceDateEpoch })
  Object.assign(process.env, env)

  const tag = options.tag || readWorkspaceVersionTag(readFileSync(rootCargoToml, 'utf8'))
  const releaseTree = options.releaseTree || env.NVPN_RELEASE_TREE || 'releases/nostr-vpn'
  const umbrelImageRepo = env.NVPN_UMBREL_IMAGE_REPO || 'ghcr.io/mmalmi/nostr-vpn-umbrel'
  const stageDir =
    options.stageDir || join(os.tmpdir(), `nostr-vpn-release-${tag.replace(/[^\w.-]/g, '_')}`)
  const releaseGateLogDir = resolve(
    env.NVPN_RELEASE_GATE_LOG_DIR
      || join(
        repoRoot,
        'artifacts',
        'release-gate-logs',
        `local-release-${tag.replace(/[^\w.-]/g, '_')}`,
      ),
  )
  const androidGateReceiptPath = join(
    releaseGateLogDir,
    'mobile-release-artifacts',
    'android.json',
  )
  const releaseGateSummaryPath = join(
    releaseGateLogDir,
    'release-gate-summary.json',
  )
  const releaseJoinResultDir = resolve(
    env.NVPN_RELEASE_JOIN_RESULT_DIR
      || join(repoRoot, 'artifacts', 'mobile-release-join'),
  )
  const platformReceiptPaths = {
    android: {
      install: join(releaseJoinResultDir, 'android-release-install.json'),
      physical: androidGateReceiptPath,
      foreground_idle_cpu: join(
        releaseGateLogDir,
        'mobile-network',
        'android-release-foreground-vpn-off-idle',
        'receipt.json',
      ),
      foreground_idle_cpu_raw: join(
        releaseGateLogDir,
        'mobile-network',
        'android-release-foreground-vpn-off-idle',
        'idle-cpu.json',
      ),
      mobile_join: join(releaseJoinResultDir, 'summary.json'),
      wireguard_dns: join(
        releaseGateLogDir,
        'mobile-network',
        'android-wireguard-dns.json',
      ),
      underlay_lifecycle: join(
        releaseGateLogDir,
        'mobile-network',
        'android-underlay-lifecycle.json',
      ),
      replacement_singleton: join(
        releaseGateLogDir,
        'mobile-network',
        'android-replacement-artifacts',
        'mobile-android-legacy-replacement.json',
      ),
    },
    ios: {
      frozen_archive: join(
        repoRoot,
        'dist',
        'ios',
        'frozen',
        'physical-gate-seal.json',
      ),
      mobile_artifact: join(
        repoRoot,
        'dist',
        'ios',
        'frozen',
        'physical-mobile-receipt.json',
      ),
      join_variant: join(
        releaseJoinResultDir,
        'ios-join-test-variant.json',
      ),
      mobile_join: join(releaseJoinResultDir, 'summary.json'),
      desktop_mobile_join: join(
        releaseJoinResultDir,
        'macos',
        'summary.json',
      ),
      wireguard_dns: join(
        releaseGateLogDir,
        'mobile-network',
        'ios-wireguard-dns.json',
      ),
      underlay_lifecycle: join(
        releaseGateLogDir,
        'mobile-network',
        'ios-underlay-lifecycle.json',
      ),
    },
    linux: {
      artifact: join(
        releaseJoinResultDir,
        'linux',
        'import',
        'host-bundle-receipt.json',
      ),
      public_ui_join: join(releaseJoinResultDir, 'linux', 'summary.json'),
      package_install: join(
        releaseJoinResultDir,
        'linux',
        'import',
        'debian-package-install.json',
      ),
      network: join(
        releaseGateLogDir,
        'desktop-network',
        'linux.json',
      ),
      arm64_cli: resolve(
        env.NVPN_LINUX_ARM64_CLI_RECEIPT
          || join(releaseGateLogDir, 'linux-arm64-cli', 'receipt.json'),
      ),
    },
    macos: {
      artifact: join(releaseJoinResultDir, 'macos', 'artifact.json'),
      public_ui_join: join(releaseJoinResultDir, 'macos', 'summary.json'),
      network: join(
        releaseGateLogDir,
        'desktop-network',
        'macos.json',
      ),
    },
    windows: {
      artifact: join(
        releaseJoinResultDir,
        'windows',
        'windows-release-artifact.json',
      ),
      installer: join(
        releaseGateLogDir,
        'windows-installer',
        'installer-receipt.json',
      ),
      public_ui_join: join(releaseJoinResultDir, 'windows', 'summary.json'),
      network: join(
        releaseGateLogDir,
        'desktop-network',
        'windows.json',
      ),
    },
  }
  const expectedStagedAndroidApkPath = join(
    stageDir,
    'assets',
    androidReleaseAssetName(tag),
  )
  const allowPartial = options.allowPartial || envFlagEnabled(env.NVPN_RELEASE_ALLOW_PARTIAL)
  const finalPublication = options.publish && !options.draft
  const requireZapstore = zapstorePublicationRequired({
    cliRequired: options.requireZapstore || finalPublication,
    envValue: env.NVPN_RELEASE_REQUIRE_ZAPSTORE,
  })
  const builtLines = []
  const skippedLines = []
  let androidReleaseGate = null
  let iosAppStoreGate = null
  let releaseGateEvidence = null
  const artifactProofs = {}

  if (
    options.completeGateFromReceipts
    && (
      options.dryRun
      || options.publish
      || options.publishStagedDraft
      || options.promoteDraft
      || options.reuseGateReceipts
      || options.skipVerify
      || options.only
      || options.skip.size > 0
      || allowPartial
      || options.cargoPublish
      || options.skipCargoPublish
      || options.skipZapstore
      || options.skipUmbrel
      || options.requireZapstore
    )
  ) {
    throw new Error(
      '--complete-gate-from-receipts cannot be combined with build, partial, dry-run, or publication modes.',
    )
  }

  if (
    options.reuseGateReceipts
    && (
      options.skipVerify
      || options.skip.has('verify')
      || (options.only && !options.only.has('verify'))
      || allowPartial
      || options.publishStagedDraft
      || options.promoteDraft
    )
  ) {
    throw new Error(
      '--reuse-gate-receipts requires complete verification and cannot be combined with skipped or partial staging.',
    )
  }

  if (options.publishStagedDraft) {
    const conflicts = []
    if (options.publish) conflicts.push('another publication mode')
    if (options.cargoPublish) conflicts.push('--cargo-publish')
    if (options.skipCargoPublish) conflicts.push('--skip-cargo-publish')
    if (options.skipZapstore) conflicts.push('--skip-zapstore')
    if (options.skipUmbrel) conflicts.push('--skip-umbrel')
    if (options.requireZapstore) conflicts.push('--require-zapstore')
    if (options.skipVerify) conflicts.push('--skip-verify')
    if (options.only) conflicts.push('--only')
    if (options.skip.size > 0) conflicts.push('--skip')
    if (allowPartial) conflicts.push('--allow-partial')
    if (conflicts.length > 0) {
      throw new Error(
        `--publish-staged-draft cannot be combined with ${conflicts.join(', ')}.`,
      )
    }
  }
  if (options.publish && !options.promoteDraft) {
    throw new Error(
      'Direct --publish/--final is disabled: stage first, then use --publish-staged-draft and --promote-draft.',
    )
  }
  if (options.cargoPublish && !options.promoteDraft) {
    throw new Error(
      'Direct --cargo-publish is disabled: publish crates only while promoting an exact staged draft.',
    )
  }
  if (requireZapstore && options.skipZapstore) {
    throw new Error('--require-zapstore conflicts with --skip-zapstore.')
  }
  if (finalPublication && !options.dryRun && allowPartial) {
    throw new Error('A final release cannot be published with partial platform artifacts.')
  }
  if (
    finalPublication
    && !options.dryRun
    && !options.promoteDraft
    && (options.only || options.skip.size > 0)
  ) {
    throw new Error(
      'A final release must run every platform step; --only and --skip are staging-only.',
    )
  }
  if (
    requireZapstore
    && !options.dryRun
    && (!options.publish || options.draft)
  ) {
    throw new Error(
      'Required Zapstore publication needs --final or --promote-draft.',
    )
  }

  console.log(`Release tag: ${tag}`)
  console.log(`Release tree: ${releaseTree}`)
  if (requireZapstore) {
    console.log('Zapstore publication and post-publish verification are required.')
  }
  if (finalPublication && !options.skipUmbrel) {
    console.log('Umbrel multi-arch image publication and anonymous digest verification are required.')
  }
  if (loadedPaths.length > 0) {
    console.log(`Loaded env files: ${loadedPaths.join(', ')}`)
  }
  if (options.dryRun) {
    console.log('Dry run mode: no build, copy, or publish commands will be executed.')
  }
  if (options.promoteDraft) {
    console.log('Promote mode: reusing an existing staged draft and publishing it as final/latest.')
  } else if (options.publishStagedDraft) {
    console.log('Staged-draft mode: publishing only the existing validated draft bytes.')
  } else if (options.publish && options.draft) {
    console.log('Draft mode: htree publish will repoint draft instead of latest, and crate/Zapstore publish steps are disabled.')
  }

  if (
    (options.publish || options.publishStagedDraft)
    && !options.dryRun
    && !commandExists('htree')
  ) {
    throw new Error('Missing htree; cannot publish release.')
  }
  if (options.publishStagedDraft) {
    const stagedManifest = readReleaseManifest(stageDir)
    validatePromotableReleaseManifest(stagedManifest)
    const stagedCommit = assertPublishableStagedDraftSource(tag, stagedManifest)
    verifyStagedPublicationBundle({
      stageDir,
      tag,
      commit: stagedCommit,
      tree: gitTree(stagedCommit),
    })
    const mutationEnv = releaseMutationEnvironment({
      env,
      stageDir,
      stagedManifest,
    })
    preflightHtreeRelease({
      repoRoot,
      env: mutationEnv,
      dryRun: options.dryRun,
    })
    const cid = publishRelease({
      stageDir,
      releaseTree,
      tag,
      draft: true,
      dryRun: options.dryRun,
      beforeMutation: () => {
        preflightHtreeRelease({
          repoRoot,
          env: mutationEnv,
          dryRun: options.dryRun,
        })
        replayCanonicalMutationGate({
          stageDir,
          tag,
          env: mutationEnv,
          requireTag: false,
        })
      },
    })
    console.log(`Published staged draft ${tag} to ${releaseTree} via ${cid}`)
    return
  }
  if (
    options.publish
    && !options.dryRun
    && (
      options.skipVerify
      || options.skip.has('verify')
      || (options.only && !options.only.has('verify'))
    )
  ) {
    throw new Error('Publishing a new release candidate cannot skip the required release gate.')
  }

  const candidateCommit =
    options.dryRun || options.promoteDraft
      ? ''
      : assertCleanReleaseSource(tag)
  const candidateTree =
    options.dryRun || options.promoteDraft
      ? ''
      : gitTree(candidateCommit)

  if (options.completeGateFromReceipts) {
    const result = completeReleaseGateFromReceipts({
      commit: candidateCommit,
      tree: candidateTree,
      candidateRoot: repoRoot,
      releaseGateSummaryPath,
      platformReceiptPaths,
      targetSeconds: Number(env.NVPN_RELEASE_GATE_TARGET_SECS || 1_800),
    })
    console.log(
      `${result.created ? 'Created' : 'Validated existing'} exact release-gate completion receipt: ${releaseGateSummaryPath}`,
    )
    return
  }

  if (options.promoteDraft) {
    if (!commandExists('htree')) {
      throw new Error('Missing htree; cannot promote release.')
    }
    const stagedManifest = readReleaseManifest(stageDir)
    validatePromotableReleaseManifest(stagedManifest)
    const stagedCommit = assertPromotableDraftSource(
      tag,
      stagedManifest,
    )
    verifyStagedPublicationBundle({
      stageDir,
      tag,
      commit: stagedCommit,
      tree: gitTree(stagedCommit),
    })
    const mutationEnv = releaseMutationEnvironment({
      env,
      stageDir,
      stagedManifest,
    })
    preflightHtreeRelease({
      repoRoot,
      env: mutationEnv,
      dryRun: options.dryRun,
    })
    const githubPreflight = preflightGithubRelease({
      repoRoot,
      tag,
      commit: stagedCommit,
      dryRun: options.dryRun,
    })
    const iosPublication = preflightIosPublication({
      repoRoot,
      stagedManifest,
      mutationEnv,
      dryRun: options.dryRun,
    })
    if (!options.skipUmbrel) {
      preflightUmbrelPublication({
        dryRun: options.dryRun,
        imageRepo: umbrelImageRepo,
        platforms: ['linux/amd64', 'linux/arm64'],
      })
    }
    if (!options.dryRun && !options.skipZapstore) {
      preflightExactZapstorePublication({
        repoRoot,
        env,
        mutationEnv,
        requireApk: true,
        apkPath: join(
          stageDir,
          stagedManifest.android_release_gate.apk_path,
        ),
        expectedApk: {
          sha256: stagedManifest.android_release_gate.apk_sha256,
          signerSha256:
            stagedManifest.android_release_gate
              .signer_certificate_sha256,
        },
        tag,
      })
    }
    if (options.cargoPublish || !options.skipCargoPublish) {
      preflightRustCrates({
        dryRun: options.dryRun,
        env,
        stageDir,
        stagedManifest,
      })
    }
    const apple = publishExactIosDistribution({
      repoRoot,
      stagedManifest,
      mutationEnv,
      preflight: iosPublication,
      beforeMutation: () => replayCanonicalMutationGate({
        stageDir,
        tag,
        env: mutationEnv,
        requireTag: true,
      }),
      dryRun: options.dryRun,
    })
    console.log(
      `${apple.submitted ? 'Submitted and verified' : 'Would submit'} ${tag} for internal and external TestFlight plus App Review.`,
    )
    const promoted = promoteStagedDraft({
      stageDir,
      releaseTree,
      tag,
      dryRun: options.dryRun,
      beforeMutation: () => {
        preflightHtreeRelease({
          repoRoot,
          env: mutationEnv,
          dryRun: options.dryRun,
        })
        replayCanonicalMutationGate({
          stageDir,
          tag,
          env: mutationEnv,
          requireTag: true,
        })
      },
    })
    console.log(`Promoted ${tag} to ${releaseTree} via ${promoted.cid}`)
    replayCanonicalMutationGate({
      stageDir,
      tag,
      env: mutationEnv,
      requireTag: true,
    })
    const githubRelease = publishExactGithubRelease({
      repoRoot,
      stageDir,
      manifest: stagedManifest,
      tag,
      commit: stagedCommit,
      repository: githubPreflight.repository,
      beforeMutation: () => replayCanonicalMutationGate({
        stageDir,
        tag,
        env: mutationEnv,
        requireTag: true,
      }),
      dryRun: options.dryRun,
    })
    console.log(
      `${githubRelease.created ? 'Created and verified' : 'Verified existing'} exact GitHub release ${tag}.`,
    )
    if (!options.skipUmbrel) {
      const umbrel = publishVerifiedUmbrelRelease({
        beforeMutation: () => replayCanonicalMutationGate({
          stageDir,
          tag,
          env: mutationEnv,
          requireTag: true,
        }),
        dryRun: options.dryRun,
        imageRepo: umbrelImageRepo,
        outputDir: join(distDir, `umbrel-${tag}`),
        platforms: ['linux/amd64', 'linux/arm64'],
        tag,
      })
      console.log(
        `${umbrel.published ? 'Published and anonymously verified' : 'Would publish'} ${tag} for Umbrel.`,
      )
    }
    if (options.cargoPublish || !options.skipCargoPublish) {
      publishRustCrates({
        dryRun: options.dryRun,
        env,
        stageDir,
        stagedManifest,
      })
    }
    if (!options.skipZapstore) {
      const zapstore = publishExactZapstoreRelease({
        repoRoot,
        env,
        mutationEnv,
        tag,
        apkPath: promoted.stagedAndroidApkPath,
        expectedApk: {
          sha256: stagedManifest.android_release_gate.apk_sha256,
          signerSha256:
            stagedManifest.android_release_gate
              .signer_certificate_sha256,
        },
        dryRun: options.dryRun,
        required: requireZapstore,
      })
      console.log(
        `${zapstore.published ? 'Published and verified' : 'Would publish'} ${tag} on Zapstore.`,
      )
    }
    return
  }

  if (!options.dryRun && shouldRunStep('startos', options)) {
    preflightStartosRelease({
      needsWorkspace: !String(env.NVPN_RELEASE_STARTOS_ARTIFACT_DIR ?? '').trim(),
    })
  }

  const steps = [
    ['platform-versions', () => syncPlatformVersions({
      env,
      tag,
      dryRun: options.dryRun,
      builtLines,
    })],
    ['verify', () => {
      if (options.reuseGateReceipts) {
        builtLines.push('Validated and reused the complete existing release-gate receipt set.')
      } else {
        runVerify({
          dryRun: options.dryRun,
          builtLines,
          releaseGateLogDir,
          tag,
        })
      }
      if (!options.dryRun && !allowPartial) {
        releaseGateEvidence = collectReleaseGateReceipts({
          commit: candidateCommit,
          tree: candidateTree,
          candidateRoot: repoRoot,
          releaseGateSummaryPath,
          platformReceiptPaths,
        })
      }
    }],
    ['startos', () => mergeArtifactProofs(
      artifactProofs,
      buildStartosArtifacts({
        env,
        tag,
        dryRun: options.dryRun,
        builtLines,
        releaseGateSummaryPath,
      }),
    )],
    ['macos', () => mergeArtifactProofs(
      artifactProofs,
      buildMacosArtifacts({
        tag,
        dryRun: options.dryRun,
        builtLines,
        candidateCommit,
        candidateTree,
        gateReceiptPath: platformReceiptPaths.macos.artifact,
        gatedAppPath: join(
          releaseJoinResultDir,
          'macos',
          'publication',
          'Nostr VPN.app',
        ),
      }),
    )],
    ['android', () => {
      const android = buildAndroidArtifacts({
        env,
        tag,
        dryRun: options.dryRun,
        builtLines,
        gateReceiptPath: androidGateReceiptPath,
        candidateCommit,
        candidateTree,
      })
      androidReleaseGate = android.gate
      mergeArtifactProofs(artifactProofs, android.proofs)
    }],
    ['linux', () => mergeArtifactProofs(
      artifactProofs,
      buildLinuxArtifacts({
        env,
        tag,
        dryRun: options.dryRun,
        builtLines,
        candidateCommit,
        candidateTree,
        testedReceiptPath: platformReceiptPaths.linux.artifact,
        testedPackageInstallReceiptPath:
          platformReceiptPaths.linux.package_install,
        gatedBundlePathReceipt: join(
          releaseGateLogDir,
          'host-linux-vm-bundle-path.txt',
        ),
        arm64CliReceiptPath: platformReceiptPaths.linux.arm64_cli,
        arm64CliArchivePath: resolve(
          env.NVPN_LINUX_ARM64_CLI_ARCHIVE
            || join(dirname(platformReceiptPaths.linux.arm64_cli), 'nvpn-aarch64-unknown-linux-musl.tar.gz'),
        ),
      }),
    )],
    ['windows', () => mergeArtifactProofs(
      artifactProofs,
      buildWindowsArtifacts({
        env,
        tag,
        dryRun: options.dryRun,
        builtLines,
        candidateCommit,
        candidateTree,
        gateReceiptPath: platformReceiptPaths.windows.artifact,
        installerReceiptPath: platformReceiptPaths.windows.installer,
        installerArtifactPath: join(
          releaseGateLogDir,
          'windows-installer',
          `nostr-vpn-${tag}-windows-x64-setup.exe`,
        ),
      }),
    )],
    // Upload the TestFlight/App Store candidate only after every downloadable
    // platform artifact has built successfully, avoiding a partial upload.
    ['ios', () => {
      iosAppStoreGate = buildIosArtifacts({
        tag,
        dryRun: options.dryRun,
        builtLines,
        releaseGateLogDir,
        candidateCommit,
        candidateTree,
      })
    }],
  ]

  for (const [name, fn] of steps) {
    if (!shouldRunStep(name, options)) {
      skippedLines.push(`${name} skipped by CLI options.`)
      continue
    }

    try {
      fn()
      if (
        name === 'platform-versions'
        && !options.dryRun
        && !options.promoteDraft
      ) {
        assertCleanReleaseSource(tag, candidateCommit)
      }
    } catch (error) {
      if (error instanceof SkipStepError) {
        skippedLines.push(error.message)
        continue
      }
      if (name === 'verify') {
        throw error
      }
      const failure = `${name} build failed: ${error.message}`
      skippedLines.push(failure)
      if (!allowPartial) {
        throw new Error(`${failure}\nPass --allow-partial or set NVPN_RELEASE_ALLOW_PARTIAL=1 to stage/publish without this artifact.`)
      }
    }
  }

  if (!options.dryRun) {
    assertCleanReleaseSource(tag, candidateCommit)
  }

  const commit = resolveReleaseCommit(tag, { dryRun: options.dryRun })
  if (!options.dryRun && !allowPartial) {
    if (!releaseGateEvidence) {
      throw new Error(
        'Complete release staging requires validated real-platform receipts.',
      )
    }
  }
  stageRelease({
    tag,
    commit,
    tree: candidateTree,
    stageDir,
    builtLines,
    skippedLines,
    dryRun: options.dryRun,
    requireCompleteAppRelease: !allowPartial && !options.dryRun,
    draft: options.draft,
    androidReleaseGate,
    iosAppStoreGate,
    releaseGateEvidence,
    artifactProofs,
  })

  if (!options.dryRun) {
    console.log(`Staged ${tag} at ${stageDir}`)
  }
}

try {
  main()
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
