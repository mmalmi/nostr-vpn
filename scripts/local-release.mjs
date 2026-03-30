#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  autoDetectWindowsVmName,
  buildReleaseManifest,
  normalizeTag,
  parseEnvFile,
  readWorkspaceVersionTag,
  renderReleaseNotes,
  splitCsv,
} from './local-release-lib.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '..')
const guiRoot = join(repoRoot, 'crates', 'nostr-vpn-gui')
const rootCargoToml = join(repoRoot, 'Cargo.toml')
const distDir = join(repoRoot, 'dist')
const defaultEnvFiles = [
  join(repoRoot, '.env.release.local'),
  join(repoRoot, '.env.zapstore.local'),
]
const versionlessCliAssets = new Map([
  ['nvpn-aarch64-apple-darwin.tar.gz', 'nvpn-v{tag}-aarch64-apple-darwin.tar.gz'],
  ['nvpn-x86_64-unknown-linux-musl.tar.gz', 'nvpn-v{tag}-x86_64-unknown-linux-musl.tar.gz'],
  ['nvpn-aarch64-unknown-linux-musl.tar.gz', 'nvpn-v{tag}-aarch64-unknown-linux-musl.tar.gz'],
])

class SkipStepError extends Error {}

function usage() {
  console.log(`Usage: node scripts/local-release.mjs [options]

Build locally-available release artifacts, stage a hashtree release directory, and optionally publish it.

Options:
  --publish                 Publish the staged release tree with htree
  --dry-run                 Print the plan without running build or publish commands
  --skip-verify            Skip fmt/clippy/test verification
  --tag <tag>              Release tag (defaults to workspace version, for example v0.2.27)
  --release-tree <name>    htree release tree name (default: releases/nostr-vpn)
  --stage-dir <path>       Directory used for staged release metadata
  --env-file <path>        Extra dotenv file to load (repeatable)
  --only <csv>             Limit steps to verify,macos,android,windows
  --skip <csv>             Skip steps by name
  --help                   Show this help

The script auto-loads .env.release.local and .env.zapstore.local when present.
Shell environment variables override values from those files.`)
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    publish: false,
    skipVerify: false,
    releaseTree: null,
    stageDir: null,
    tag: null,
    envFiles: [],
    only: null,
    skip: new Set(),
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
      case '--dry-run':
        options.dryRun = true
        break
      case '--skip-verify':
        options.skipVerify = true
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

function quote(arg) {
  const value = String(arg)
  return /[^\w./:-]/.test(value) ? JSON.stringify(value) : value
}

function run(command, args, { cwd = repoRoot, env = process.env, capture = false, dryRun = false } = {}) {
  const rendered = [command, ...args].map(quote).join(' ')
  console.log(`$ ${rendered}`)
  if (dryRun) {
    return ''
  }

  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  })

  if (result.status !== 0) {
    const stderr = capture ? result.stderr.trim() : ''
    throw new Error(stderr || `${command} exited with status ${result.status ?? 'unknown'}`)
  }

  return capture ? result.stdout.trim() : ''
}

function resolveHostPnpmInvocation() {
  if (commandExists('pnpm')) {
    return ['pnpm']
  }
  if (commandExists('corepack')) {
    return ['corepack', 'pnpm']
  }

  throw new Error('Missing pnpm (or corepack) on the local host')
}

function runPnpm(pnpmInvocation, args, options = {}) {
  const [command, ...prefix] = pnpmInvocation
  return run(command, [...prefix, ...args], options)
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

echo "Installing nvpn to \${INSTALL_DIR}"

if [ -e "\${INSTALL_DIR}" ] && [ ! -d "\${INSTALL_DIR}" ]; then
  echo "Install target exists but is not a directory: \${INSTALL_DIR}" >&2
  exit 1
fi

if [ ! -d "\${INSTALL_DIR}" ]; then
  PARENT_DIR="$(dirname "\${INSTALL_DIR}")"
  if [ ! -w "\${PARENT_DIR}" ]; then
    echo "Need sudo to create \${INSTALL_DIR}"
    sudo mkdir -p "\${INSTALL_DIR}"
  else
    mkdir -p "\${INSTALL_DIR}"
  fi
fi

if [ ! -w "\${INSTALL_DIR}" ]; then
  echo "Need sudo to install to \${INSTALL_DIR}"
  sudo install -m 755 nvpn "\${INSTALL_DIR}/"
else
  install -m 755 nvpn "\${INSTALL_DIR}/"
fi

echo "Installed nvpn"
if ! path_contains "\${INSTALL_DIR}"; then
  echo "Note: \${INSTALL_DIR} is not currently in PATH"
fi
echo "Verify with:"
echo "  nvpn --help"
`,
  )
}

function writeUnixReadme(path) {
  writeFileSync(
    path,
    `nvpn - Nostr-signaled WireGuard control plane
============================================

Binary included:
  nvpn  - CLI control plane

Quick install:
  ./install.sh              # installs to /opt/homebrew/bin on Apple Silicon macOS when appropriate, otherwise /usr/local/bin
  ./install.sh ~/.local/bin # installs to a custom directory

Manual install:
  cp nvpn /usr/local/bin/

Quick start:
  nvpn init --participant npub1...alice --participant npub1...bob
  nvpn up
  nvpn status
`,
  )
}

function packageUnixCliTarball({ binaryPath, targetTriple, tag, dryRun }) {
  const bundleDir = join(distDir, 'nvpn')
  if (!dryRun) {
    rmSync(bundleDir, { recursive: true, force: true })
    mkdirSync(bundleDir, { recursive: true })
    copyFileSync(binaryPath, join(bundleDir, 'nvpn'))
    writeUnixInstallScript(join(bundleDir, 'install.sh'))
    writeUnixReadme(join(bundleDir, 'README.txt'))
  }

  run('chmod', ['+x', join(bundleDir, 'install.sh')], { dryRun })

  const unversioned = join(distDir, `nvpn-${targetTriple}.tar.gz`)
  const versioned = join(distDir, `nvpn-${tag}-${targetTriple}.tar.gz`)
  run('tar', ['-czf', unversioned, '-C', distDir, 'nvpn'], { dryRun })
  if (!dryRun && !existsSync(unversioned)) {
    throw new Error(`Expected CLI archive at ${unversioned}`)
  }
  if (!dryRun) {
    copyFileSync(unversioned, versioned)
  }
  return [unversioned, versioned]
}

function findFirstFile(root, matcher) {
  if (!existsSync(root)) {
    return null
  }

  const entries = readdirSync(root)
  const match = entries.find((entry) => matcher(entry))
  return match ? join(root, match) : null
}

function defaultSharedWindowsRepoPath() {
  if (process.platform !== 'darwin') {
    return null
  }

  const homeDir = os.homedir()
  if (!repoRoot.startsWith(`${homeDir}/`)) {
    return null
  }

  const relative = repoRoot.slice(homeDir.length + 1).split('/').join('\\')
  return `C:\\Mac\\Home\\${relative}`
}

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`
}

function runWindowsPowerShell(vmName, script, { capture = false, dryRun = false } = {}) {
  return run(
    'prlctl',
    ['exec', vmName, '--current-user', 'powershell.exe', '-NoProfile', '-Command', script],
    { capture, dryRun },
  )
}

function windowsArtifactArch(targetTriple) {
  if (targetTriple.startsWith('x86_64-')) {
    return 'x64'
  }
  if (targetTriple.startsWith('aarch64-')) {
    return 'arm64'
  }

  return targetTriple
}

function syncRepoToWindowsVm({ vmName, sharedRepoPath, dryRun }) {
  const script = `
$sharedRepo = ${psQuote(sharedRepoPath)}
$guestRepo = Join-Path $env:USERPROFILE 'src\\nostr-vpn'
$guestRoot = Split-Path $guestRepo
New-Item -ItemType Directory -Force -Path $guestRoot | Out-Null
robocopy $sharedRepo $guestRepo /MIR /XD target dist .git node_modules .pnpm-store artifacts /XF .env.release.local .env.zapstore.local | Out-Null
$binDir = Join-Path $env:USERPROFILE 'bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$shimPath = Join-Path $binDir 'pnpm.cmd'
$shimLines = @(
  '@echo off'
  'corepack pnpm %*'
)
Set-Content -Encoding ASCII -Path $shimPath -Value $shimLines
`

  runWindowsPowerShell(vmName, script, { dryRun })
}

function buildWindowsArtifacts({
  env,
  tag,
  dryRun,
  builtLines,
}) {
  if (process.platform !== 'darwin') {
    throw new SkipStepError('Windows VM builds are only wired up for the macOS + Parallels workflow.')
  }
  if (!commandExists('prlctl')) {
    throw new SkipStepError('Skipping Windows artifacts because prlctl is unavailable.')
  }

  const sharedRepoPath = env.NVPN_WINDOWS_SHARED_REPO_PATH || defaultSharedWindowsRepoPath()
  if (!sharedRepoPath) {
    throw new SkipStepError('Skipping Windows artifacts because the shared repo path could not be derived; set NVPN_WINDOWS_SHARED_REPO_PATH.')
  }

  const vmName =
    env.NVPN_WINDOWS_VM_NAME ||
    autoDetectWindowsVmName(run('prlctl', ['list', '-a'], { capture: true, dryRun }))
  if (!vmName) {
    throw new SkipStepError('Skipping Windows artifacts because no unique running Windows VM was detected; set NVPN_WINDOWS_VM_NAME.')
  }

  syncRepoToWindowsVm({ vmName, sharedRepoPath, dryRun })

  const llvmBin = env.NVPN_WINDOWS_LLVM_BIN || 'C:\\Program Files\\LLVM\\bin'
  const cliTargets = splitCsv(
    env.NVPN_WINDOWS_CLI_TARGETS || 'x86_64-pc-windows-msvc,aarch64-pc-windows-msvc',
  )
  const guiTargets = splitCsv(env.NVPN_WINDOWS_GUI_TARGETS || 'x86_64-pc-windows-msvc')

  const guestRepo = "(Join-Path $env:USERPROFILE 'src\\nostr-vpn')"
  const distPath = `${sharedRepoPath}\\dist`
  const pathSetup = `$env:PATH = (Join-Path $env:USERPROFILE 'bin') + ';' + ${psQuote(llvmBin)} + ';' + $env:PATH`

  runWindowsPowerShell(
    vmName,
    `
${pathSetup}
Set-Location ${guestRepo}
corepack pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile
`,
    { dryRun },
  )

  for (const target of cliTargets) {
    const archiveName = `nvpn-${tag}-${target}.zip`
    runWindowsPowerShell(
      vmName,
      `
${pathSetup}
Set-Location ${guestRepo}
cargo build --release --target ${psQuote(target)} -p nostr-vpn-cli
$cli = Join-Path ${guestRepo} ${psQuote(`target\\${target}\\release\\nvpn.exe`)}
if (!(Test-Path $cli)) { throw "Missing nvpn.exe for ${target}" }
$tempDir = Join-Path $env:TEMP ${psQuote(`nvpn-${target}-zip`)}
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
Copy-Item $cli (Join-Path $tempDir 'nvpn.exe')
Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath ${psQuote(`${distPath}\\${archiveName}`)} -Force
Remove-Item -Recurse -Force $tempDir
`,
      { dryRun },
    )
    builtLines.push(`Built Windows ${windowsArtifactArch(target)} CLI inside Parallels VM ${vmName}.`)
  }

  for (const target of guiTargets) {
    const arch = windowsArtifactArch(target)
    const installerName = `nostr-vpn-${tag}-windows-${arch}-setup.exe`
    runWindowsPowerShell(
      vmName,
      `
${pathSetup}
Set-Location ${guestRepo}
corepack pnpm --dir crates/nostr-vpn-gui run tauri build --target ${psQuote(target)} --ci
$bundleDir = Join-Path ${guestRepo} ${psQuote(`target\\${target}\\release\\bundle\\nsis`)}
$installer = Get-ChildItem $bundleDir -Filter '*-setup.exe' | Select-Object -First 1
if (-not $installer) { throw "No installer found for ${target}" }
Copy-Item $installer.FullName ${psQuote(`${distPath}\\${installerName}`)} -Force
`,
      { dryRun },
    )
    builtLines.push(`Built Windows ${arch} desktop installer inside Parallels VM ${vmName}.`)
  }
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

  return updated
}

function buildAndroidArtifacts({ env, pnpmInvocation, tag, dryRun, builtLines }) {
  const androidEnv = ensureAndroidSdkEnv(env)
  if (!androidEnv.ANDROID_SDK_ROOT && !androidEnv.ANDROID_HOME) {
    throw new SkipStepError('Skipping Android artifacts because ANDROID_SDK_ROOT/ANDROID_HOME is not configured.')
  }

  const installedTargets = run('rustup', ['target', 'list', '--installed'], {
    capture: true,
    dryRun,
  })
  if (!installedTargets.includes('aarch64-linux-android')) {
    run('rustup', ['target', 'add', 'aarch64-linux-android'], { dryRun })
  }

  const androidDir = join(guiRoot, 'src-tauri', 'gen', 'android')
  const keyPropertiesPath = join(androidDir, 'key.properties')
  const tempKeystorePath = join(androidDir, 'upload-keystore.jks')
  let wroteKeyProperties = false
  let wroteTempKeystore = false

  try {
    const keystorePath =
      androidEnv.ANDROID_KEYSTORE_PATH ||
      (androidEnv.ANDROID_KEYSTORE_B64 ? tempKeystorePath : '')
    if (androidEnv.ANDROID_KEYSTORE_B64 && !dryRun) {
      writeFileSync(tempKeystorePath, Buffer.from(androidEnv.ANDROID_KEYSTORE_B64, 'base64'))
      wroteTempKeystore = true
    }

    const hasSigning =
      keystorePath &&
      androidEnv.ANDROID_KEYSTORE_PASSWORD &&
      (androidEnv.ANDROID_KEY_ALIAS || 'nostr-vpn-upload') &&
      (androidEnv.ANDROID_KEY_PASSWORD || androidEnv.ANDROID_KEYSTORE_PASSWORD)

    if (hasSigning && !dryRun) {
      writeFileSync(
        keyPropertiesPath,
        `storePassword=${androidEnv.ANDROID_KEYSTORE_PASSWORD}
keyPassword=${androidEnv.ANDROID_KEY_PASSWORD || androidEnv.ANDROID_KEYSTORE_PASSWORD}
keyAlias=${androidEnv.ANDROID_KEY_ALIAS || 'nostr-vpn-upload'}
storeFile=${keystorePath}
`,
      )
      wroteKeyProperties = true
    }

    runPnpm(
      pnpmInvocation,
      ['--dir', guiRoot, 'exec', 'tauri', 'android', 'build', '--target', 'aarch64', '--apk', '--aab', '--ci'],
      { env: androidEnv, dryRun },
    )

    const apkPath = findFirstFile(
      join(androidDir, 'app', 'build', 'outputs', 'apk', 'universal', 'release'),
      (entry) => entry.endsWith('.apk'),
    )
    const aabPath = findFirstFile(
      join(androidDir, 'app', 'build', 'outputs', 'bundle', 'universalRelease'),
      (entry) => entry.endsWith('.aab'),
    )

    if (!dryRun && (!apkPath || !aabPath)) {
      throw new Error('Expected Android APK/AAB outputs were not produced.')
    }

    const suffix = wroteKeyProperties ? '' : '-unsigned'
    const apkDest = join(distDir, `nostr-vpn-${tag}-android-arm64${suffix}.apk`)
    const aabDest = join(distDir, `nostr-vpn-${tag}-android-arm64${suffix}.aab`)
    if (!dryRun) {
      copyFileSync(apkPath, apkDest)
      copyFileSync(aabPath, aabDest)
    }

    builtLines.push(
      wroteKeyProperties
        ? 'Built signed Android arm64 APK/AAB locally.'
        : 'Built unsigned Android arm64 APK/AAB locally.',
    )
  } finally {
    if (wroteKeyProperties && existsSync(keyPropertiesPath)) {
      rmSync(keyPropertiesPath, { force: true })
    }
    if (wroteTempKeystore && existsSync(tempKeystorePath)) {
      rmSync(tempKeystorePath, { force: true })
    }
  }
}

function buildMacosArtifacts({ pnpmInvocation, tag, dryRun, builtLines }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new SkipStepError('Skipping macOS artifacts because the host is not Apple Silicon macOS.')
  }

  run('cargo', ['build', '--release', '--target', 'aarch64-apple-darwin', '-p', 'nostr-vpn-cli'], {
    dryRun,
  })
  packageUnixCliTarball({
    binaryPath: join(repoRoot, 'target', 'aarch64-apple-darwin', 'release', 'nvpn'),
    targetTriple: 'aarch64-apple-darwin',
    tag,
    dryRun,
  })

  runPnpm(
    pnpmInvocation,
    ['--dir', guiRoot, 'exec', 'tauri', 'build', '--target', 'aarch64-apple-darwin', '--bundles', 'app', '--no-sign', '--ci'],
    { dryRun },
  )

  const appPath = findFirstFile(
    join(repoRoot, 'target', 'aarch64-apple-darwin', 'release', 'bundle', 'macos'),
    (entry) => entry.endsWith('.app'),
  )
  if (!dryRun && !appPath) {
    throw new Error('No macOS .app bundle found in build output.')
  }
  const appPathForZip = appPath || '<macos-app-bundle>'

  run(
    'ditto',
    ['-c', '-k', '--sequesterRsrc', '--keepParent', appPathForZip, join(distDir, `nostr-vpn-${tag}-macos-arm64.zip`)],
    { dryRun },
  )

  builtLines.push('Built Apple Silicon macOS app and CLI locally.')
}

function runVerify({ pnpmInvocation, dryRun, builtLines }) {
  runPnpm(pnpmInvocation, ['--dir', guiRoot, 'install', '--frozen-lockfile'], { dryRun })
  runPnpm(pnpmInvocation, ['--dir', guiRoot, 'build'], { dryRun })
  run('cargo', ['fmt', '--check'], { dryRun })
  run('cargo', ['clippy', '--workspace', '--exclude', 'nostr-vpn-gui', '--all-targets', '--', '-D', 'warnings'], {
    dryRun,
  })
  run('cargo', ['test', '--workspace', '--exclude', 'nostr-vpn-gui'], { dryRun })
  builtLines.push('Ran frontend build, cargo fmt --check, cargo clippy, and cargo test.')
}

function shouldRunStep(step, options) {
  if (options.skipVerify && step === 'verify') {
    return false
  }
  if (options.only && !options.only.has(step)) {
    return false
  }
  if (options.skip.has(step)) {
    return false
  }
  return true
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

function stageRelease({ tag, commit, stageDir, builtLines, skippedLines, dryRun }) {
  const assetPaths = collectReleaseAssetPaths(tag)
  if (dryRun) {
    console.log(`Would stage ${assetPaths.length} currently visible asset(s) into ${stageDir}`)
    return { assetPaths, stageDir }
  }

  if (assetPaths.length === 0) {
    throw new Error(`No dist assets found for ${tag}.`)
  }

  rmSync(stageDir, { recursive: true, force: true })
  mkdirSync(join(stageDir, 'assets'), { recursive: true })

  const stagedAssetPaths = []
  for (const assetPath of assetPaths) {
    const stagedPath = join(stageDir, 'assets', basename(assetPath))
    copyFileSync(assetPath, stagedPath)
    stagedAssetPaths.push(stagedPath)
  }

  const createdAt = Math.floor(Date.now() / 1000)
  const manifest = buildReleaseManifest({
    tag,
    commit,
    createdAt,
    assetPaths: stagedAssetPaths,
  })

  writeFileSync(join(stageDir, 'release.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  writeFileSync(
    join(stageDir, 'notes.md'),
    renderReleaseNotes({
      tag,
      commit,
      assetNames: stagedAssetPaths.map((assetPath) => basename(assetPath)),
      builtLines,
      skippedLines,
    }),
  )

  return { assetPaths, stageDir }
}

function publishRelease({ stageDir, releaseTree, tag, dryRun }) {
  if (dryRun) {
    console.log(`Would publish ${tag} from ${stageDir} into ${releaseTree}`)
    return 'dry-run'
  }

  const addOutput = run('htree', ['add', stageDir], { capture: true, dryRun })
  const match = addOutput.match(/^\s*url:\s*(\S+)/m)
  if (!match) {
    throw new Error('Could not parse htree add output for release CID.')
  }

  const cid = match[1]
  run('htree', ['release', 'publish', releaseTree, tag, cid], { dryRun })
  return cid
}

function main() {
  const options = parseArgs(process.argv.slice(2))
  const { loaded, loadedPaths } = readOptionalEnvFiles([...defaultEnvFiles, ...options.envFiles])
  const env = { ...loaded, ...process.env }

  const tag = options.tag || readWorkspaceVersionTag(readFileSync(rootCargoToml, 'utf8'))
  const releaseTree = options.releaseTree || env.NVPN_RELEASE_TREE || 'releases/nostr-vpn'
  const stageDir =
    options.stageDir || join(os.tmpdir(), `nostr-vpn-release-${tag.replace(/[^\w.-]/g, '_')}`)

  const builtLines = []
  const skippedLines = []

  console.log(`Release tag: ${tag}`)
  console.log(`Release tree: ${releaseTree}`)
  if (loadedPaths.length > 0) {
    console.log(`Loaded env files: ${loadedPaths.join(', ')}`)
  }
  if (options.dryRun) {
    console.log('Dry run mode: no build, copy, or publish commands will be executed.')
  }

  const pnpmInvocation = resolveHostPnpmInvocation()

  const steps = [
    ['verify', () => runVerify({ pnpmInvocation, dryRun: options.dryRun, builtLines })],
    ['macos', () => buildMacosArtifacts({ pnpmInvocation, tag, dryRun: options.dryRun, builtLines })],
    ['android', () => buildAndroidArtifacts({ env, pnpmInvocation, tag, dryRun: options.dryRun, builtLines })],
    ['windows', () => buildWindowsArtifacts({ env, tag, dryRun: options.dryRun, builtLines })],
  ]

  for (const [name, fn] of steps) {
    if (!shouldRunStep(name, options)) {
      skippedLines.push(`${name} skipped by CLI options.`)
      continue
    }

    try {
      fn()
    } catch (error) {
      if (error instanceof SkipStepError) {
        skippedLines.push(error.message)
        continue
      }
      if (name === 'verify') {
        throw error
      }
      skippedLines.push(`${name} build failed: ${error.message}`)
    }
  }

  if (
    !skippedLines.some((line) => line.startsWith('Linux')) &&
    process.platform !== 'linux'
  ) {
    skippedLines.push('Linux release artifacts are not built by this host script unless run on Linux or extended with a working local cross toolchain.')
  }

  const commit = run('git', ['rev-parse', 'HEAD'], { capture: true, dryRun: options.dryRun }) || 'HEAD'
  stageRelease({
    tag,
    commit,
    stageDir,
    builtLines,
    skippedLines,
    dryRun: options.dryRun,
  })

  if (options.publish) {
    if (!commandExists('htree')) {
      throw new Error('Missing htree; cannot publish release.')
    }
    const cid = publishRelease({
      stageDir,
      releaseTree,
      tag,
      dryRun: options.dryRun,
    })
    console.log(`Published ${tag} to ${releaseTree} via ${cid}`)
  } else {
    console.log(`Staged release at ${stageDir}`)
  }
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exit(1)
}
