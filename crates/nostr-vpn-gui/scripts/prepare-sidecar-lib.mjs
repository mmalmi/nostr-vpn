import { execFileSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

export function resolveBinaryExeSuffix(targetTriple, { hostPlatform = process.platform } = {}) {
  return isWindowsBinaryTarget(targetTriple, { hostPlatform }) ? '.exe' : ''
}

export function isWindowsTarget(targetTriple, { hostPlatform = process.platform } = {}) {
  return (targetTriple && targetTriple.includes('windows')) || hostPlatform === 'win32'
}

export function resolveCargoCommand(
  targetTriple,
  {
    hostPlatform = process.platform,
    hasCommand = commandExists,
  } = {},
) {
  if (
    targetTriple &&
    targetTriple.includes('windows') &&
    hostPlatform !== 'win32' &&
    hasCommand('cargo-xwin')
  ) {
    return 'cargo-xwin'
  }

  return 'cargo'
}

export function resolveTargetTriple(
  workspaceRootPath,
  {
    env = process.env,
    execRustc = (args) =>
      execFileSync('rustc', args, {
        cwd: workspaceRootPath,
        encoding: 'utf8',
      }),
  } = {},
) {
  const envTarget = env.TAURI_ENV_TARGET_TRIPLE || env.CARGO_BUILD_TARGET || env.TARGET
  if (envTarget && envTarget.trim().length > 0) {
    return envTarget.trim()
  }

  try {
    const rustcInfo = execRustc(['-vV'])
    const hostLine = rustcInfo
      .split('\n')
      .find((line) => line.startsWith('host:'))
    if (!hostLine) {
      return null
    }
    const host = hostLine.slice('host:'.length).trim()
    return host.length > 0 ? host : null
  } catch {
    return null
  }
}

export function prepareSidecar({
  release = false,
  hostPlatform = process.platform,
  env = process.env,
  execFile = (command, args, options) => execFileSync(command, args, options),
  scriptPath = fileURLToPath(import.meta.url),
} = {}) {
  const profile = release ? 'release' : 'debug'
  const scriptDir = dirname(scriptPath)
  const guiRoot = resolve(scriptDir, '..')
  const workspaceRoot = resolve(guiRoot, '..', '..')
  const targetTriple = resolveTargetTriple(workspaceRoot, { env })
  const exeSuffix = resolveBinaryExeSuffix(targetTriple, { hostPlatform })
  const cargoArgs = ['build', '--bin', 'nvpn', '-p', 'nostr-vpn-cli']

  if (release) {
    cargoArgs.push('--release')
  }
  if (targetTriple) {
    cargoArgs.push('--target', targetTriple)
  }

  execFile(resolveCargoCommand(targetTriple, { hostPlatform }), cargoArgs, {
    cwd: workspaceRoot,
    stdio: 'inherit',
  })

  const buildTargetRoot = targetTriple
    ? resolve(workspaceRoot, 'target', targetTriple, profile)
    : resolve(workspaceRoot, 'target', profile)

  const sourceBinary = resolve(buildTargetRoot, `nvpn${exeSuffix}`)
  if (!existsSync(sourceBinary)) {
    console.error(`expected nvpn binary at ${sourceBinary}, but it was not found`)
    process.exit(1)
  }

  const sidecarDir = resolve(guiRoot, 'src-tauri', 'binaries')
  mkdirSync(sidecarDir, { recursive: true })

  const sidecarName = targetTriple
    ? `nvpn-${targetTriple}${exeSuffix}`
    : `nvpn${exeSuffix}`
  const sidecarBinary = resolve(sidecarDir, sidecarName)
  copyFileSync(sourceBinary, sidecarBinary)

  if (isWindowsTarget(targetTriple, { hostPlatform })) {
    const sourceDll = resolve(buildTargetRoot, 'wintun.dll')
    if (!existsSync(sourceDll)) {
      console.error(`expected wintun.dll at ${sourceDll}, but it was not found`)
      process.exit(1)
    }

    copyFileSync(sourceDll, resolve(sidecarDir, 'wintun.dll'))
  }

  if (hostPlatform !== 'win32') {
    chmodSync(sidecarBinary, 0o755)
  }

  console.log(
    `prepared nvpn sidecar (${profile}${targetTriple ? `, ${targetTriple}` : ''}): ${sidecarBinary}`,
  )
}

function isWindowsBinaryTarget(targetTriple, { hostPlatform }) {
  if (targetTriple) {
    return targetTriple.includes('windows')
  }

  return hostPlatform === 'win32'
}

function commandExists(command) {
  try {
    execFileSync(command, ['--version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}
