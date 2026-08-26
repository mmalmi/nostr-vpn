#!/usr/bin/env node
// Marketing-version source of truth: [workspace.package].version in
// /Cargo.toml. iOS CFBundleVersion is intentionally independent and comes
// from /ios/app-store-build-number so corrected App Store uploads can advance
// without changing the public marketing version.
//
//   node scripts/sync-versions.mjs            # write (idempotent)
//   node scripts/sync-versions.mjs --check    # exit 1 if any file is stale

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  bumpAndroidGradleVersion,
  bumpStartosSourceVersion,
} from './local-release-lib.mjs'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function readWorkspaceVersion() {
  const text = readFileSync(join(repoRoot, 'Cargo.toml'), 'utf8')
  const match = text.match(/^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"\n]+)"/m)
  if (!match) {
    throw new Error('Could not find [workspace.package] version in Cargo.toml')
  }
  return match[1].trim()
}

function appleVersionCode(version) {
  const core = version.split(/[-+]/, 1)[0]
  const parts = core.split('.').map((part) => parseInt(part, 10))
  if (parts.length === 0 || parts.some((value) => Number.isNaN(value))) {
    throw new Error(`Could not derive Apple build number from "${version}"`)
  }
  const [major = 0, minor = 0, patch = 0] = parts
  if (minor > 999 || patch > 999) {
    throw new Error(
      `Apple build number formula needs an update for "${version}" (minor/patch > 999)`,
    )
  }
  return major * 1_000_000 + minor * 1_000 + patch
}

function readIosBuildNumber() {
  const buildNumber = readFileSync(
    join(repoRoot, 'ios', 'app-store-build-number'),
    'utf8',
  ).trim()
  if (!/^[1-9][0-9]*$/.test(buildNumber)) {
    throw new Error(
      `ios/app-store-build-number must contain a positive integer, got "${buildNumber}"`,
    )
  }
  return buildNumber
}

function versionTag(version) {
  return version.startsWith('v') ? version : `v${version}`
}

function makeTarget(relPath, transform) {
  return {
    relPath,
    apply(currentText, version) {
      return transform(currentText, version)
    },
  }
}

function bumpCargoLockPackages(text, packageNames, version) {
  let updated = text
  for (const packageName of packageNames) {
    const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const packagePattern = new RegExp(
      `(\\[\\[package\\]\\]\\nname = "${escapedName}"\\nversion = ")[^"\\n]+(")`,
      'g',
    )
    const matches = [...updated.matchAll(packagePattern)]
    if (matches.length !== 1) {
      throw new Error(
        `Expected exactly one ${packageName} package in Cargo.lock, found ${matches.length}`,
      )
    }
    updated = updated.replace(
      packagePattern,
      (_, prefix, suffix) => `${prefix}${version}${suffix}`,
    )
  }
  return updated
}

const targets = [
  makeTarget('linux/Cargo.toml', (text, version) =>
    text.replace(
      /^(version\s*=\s*")[^"\n]+(")/m,
      (_, prefix, suffix) => `${prefix}${version}${suffix}`,
    ),
  ),
  makeTarget('linux/Cargo.lock', (text, version) =>
    bumpCargoLockPackages(
      text,
      ['nostr-vpn-app-core', 'nostr-vpn-core', 'nostr-vpn-linux'],
      version,
    ),
  ),
  // ios/project.yml + macos/project.yml use plain ${NVPN_APP_VERSION_NAME} /
  // ${NVPN_APP_VERSION_CODE} substitution. Entry-point scripts resolve those
  // immediately before xcodegen: macOS derives both from Cargo, while iOS uses
  // Cargo for marketing version and ios/app-store-build-number for
  // CFBundleVersion.
  makeTarget('macos/NostrVpnMac.xcodeproj/project.pbxproj', (text, version) => {
    const code = appleVersionCode(version)
    return text
      .replace(
        /(\bMARKETING_VERSION\s*=\s*)[^;]+(;)/g,
        (_, prefix, suffix) => `${prefix}${version}${suffix}`,
      )
      .replace(
        /(\bCURRENT_PROJECT_VERSION\s*=\s*)[^;]+(;)/g,
        (_, prefix, suffix) => `${prefix}${code}${suffix}`,
      )
  }),
  makeTarget('ios/NostrVpnIos.xcodeproj/project.pbxproj', (text, version) => {
    const code = readIosBuildNumber()
    return text
      .replace(
        /(\bMARKETING_VERSION\s*=\s*)[^;]+(;)/g,
        (_, prefix, suffix) => `${prefix}${version}${suffix}`,
      )
      .replace(
        /(\bCURRENT_PROJECT_VERSION\s*=\s*)[^;]+(;)/g,
        (_, prefix, suffix) => `${prefix}${code}${suffix}`,
      )
  }),
  makeTarget('android/app/build.gradle.kts', (text, version) =>
    bumpAndroidGradleVersion(text, version),
  ),
  makeTarget('windows/NostrVpn.Windows/NostrVpn.Windows.csproj', (text, version) =>
    text.replace(
      /(<Version>)[^<]+(<\/Version>)/,
      (_, prefix, suffix) => `${prefix}${version}${suffix}`,
    ),
  ),
  makeTarget('umbrel/umbrel-app.yml', (text, version) =>
    text.replace(
      /^(version:\s*")[^"\n]+(")/m,
      (_, prefix, suffix) => `${prefix}${versionTag(version)}${suffix}`,
    ),
  ),
  makeTarget('startos/versions/current.ts', (text, version) =>
    bumpStartosSourceVersion(text, version),
  ),
]

function main() {
  const checkOnly = process.argv.includes('--check')
  const version = readWorkspaceVersion()
  let stale = []
  let updated = []

  for (const target of targets) {
    const path = join(repoRoot, target.relPath)
    const before = readFileSync(path, 'utf8')
    const after = target.apply(before, version)
    if (after === before) continue
    if (checkOnly) {
      stale.push(target.relPath)
    } else {
      writeFileSync(path, after)
      updated.push(target.relPath)
    }
  }

  if (checkOnly) {
    if (stale.length === 0) {
      console.log(`Versions in sync at ${version}.`)
      return
    }
    console.error(
      `Versions out of sync with workspace ${version}:\n  - ${stale.join('\n  - ')}\n` +
        `Run \`node scripts/sync-versions.mjs\` to fix.`,
    )
    process.exit(1)
  }

  if (updated.length === 0) {
    console.log(`All version files already at ${version}.`)
  } else {
    console.log(`Synced ${updated.length} file(s) to ${version}:\n  - ${updated.join('\n  - ')}`)
  }
}

main()
