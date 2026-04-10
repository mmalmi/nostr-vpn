import { statSync } from 'node:fs'
import { basename } from 'node:path'

export function parseEnvFile(text) {
  const values = {}
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) {
      continue
    }

    const separator = line.indexOf('=')
    if (separator <= 0) {
      continue
    }

    const key = line.slice(0, separator).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue
    }

    let value = line.slice(separator + 1).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }

    value = value
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')

    values[key] = value
  }

  return values
}

export function splitCsv(value) {
  return (value || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
}

export function readWorkspaceVersionTag(cargoTomlText) {
  const match = cargoTomlText.match(
    /^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"\n]+)"/m,
  )
  if (!match) {
    throw new Error('Could not find [workspace.package] version in Cargo.toml')
  }

  return normalizeTag(match[1])
}

export function normalizeTag(value) {
  if (!value || !value.trim()) {
    throw new Error('Release tag must not be empty')
  }

  return value.startsWith('v') ? value : `v${value}`
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function extractChangelogSection(changelogText, tag) {
  const version = normalizeTag(tag).replace(/^v/, '')
  const headingPattern = new RegExp(`^##\\s+${escapeRegExp(version)}(?:\\s+-\\s+.*)?\\s*$`, 'm')
  const headingMatch = changelogText.match(headingPattern)
  if (!headingMatch || headingMatch.index == null) {
    return null
  }

  const sectionStart = headingMatch.index + headingMatch[0].length
  const remainder = changelogText.slice(sectionStart).replace(/^\r?\n/, '')
  const nextHeadingMatch = remainder.match(/^##\s+/m)
  const section = nextHeadingMatch ? remainder.slice(0, nextHeadingMatch.index) : remainder
  const trimmed = section.trim()
  return trimmed || null
}

export function autoDetectWindowsVmName(prlctlListOutput) {
  const candidates = []
  for (const line of prlctlListOutput.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) {
      continue
    }

    const match = trimmed.match(/^\{[^}]+\}\s+(\S+)\s+\S+\s+(.+)$/)
    if (!match) {
      continue
    }

    const status = match[1].toLowerCase()
    const name = match[2].trim()
    if ((status === 'running' || status === 'suspended') && /windows/i.test(name)) {
      candidates.push(name)
    }
  }

  return candidates.length === 1 ? candidates[0] : null
}

export function describeAsset(name) {
  if (/^nostr-vpn-.*-macos-arm64\.zip$/.test(name)) {
    return 'macOS Apple Silicon app'
  }
  if (/^nostr-vpn-.*-linux-x64\.AppImage$/.test(name)) {
    return 'Linux x64 AppImage'
  }
  if (/^nostr-vpn-.*-linux-x64\.deb$/.test(name)) {
    return 'Linux x64 Debian package'
  }
  if (/^nostr-vpn-.*-windows-x64-setup\.exe$/.test(name)) {
    return 'Windows x64 installer'
  }
  if (/^nostr-vpn-.*-windows-arm64-setup\.exe$/.test(name)) {
    return 'Windows ARM64 installer'
  }
  if (/^nostr-vpn-.*-android-arm64(?:-unsigned)?\.apk$/.test(name)) {
    return name.includes('-unsigned.') ? 'Android arm64 APK (unsigned)' : 'Android arm64 APK'
  }
  if (/^nostr-vpn-.*-android-arm64(?:-unsigned)?\.aab$/.test(name)) {
    return name.includes('-unsigned.') ? 'Android arm64 AAB (unsigned)' : 'Android arm64 AAB'
  }
  if (/^nvpn-.*-aarch64-apple-darwin\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Apple Silicon CLI (versioned)' : 'Apple Silicon CLI'
  }
  if (/^nvpn-.*-x86_64-unknown-linux-musl\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Linux x64 CLI (versioned)' : 'Linux x64 CLI'
  }
  if (/^nvpn-.*-aarch64-unknown-linux-musl\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Linux ARM64 CLI (versioned)' : 'Linux ARM64 CLI'
  }
  if (/^nvpn-.*-x86_64-pc-windows-msvc\.zip$/.test(name)) {
    return 'Windows x64 CLI'
  }
  if (/^nvpn-.*-aarch64-pc-windows-msvc\.zip$/.test(name)) {
    return 'Windows ARM64 CLI'
  }

  return name
}

export function androidReleaseAssetName(tag, { extension = 'apk', signed = true } = {}) {
  const normalizedTag = normalizeTag(tag)
  const suffix = signed ? '' : '-unsigned'
  return `nostr-vpn-${normalizedTag}-android-arm64${suffix}.${extension}`
}

export function buildReleaseManifest({ tag, commit, createdAt, assetPaths }) {
  const normalizedTag = normalizeTag(tag)
  const assets = [...assetPaths]
    .map((assetPath) => ({
      name: basename(assetPath),
      path: `assets/${basename(assetPath)}`,
      size: statSync(assetPath).size,
    }))
    .sort((left, right) => left.name.localeCompare(right.name))

  return {
    id: normalizedTag,
    title: normalizedTag,
    tag: normalizedTag,
    commit,
    created_at: createdAt,
    published_at: createdAt,
    draft: false,
    prerelease: normalizedTag.includes('-'),
    notes_file: 'notes.md',
    assets,
  }
}

export function renderReleaseNotes({
  tag,
  commit,
  assetNames,
  builtLines = [],
  skippedLines = [],
  changelogText = '',
  assetBaseUrl = '',
}) {
  const normalizedTag = normalizeTag(tag)
  const lines = []
  const changelogSection = extractChangelogSection(changelogText, normalizedTag)
  const visibleSkippedLines = skippedLines.filter((line) => !line.endsWith('skipped by CLI options.'))

  if (changelogSection) {
    lines.push('## Changes', '', ...changelogSection.split('\n'), '')
  }

  lines.push('## Downloads', '')

  for (const name of [...assetNames].sort((left, right) => left.localeCompare(right))) {
    if (assetBaseUrl) {
      lines.push(`- ${describeAsset(name)}: [${name}](${assetBaseUrl}/${name})`)
    } else {
      lines.push(`- ${describeAsset(name)}: \`${name}\``)
    }
  }

  if (commit || builtLines.length > 0) {
    lines.push('', '## Release Build', '')
    if (commit) {
      lines.push(`- Built from commit \`${commit}\` for release \`${normalizedTag}\`.`)
    }
  }

  for (const line of builtLines) {
    lines.push(`- ${line}`)
  }

  if (visibleSkippedLines.length > 0) {
    lines.push('', '## Skipped or Not Built', '')
    for (const line of visibleSkippedLines) {
      lines.push(`- ${line}`)
    }
  }

  return `${lines.join('\n')}\n`
}
