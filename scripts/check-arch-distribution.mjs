#!/usr/bin/env node
// Downstream metadata is advisory: it cannot attest installed package bytes.
import { pathToFileURL } from 'node:url'

export const packages = ['nostr-vpn-bin', 'nostr-vpn-cli-bin']

export async function checkArchDistribution(tag, fetcher = fetch) {
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
    throw new Error('Pass an explicit stable tag, for example v4.1.19.')
  }
  const url = new URL('https://aur.archlinux.org/rpc/v5/info')
  for (const name of packages) url.searchParams.append('arg[]', name)
  const response = await fetcher(url, { signal: AbortSignal.timeout(15000) })
  if (!response.ok) throw new Error(`AUR lookup returned HTTP ${response.status}`)
  const data = await response.json()
  if (data.type !== 'multiinfo' || !Array.isArray(data.results)) {
    throw new Error('AUR returned an invalid package response.')
  }
  return packages.map(name => {
    const matches = data.results.filter(item => item.Name === name)
    if (matches.length > 1) throw new Error(`AUR returned duplicate records for ${name}`)
    const item = matches[0]
    const version = item?.Version ?? null
    // Arch's pkgrel is separate from the application's release version.
    const current = typeof version === 'string' &&
      new RegExp(`^${tag.slice(1).replaceAll('.', '\\.')}-[0-9]+(?:\\.[0-9]+)*$`).test(version)
    return { name, version, current }
  })
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3) throw new Error('Usage: node scripts/check-arch-distribution.mjs vX.Y.Z')
    const tag = process.argv[2]
    const results = await checkArchDistribution(tag)
    for (const item of results) {
      console.log(`AUR ${item.name}: ${item.version ?? 'not listed'} (${item.current ? 'matches' : 'does not match'} ${tag})`)
    }
    console.log('Recipe versions only; this does not verify binaries or Omarchy repository availability.')
    console.log('Omarchy consumes its own upstream release watches after package acceptance; no second upstream build is needed.')
    if (results.some(item => !item.current)) process.exitCode = 1
  } catch (error) {
    console.error(`Arch distribution status unknown: ${error.message}`)
    process.exitCode = 2
  }
}
