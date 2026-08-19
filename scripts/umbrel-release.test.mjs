import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildPinnedImageRef,
  extractDockerCliPluginPath,
  extractBuildxDigest,
  parsePinnedImageRef,
  renderUmbrelCompose,
  renderUmbrelManifest,
  validatePublishedImageIndex,
  validatePinnedImageRef,
} from './umbrel-release.mjs'

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)))

test('buildPinnedImageRef renders a pinned tag plus digest', () => {
  const digest = `sha256:${'a'.repeat(64)}`
  assert.equal(
    buildPinnedImageRef('ghcr.io/example/nostr-vpn-umbrel', '0.3.4', digest),
    `ghcr.io/example/nostr-vpn-umbrel:v0.3.4@${digest}`,
  )
})

test('validatePinnedImageRef rejects unpinned refs', () => {
  assert.throws(
    () => validatePinnedImageRef('ghcr.io/example/nostr-vpn-umbrel:v0.3.4'),
    /Expected a pinned image reference/,
  )
})

test('parsePinnedImageRef preserves registry ports and exact release tags', () => {
  const digest = `sha256:${'e'.repeat(64)}`
  assert.deepEqual(
    parsePinnedImageRef(`registry.example:5443/team/nvpn:v4.1.7@${digest}`),
    {
      digest,
      imageRef: `registry.example:5443/team/nvpn:v4.1.7@${digest}`,
      imageRepo: 'registry.example:5443/team/nvpn',
      tag: 'v4.1.7',
    },
  )
  assert.throws(
    () => parsePinnedImageRef(`registry.example/team/nvpn@${digest}`),
    /tagged image reference/i,
  )
})

test('extractBuildxDigest reads the primary metadata field', () => {
  const digest = `sha256:${'b'.repeat(64)}`
  const metadata = JSON.stringify({
    'containerimage.digest': digest,
    'containerimage.descriptor': {
      digest,
    },
  })

  assert.equal(extractBuildxDigest(metadata), digest)
})

test('extractDockerCliPluginPath selects one absolute buildx executable', () => {
  assert.equal(
    extractDockerCliPluginPath(JSON.stringify([
      { Name: 'compose', Path: '/opt/docker/docker-compose' },
      { Name: 'buildx', Path: '/opt/docker/docker-buildx' },
    ]), 'buildx'),
    '/opt/docker/docker-buildx',
  )

  for (const value of [
    'not json',
    JSON.stringify([]),
    JSON.stringify([{ Name: 'buildx', Path: 'docker-buildx' }]),
    JSON.stringify([
      { Name: 'buildx', Path: '/one/docker-buildx' },
      { Name: 'buildx', Path: '/two/docker-buildx' },
    ]),
  ]) {
    assert.throws(
      () => extractDockerCliPluginPath(value, 'buildx'),
      /Docker CLI plugin metadata/i,
    )
  }
})

test('published image verification requires both release platforms and allows only attestations besides them', () => {
  const digest = `sha256:${'d'.repeat(64)}`
  const index = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [
      { digest: `sha256:${'1'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' } },
      { digest: `sha256:${'2'.repeat(64)}`, platform: { os: 'linux', architecture: 'arm64' } },
      { digest: `sha256:${'3'.repeat(64)}`, artifactType: 'application/vnd.in-toto+json', platform: { os: 'unknown', architecture: 'unknown' } },
    ],
  })
  assert.deepEqual(
    validatePublishedImageIndex(index, {
      digest,
      imageRef: `ghcr.io/example/nostr-vpn-umbrel@${digest}`,
      platforms: ['linux/amd64', 'linux/arm64'],
    }),
    {
      digest,
      imageRef: `ghcr.io/example/nostr-vpn-umbrel@${digest}`,
      platforms: ['linux/amd64', 'linux/arm64'],
      attestationManifestCount: 1,
    },
  )

  for (const manifests of [
    [{ digest: `sha256:${'1'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' } }],
    [
      { digest: `sha256:${'1'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' } },
      { digest: `sha256:${'2'.repeat(64)}`, platform: { os: 'linux', architecture: 'arm64' } },
      { digest: `sha256:${'4'.repeat(64)}`, platform: { os: 'linux', architecture: 's390x' } },
    ],
  ]) {
    assert.throws(
      () => validatePublishedImageIndex(JSON.stringify({ schemaVersion: 2, manifests }), {
        digest,
        imageRef: `ghcr.io/example/nostr-vpn-umbrel@${digest}`,
        platforms: ['linux/amd64', 'linux/arm64'],
      }),
      /published Umbrel image platforms/i,
    )
  }
})

test('renderUmbrelCompose includes the pinned image and tunnel access', () => {
  const digest = `sha256:${'c'.repeat(64)}`
  const compose = renderUmbrelCompose(
    `ghcr.io/example/nostr-vpn-umbrel:v0.3.4@${digest}`,
  )

  assert.match(compose, /image: ghcr\.io\/example\/nostr-vpn-umbrel:v0\.3\.4@sha256:c+/)
  assert.match(compose, /app_proxy:/)
  assert.match(compose, /APP_HOST: nostr-vpn_web_1/)
  assert.match(compose, /daemon:/)
  assert.equal(compose.match(/restart: unless-stopped/g)?.length, 3)
  assert.doesNotMatch(compose, /^version:/m)
  assert.match(compose, /network_mode: "host"/)
  assert.match(compose, /\/dev\/net\/tun:\/dev\/net\/tun/)
  assert.match(compose, /\$\{APP_DATA_DIR\}\/data:\/data/)
  assert.match(compose, /NVPN_DAEMON_STATUS_MODE: state-file/)
  assert.match(compose, /NVPN_EXTERNAL_DAEMON: "true"/)
  assert.match(compose, /^      APP_PORT: 38080$/m)
  assert.match(
    compose,
    /^    command:\n      - --listen\n      - 0\.0\.0\.0:38080\n      - --behind-trusted-proxy\n      - --config\n      - \/data\/config\/nvpn\/config\.toml$/m,
  )
})

test('renderUmbrelManifest syncs version and release notes', () => {
  const manifest = renderUmbrelManifest(
    `manifestVersion: 1
version: "v0.3.4"
releaseNotes: ""
submission: ""
`,
    {
      tag: '0.3.5',
      releaseNotes: 'https://example.test/releases/v0.3.5',
    },
  )

  assert.match(manifest, /^version: "v0\.3\.5"$/m)
  assert.match(manifest, /^releaseNotes: "https:\/\/example\.test\/releases\/v0\.3\.5"$/m)
  assert.doesNotMatch(manifest, /^submission: ""$/m)
})

test('base Umbrel manifest does not ship a blank submission URL', () => {
  const manifest = readFileSync(join(repoRoot, 'umbrel/umbrel-app.yml'), 'utf8')
  assert.doesNotMatch(manifest, /^submission:\s*""$/m)
})

test('base Umbrel manifest uses the app-store port assigned for Nostr VPN', () => {
  const manifest = readFileSync(join(repoRoot, 'umbrel/umbrel-app.yml'), 'utf8')
  assert.match(manifest, /^port: 38180$/m)
})

test('base Umbrel app includes an exports file', () => {
  assert.equal(existsSync(join(repoRoot, 'umbrel/exports.sh')), true)
})

test('Umbrel publication uses anonymous digest readback and atomic append-only bundles', () => {
  const source = readFileSync(join(repoRoot, 'scripts/umbrel-release.mjs'), 'utf8')
  assert.match(source, /DOCKER_CONFIG:\s*anonymousDockerConfig/)
  assert.match(source, /'DOCKER_AUTH_CONFIG',[\s\S]*?'REGISTRY_AUTH_FILE'/)
  assert.match(source, /delete publicEnvironment\[name\]/)
  assert.match(source, /resolveDockerCliPluginExecutable\('buildx'\)/)
  assert.match(source, /\['imagetools', 'inspect', '--raw', digestRef\]/)
  assert.doesNotMatch(source, /\['buildx', 'imagetools', 'inspect', '--raw', digestRef\]/)
  assert.match(source, /Refusing to replace existing Umbrel bundle/)
  assert.match(source, /renameSync\(temporary, outputDir\)/)
  assert.match(source, /publication\.bundleFiles = Object\.fromEntries/)
  assert.match(source, /anonymousRegistryReadback:\s*inspection\.anonymousReadback/)
  assert.match(source, /verifyPublishedUmbrelRelease\(\{[\s\S]*?imageRef/)
  assert.match(source, /const parsed = parsePinnedImageRef\(imageRef\)/)
  assert.match(source, /const verified = verifyPublishedUmbrelRelease\(\{/)
})
