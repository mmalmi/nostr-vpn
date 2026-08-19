#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  accessSync,
  constants as fsConstants,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { normalizeTag, readWorkspaceVersionTag, splitCsv } from './local-release-lib.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '..')
const rootCargoToml = join(repoRoot, 'Cargo.toml')
const umbrelDir = join(repoRoot, 'umbrel')
const baseComposePath = join(umbrelDir, 'docker-compose.yml')
const baseManifestPath = join(umbrelDir, 'umbrel-app.yml')
const baseIconPath = join(umbrelDir, 'icon.svg')
const baseExportsPath = join(umbrelDir, 'exports.sh')

function usage() {
  console.log(`Usage: node scripts/umbrel-release.mjs [options]

Generate a submission-ready Umbrel app bundle with a pinned container image.

Options:
  --image-ref <ref>       Full pinned image reference (repo:tag@sha256:...)
  --push                  Build and push the multi-arch image before rendering
  --image-repo <repo>     Registry repository to push (required with --push)
  --tag <tag>             Release tag (defaults to workspace version)
  --platforms <csv>       Target platforms (default: linux/amd64,linux/arm64)
  --output-dir <path>     Bundle output directory (default: dist/umbrel-vX.Y.Z)
  --dry-run               Print actions without writing a bundle
  --help                  Show this help

Examples:
  node scripts/umbrel-release.mjs \\
    --image-ref ghcr.io/example/nostr-vpn-umbrel:v0.3.4@sha256:...

  node scripts/umbrel-release.mjs \\
    --push \\
    --image-repo ghcr.io/example/nostr-vpn-umbrel`)
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    imageRef: null,
    imageRepo: null,
    outputDir: null,
    platforms: ['linux/amd64', 'linux/arm64'],
    push: false,
    tag: null,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    switch (arg) {
      case '--help':
      case '-h':
        usage()
        process.exit(0)
      case '--dry-run':
        options.dryRun = true
        break
      case '--image-ref':
        options.imageRef = argv[++index] ?? ''
        break
      case '--image-repo':
        options.imageRepo = argv[++index] ?? ''
        break
      case '--output-dir':
        options.outputDir = argv[++index] ?? ''
        break
      case '--platforms':
      case '--platform':
        options.platforms = splitCsv(argv[++index] ?? '')
        break
      case '--push':
        options.push = true
        break
      case '--tag':
        options.tag = normalizeTag(argv[++index] ?? '')
        break
      default:
        throw new Error(`Unknown argument: ${arg}`)
    }
  }

  return options
}

function quote(arg) {
  const value = String(arg)
  return /[^\w./:@=-]/.test(value) ? JSON.stringify(value) : value
}

function run(
  command,
  args,
  {
    capture = false,
    cwd = repoRoot,
    dryRun = false,
    env = process.env,
  } = {},
) {
  const rendered = [command, ...args].map(quote).join(' ')
  console.log(`$ ${rendered}`)

  if (dryRun) {
    return ''
  }

  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env,
    stdio: capture ? 'pipe' : 'inherit',
  })

  if (result.status !== 0) {
    const stderr = capture ? result.stderr.trim() : ''
    throw new Error(stderr || `${command} exited with status ${result.status ?? 'unknown'}`)
  }

  return capture ? result.stdout.trim() : ''
}

function commandExists(command) {
  const result =
    process.platform === 'win32'
      ? spawnSync('where', [command], { stdio: 'ignore' })
      : spawnSync('sh', ['-lc', `command -v "${command}"`], { stdio: 'ignore' })
  return result.status === 0
}

export function extractDockerCliPluginPath(infoText, pluginName) {
  let plugins
  try {
    plugins = JSON.parse(infoText)
  } catch {
    throw new Error('Docker CLI plugin metadata is not valid JSON')
  }
  const matches = Array.isArray(plugins)
    ? plugins.filter((plugin) => plugin?.Name === pluginName)
    : []
  const pluginPath = matches.length === 1 ? String(matches[0]?.Path ?? '').trim() : ''
  if (!isAbsolute(pluginPath)) {
    throw new Error(
      `Docker CLI plugin metadata must contain exactly one absolute ${pluginName} path`,
    )
  }
  return pluginPath
}

function resolveDockerCliPluginExecutable(pluginName) {
  const pluginPath = extractDockerCliPluginPath(
    run(
      'docker',
      ['info', '--format', '{{json .ClientInfo.Plugins}}'],
      { capture: true },
    ),
    pluginName,
  )
  const executable = realpathSync(pluginPath)
  if (!statSync(executable).isFile()) {
    throw new Error(`Docker CLI plugin is not a regular file: ${pluginPath}`)
  }
  accessSync(executable, fsConstants.X_OK)
  return executable
}

function resolveReleaseTag(explicitTag) {
  if (explicitTag) {
    return normalizeTag(explicitTag)
  }
  return readWorkspaceVersionTag(readFileSync(rootCargoToml, 'utf8'))
}

function defaultOutputDir(tag) {
  return join(repoRoot, 'dist', `umbrel-${normalizeTag(tag)}`)
}

export function buildPinnedImageRef(imageRepo, tag, digest) {
  const normalizedTag = normalizeTag(tag)
  const trimmedRepo = String(imageRepo ?? '').trim().replace(/\/$/, '')
  if (!trimmedRepo) {
    throw new Error('Image repository must not be empty')
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(String(digest ?? '').trim())) {
    throw new Error(`Invalid image digest: ${digest}`)
  }
  return `${trimmedRepo}:${normalizedTag}@${digest.trim()}`
}

export function validatePinnedImageRef(imageRef) {
  const trimmed = String(imageRef ?? '').trim()
  if (!/^.+@sha256:[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error(`Expected a pinned image reference ending with @sha256:..., got: ${imageRef}`)
  }
  return trimmed
}

export function parsePinnedImageRef(imageRef) {
  const pinned = validatePinnedImageRef(imageRef)
  const at = pinned.lastIndexOf('@')
  const tagged = pinned.slice(0, at)
  const tagSeparator = tagged.lastIndexOf(':')
  if (tagSeparator <= tagged.lastIndexOf('/')) {
    throw new Error(`Expected a tagged image reference before the digest: ${imageRef}`)
  }
  return {
    digest: pinned.slice(at + 1),
    imageRef: pinned,
    imageRepo: normalizeImageRepo(tagged.slice(0, tagSeparator)),
    tag: normalizeTag(tagged.slice(tagSeparator + 1)),
  }
}

export function extractBuildxDigest(metadataText) {
  const metadata = JSON.parse(metadataText)
  const candidates = [
    metadata['containerimage.digest'],
    metadata.containerimage?.digest,
    metadata['containerimage.descriptor']?.digest,
    metadata.containerimage?.descriptor?.digest,
  ]

  const digest = candidates.find((value) => /^sha256:[0-9a-f]{64}$/.test(String(value ?? '')))
  if (!digest) {
    throw new Error('Could not find container image digest in docker buildx metadata')
  }
  return digest
}

function normalizePlatforms(platforms) {
  const values = [...new Set((platforms ?? []).map((value) => String(value).trim()))]
  if (
    values.length !== 2
    || values[0] !== 'linux/amd64'
    || values[1] !== 'linux/arm64'
  ) {
    throw new Error(
      `Umbrel release platforms must be exactly linux/amd64,linux/arm64; got ${values.join(',')}`,
    )
  }
  return values
}

function normalizeImageRepo(imageRepo) {
  const value = String(imageRepo ?? '').trim().replace(/\/$/, '')
  if (!/^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+$/i.test(value)) {
    throw new Error(`Invalid Umbrel image repository: ${imageRepo}`)
  }
  return value
}

export function validatePublishedImageIndex(
  indexText,
  { digest, imageRef, platforms },
) {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(digest ?? ''))) {
    throw new Error(`Invalid published Umbrel image digest: ${digest}`)
  }
  if (
    validatePinnedImageRef(imageRef) !== imageRef
    || !imageRef.endsWith(`@${digest}`)
  ) {
    throw new Error('Published Umbrel image reference is not bound to the expected digest')
  }
  const expected = normalizePlatforms(platforms)
  let index
  try {
    index = JSON.parse(indexText)
  } catch {
    throw new Error('Published Umbrel image index is not valid JSON')
  }
  if (
    index?.schemaVersion !== 2
    || !Array.isArray(index.manifests)
  ) {
    throw new Error('Published Umbrel image index has an invalid shape')
  }

  const runnable = []
  let attestationManifestCount = 0
  for (const descriptor of index.manifests) {
    if (!/^sha256:[0-9a-f]{64}$/.test(String(descriptor?.digest ?? ''))) {
      throw new Error('Published Umbrel image index contains an invalid descriptor digest')
    }
    const osName = String(descriptor?.platform?.os ?? '')
    const architecture = String(descriptor?.platform?.architecture ?? '')
    if (osName === 'unknown' && architecture === 'unknown') {
      const referenceType = descriptor?.annotations?.['vnd.docker.reference.type']
      if (!descriptor?.artifactType && referenceType !== 'attestation-manifest') {
        throw new Error('Published Umbrel image index contains an unclassified unknown platform')
      }
      attestationManifestCount += 1
      continue
    }
    const variant = String(descriptor?.platform?.variant ?? '').trim()
    runnable.push(`${osName}/${architecture}${variant ? `/${variant}` : ''}`)
  }
  runnable.sort()
  const sortedExpected = [...expected].sort()
  if (
    runnable.length !== sortedExpected.length
    || runnable.some((value, indexValue) => value !== sortedExpected[indexValue])
  ) {
    throw new Error(
      `Published Umbrel image platforms differ: expected ${sortedExpected.join(',')}; got ${runnable.join(',')}`,
    )
  }
  return {
    digest,
    imageRef,
    platforms: expected,
    attestationManifestCount,
  }
}

export function preflightUmbrelPublication({
  dryRun = false,
  imageRepo,
  platforms = ['linux/amd64', 'linux/arm64'],
} = {}) {
  const normalized = {
    imageRepo: normalizeImageRepo(imageRepo),
    platforms: normalizePlatforms(platforms),
  }
  if (!dryRun) {
    if (!commandExists('docker')) {
      throw new Error('Missing docker; cannot publish the required Umbrel image')
    }
    const buildx = spawnSync('docker', ['buildx', 'version'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: 'pipe',
    })
    if (buildx.status !== 0) {
      throw new Error('Docker buildx is unavailable; cannot publish the required Umbrel image')
    }
  }
  return normalized
}

function releaseNotesUrl(tag) {
  return `https://github.com/mmalmi/nostr-vpn/releases/tag/${normalizeTag(tag)}`
}

function renderBundleReadme({ imageRef, tag }) {
  return `# Nostr VPN Umbrel bundle

This directory is a submission-ready Umbrel app bundle for ${normalizeTag(tag)}.

Pinned image:

\`${imageRef}\`

Files:

- \`docker-compose.yml\`: Umbrel app service definition
- \`umbrel-app.yml\`: Umbrel metadata with synced version and release notes
- \`exports.sh\`: empty app exports file
- \`icon.svg\`: app icon
- \`IMAGE.txt\`: pinned container image reference used for this bundle
- \`publication.json\`: public registry readback and bundle-file digests

The real app compose uses Umbrel's built-in \`app_proxy\` service, so validate
the app inside umbrelOS. For ordinary Docker validation, use the repo's local
Compose file:

\`\`\`sh
docker compose -f umbrel/docker-compose.local.yml config
\`\`\`
`
}

export function renderUmbrelCompose(
  imageRef,
  templateText = readFileSync(baseComposePath, 'utf8'),
) {
  const pinnedRef = validatePinnedImageRef(imageRef)
  let replacementCount = 0
  const compose = templateText.replace(
    /^(\s*image:\s*)nostr-vpn-umbrel:local\s*$/gm,
    (_line, prefix) => {
      replacementCount += 1
      return `${prefix}${pinnedRef}`
    },
  )
  if (replacementCount !== 2) {
    throw new Error(
      `Expected canonical Umbrel compose to contain exactly two local image references, found ${replacementCount}`,
    )
  }
  return compose.endsWith('\n') ? compose : `${compose}\n`
}

export function renderUmbrelManifest(templateText, { tag, releaseNotes } = {}) {
  const normalizedTag = normalizeTag(tag)
  let manifest = templateText.replace(/^version: .*$/m, `version: "${normalizedTag}"`)
  if (releaseNotes) {
    manifest = manifest.replace(/^releaseNotes: .*$/m, `releaseNotes: "${releaseNotes}"`)
  }
  manifest = manifest.replace(/^submission:\s*""\s*\r?\n/m, '')
  return manifest.endsWith('\n') ? manifest : `${manifest}\n`
}

function writeBundle({ imageRef, outputDir, publication = null, tag }) {
  const parent = dirname(outputDir)
  mkdirSync(parent, { recursive: true })
  if (existsSync(outputDir)) {
    throw new Error(`Refusing to replace existing Umbrel bundle: ${outputDir}`)
  }
  const temporary = mkdtempSync(join(parent, `.${basename(outputDir)}.`))
  let completed = false
  try {
    copyFileSync(baseIconPath, join(temporary, 'icon.svg'))
    copyFileSync(baseExportsPath, join(temporary, 'exports.sh'))
    writeFileSync(join(temporary, 'README.md'), renderBundleReadme({ imageRef, tag }))
    writeFileSync(join(temporary, 'docker-compose.yml'), renderUmbrelCompose(imageRef))
    writeFileSync(
      join(temporary, 'umbrel-app.yml'),
      renderUmbrelManifest(readFileSync(baseManifestPath, 'utf8'), {
        releaseNotes: releaseNotesUrl(tag),
        tag,
      }),
    )
    writeFileSync(join(temporary, 'IMAGE.txt'), `${imageRef}\n`)
    if (publication) {
      publication.bundleFiles = Object.fromEntries(
        [
          'IMAGE.txt',
          'README.md',
          'docker-compose.yml',
          'exports.sh',
          'icon.svg',
          'umbrel-app.yml',
        ].map((name) => [
          name,
          createHash('sha256').update(readFileSync(join(temporary, name))).digest('hex'),
        ]),
      )
      writeFileSync(
        join(temporary, 'publication.json'),
        `${JSON.stringify(publication, null, 2)}\n`,
      )
    }
    renameSync(temporary, outputDir)
    completed = true
  } finally {
    if (!completed) {
      rmSync(temporary, { force: true, recursive: true })
    }
  }
}

function buildAndPushImage({ beforeMutation, dryRun, imageRepo, platforms, tag }) {
  if (!imageRepo) {
    throw new Error('--image-repo is required with --push')
  }
  if (!commandExists('docker')) {
    throw new Error('Missing docker; cannot build or push Umbrel image')
  }

  const tempDir = mkdtempSync(join(os.tmpdir(), 'nostr-vpn-umbrel-'))
  const metadataPath = join(tempDir, 'buildx-metadata.json')

  try {
    beforeMutation?.()
    run(
      'docker',
      [
        'buildx',
        'build',
        '--platform',
        platforms.join(','),
        '--file',
        'umbrel/Dockerfile',
        '--tag',
        `${imageRepo}:${tag}`,
        '--metadata-file',
        metadataPath,
        '--push',
        '.',
      ],
      { cwd: repoRoot, dryRun },
    )

    if (dryRun) {
      return null
    }

    const digest = extractBuildxDigest(readFileSync(metadataPath, 'utf8'))
    return buildPinnedImageRef(imageRepo, tag, digest)
  } finally {
    rmSync(tempDir, { force: true, recursive: true })
  }
}

function inspectPublishedImage({ digest, imageRepo, platforms, tag }) {
  const imageRef = buildPinnedImageRef(imageRepo, tag, digest)
  const digestRef = `${normalizeImageRepo(imageRepo)}@${digest}`
  const buildxExecutable = resolveDockerCliPluginExecutable('buildx')
  const anonymousDockerConfig = mkdtempSync(
    join(os.tmpdir(), 'nostr-vpn-umbrel-public-readback-'),
  )
  try {
    const publicEnvironment = {
      ...process.env,
      DOCKER_CONFIG: anonymousDockerConfig,
    }
    for (const name of [
      'BUILDX_CONFIG',
      'DOCKER_AUTH_CONFIG',
      'REGISTRY_AUTH_FILE',
    ]) {
      delete publicEnvironment[name]
    }
    const indexText = run(
      buildxExecutable,
      ['imagetools', 'inspect', '--raw', digestRef],
      {
        capture: true,
        env: publicEnvironment,
      },
    )
    const validation = validatePublishedImageIndex(indexText, {
      digest,
      imageRef,
      platforms,
    })
    return {
      ...validation,
      anonymousReadback: true,
      indexSha256: createHash('sha256').update(indexText).digest('hex'),
    }
  } finally {
    rmSync(anonymousDockerConfig, { force: true, recursive: true })
  }
}

export function publishVerifiedUmbrelRelease({
  beforeMutation,
  dryRun = false,
  imageRepo,
  outputDir,
  platforms = ['linux/amd64', 'linux/arm64'],
  tag,
} = {}) {
  const preflight = preflightUmbrelPublication({ dryRun, imageRepo, platforms })
  const normalizedTag = normalizeTag(tag)
  const targetDir = resolve(repoRoot, outputDir || defaultOutputDir(normalizedTag))
  const imageRef = buildAndPushImage({
    beforeMutation,
    dryRun,
    imageRepo: preflight.imageRepo,
    platforms: preflight.platforms,
    tag: normalizedTag,
  })
  if (dryRun) {
    console.log(`Would anonymously verify ${preflight.imageRepo}:${normalizedTag} by immutable digest`)
    console.log(`Would write verified Umbrel bundle to ${targetDir}`)
    return { published: false, imageRef: null, outputDir: targetDir }
  }
  const verified = verifyPublishedUmbrelRelease({
    imageRef,
    imageRepo: preflight.imageRepo,
    outputDir: targetDir,
    platforms: preflight.platforms,
    tag: normalizedTag,
  })
  return { ...verified, reusedPublishedImage: false }
}

export function verifyPublishedUmbrelRelease({
  imageRef,
  imageRepo,
  outputDir,
  platforms = ['linux/amd64', 'linux/arm64'],
  tag,
} = {}) {
  const preflight = preflightUmbrelPublication({ imageRepo, platforms })
  const normalizedTag = normalizeTag(tag)
  const targetDir = resolve(repoRoot, outputDir || defaultOutputDir(normalizedTag))
  const expected = buildPinnedImageRef(
    preflight.imageRepo,
    normalizedTag,
    parsePinnedImageRef(imageRef).digest,
  )
  if (imageRef !== expected) {
    throw new Error(`Pinned Umbrel image does not match ${preflight.imageRepo}:${normalizedTag}`)
  }
  const digest = imageRef.slice(imageRef.lastIndexOf('@') + 1)
  const inspection = inspectPublishedImage({
    digest,
    imageRepo: preflight.imageRepo,
    platforms: preflight.platforms,
    tag: normalizedTag,
  })
  const publication = {
    receiptSchema: 1,
    status: 'published-and-publicly-verified',
    tag: normalizedTag,
    imageRepository: preflight.imageRepo,
    imageRef,
    digest,
    platforms: inspection.platforms,
    attestationManifestCount: inspection.attestationManifestCount,
    anonymousRegistryReadback: inspection.anonymousReadback,
    imageIndexSha256: inspection.indexSha256,
  }
  writeBundle({ imageRef, outputDir: targetDir, publication, tag: normalizedTag })
  return {
    published: true,
    imageRef,
    outputDir: targetDir,
    publication,
    reusedPublishedImage: true,
  }
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv)
  const tag = resolveReleaseTag(options.tag)
  const outputDir = resolve(repoRoot, options.outputDir || defaultOutputDir(tag))

  let imageRef = options.imageRef ? validatePinnedImageRef(options.imageRef) : null
  if (!imageRef && options.push) {
    const published = publishVerifiedUmbrelRelease({
      dryRun: options.dryRun,
      imageRepo: options.imageRepo,
      outputDir,
      platforms: options.platforms,
      tag,
    })
    if (options.dryRun) return
    imageRef = published.imageRef
    console.log(`Wrote Umbrel bundle to ${published.outputDir}`)
    console.log(`Pinned image: ${imageRef}`)
    return
  }

  if (!imageRef) {
    if (options.dryRun && options.push) {
      console.log('Dry run: image build command rendered; bundle not written because no digest is available.')
      return
    }
    throw new Error('Pass --image-ref or use --push --image-repo')
  }

  if (options.dryRun) {
    console.log(`Would write Umbrel bundle to ${outputDir}`)
    console.log(`Pinned image: ${imageRef}`)
    return
  }

  const parsed = parsePinnedImageRef(imageRef)
  if (parsed.tag !== tag) {
    throw new Error(`Pinned Umbrel image tag ${parsed.tag} does not match release tag ${tag}`)
  }
  const verified = verifyPublishedUmbrelRelease({
    imageRef,
    imageRepo: parsed.imageRepo,
    outputDir,
    platforms: options.platforms,
    tag,
  })
  console.log(`Wrote anonymously verified Umbrel bundle to ${verified.outputDir}`)
  console.log(`Pinned image: ${verified.imageRef}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
  })
}
