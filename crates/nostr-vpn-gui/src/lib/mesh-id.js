export const MESH_ID_LEGACY_DEFAULT = 'nostr-vpn'
const LEGACY_MESH_ID_PREFIX = 'nostr-vpn:'

const COMPACT_MESH_ID_PATTERN = /^[A-Za-z0-9]+$/
const HYPHENATED_MESH_ID_PATTERN = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/

const chunkMeshId = (value) => value.match(/.{1,4}/g)?.join('-') ?? value

const stripLegacyMeshIdPrefix = (value) => {
  const trimmed = value.trim()
  if (!trimmed.startsWith(LEGACY_MESH_ID_PREFIX)) {
    return trimmed
  }

  return trimmed.slice(LEGACY_MESH_ID_PREFIX.length)
}

export const formatMeshIdForDisplay = (value) => {
  const trimmed = stripLegacyMeshIdPrefix(value)
  if (!trimmed || trimmed === MESH_ID_LEGACY_DEFAULT) {
    return trimmed
  }

  if (!COMPACT_MESH_ID_PATTERN.test(trimmed) || trimmed.length <= 4) {
    return trimmed
  }

  return chunkMeshId(trimmed)
}

export const formatMeshIdDraftForDisplay = (value, currentMeshId = '') => {
  const trimmed = value.trim()
  if (!trimmed) {
    return formatMeshIdForDisplay(currentMeshId)
  }

  return formatMeshIdForDisplay(trimmed)
}

export const canonicalizeMeshIdInput = (value, currentMeshId = '') => {
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }

  const currentNormalized = stripLegacyMeshIdPrefix(currentMeshId)
  if (trimmed === formatMeshIdForDisplay(currentNormalized)) {
    return currentNormalized
  }

  const normalized = stripLegacyMeshIdPrefix(trimmed)
  return normalized
}

export const validateMeshIdInput = (value, currentMeshId = '') => {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Mesh ID cannot be empty.'
  }

  const canonical = canonicalizeMeshIdInput(trimmed, currentMeshId)
  if (canonical === MESH_ID_LEGACY_DEFAULT) {
    return ''
  }

  if (COMPACT_MESH_ID_PATTERN.test(canonical)) {
    if (canonical.length < 8 || canonical.length > 24) {
      return 'Use 8 to 24 letters or numbers total.'
    }
    return ''
  }

  if (!HYPHENATED_MESH_ID_PATTERN.test(canonical)) {
    return 'Use only letters, numbers, and hyphens.'
  }

  const groups = canonical.split('-')
  if (groups.some((group) => group.length === 0 || group.length > 4)) {
    return 'Use groups of up to 4 characters.'
  }
  if (canonical.includes('-') && groups.some((group) => group.length !== 4)) {
    return 'Use 4-character groups, like abcd-efgh-ijkl.'
  }

  const compact = canonical.replace(/-/g, '')
  if (compact.length < 8 || compact.length > 24) {
    return 'Use 8 to 24 letters or numbers total.'
  }

  return ''
}
