import test from 'node:test'
import assert from 'node:assert/strict'

import {
  canonicalizeMeshIdInput,
  formatMeshIdDraftForDisplay,
  formatMeshIdForDisplay,
  validateMeshIdInput,
} from './mesh-id.js'

test('formatMeshIdForDisplay groups compact ids without adding a hidden prefix', () => {
  assert.equal(formatMeshIdForDisplay('1234abcd5678ef90'), '1234-abcd-5678-ef90')
  assert.equal(formatMeshIdForDisplay('mesh-home'), 'mesh-home')
})

test('formatMeshIdDraftForDisplay keeps compact ids grouped in inputs', () => {
  const currentMeshId = '1234abcd5678ef90'

  assert.equal(formatMeshIdDraftForDisplay('', currentMeshId), '1234-abcd-5678-ef90')
  assert.equal(formatMeshIdDraftForDisplay('1234abcd5678ef90', currentMeshId), '1234-abcd-5678-ef90')
  assert.equal(formatMeshIdDraftForDisplay('mesh-home', currentMeshId), 'mesh-home')
})

test('canonicalizeMeshIdInput returns plain ids for grouped input', () => {
  const currentMeshId = '1234abcd5678ef90'

  assert.equal(canonicalizeMeshIdInput('1234-abcd-5678-ef90', currentMeshId), '1234abcd5678ef90')
  assert.equal(canonicalizeMeshIdInput('mesh-home', currentMeshId), 'mesh-home')
})

test('validateMeshIdInput accepts plain ids and rejects malformed grouped ids', () => {
  assert.equal(validateMeshIdInput('nostr-vpn'), '')
  assert.equal(validateMeshIdInput('abcd-efgh-ijkl'), '')
  assert.equal(validateMeshIdInput('mesh-home'), '')
  assert.equal(validateMeshIdInput('ab cd'), 'Use only letters, numbers, and hyphens.')
  assert.equal(
    validateMeshIdInput('abc-efgh'),
    'Use 4-character groups, like abcd-efgh-ijkl.',
  )
})
