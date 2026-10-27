import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkArchDistribution, packages } from './check-arch-distribution.mjs'

const reply = results => async url => {
  assert.deepEqual(url.searchParams.getAll('arg[]'), packages)
  return { ok: true, json: async () => ({ type: 'multiinfo', results }) }
}

test('accepts package revisions of the exact application release', async () => {
  const result = await checkArchDistribution('v4.1.19', reply([
    { Name: packages[0], Version: '4.1.19-1' },
    { Name: packages[1], Version: '4.1.19-2.1' },
  ]))
  assert.ok(result.every(item => item.current))
})

test('old, newer, development and missing packages do not prove exact distribution', async () => {
  for (const version of ['4.1.18-1', '4.1.20-1', '4.1.19.r1.gabcdef-1', '4x1x19-1']) {
    const result = await checkArchDistribution('v4.1.19', reply([
      { Name: packages[0], Version: version },
    ]))
    assert.ok(result.every(item => !item.current))
    assert.equal(result[1].version, null)
  }
})

test('rejects implicit tags and unavailable or malformed responses', async () => {
  await assert.rejects(checkArchDistribution('latest'), /explicit stable tag/)
  await assert.rejects(checkArchDistribution('v4.1.19', async () => ({ ok: false, status: 503 })), /HTTP 503/)
  await assert.rejects(checkArchDistribution('v4.1.19', async () => ({ ok: true, json: async () => ({}) })), /invalid/)
  await assert.rejects(checkArchDistribution('v4.1.19', reply([
    { Name: packages[0] }, { Name: packages[0] },
  ])), /duplicate/)
})
