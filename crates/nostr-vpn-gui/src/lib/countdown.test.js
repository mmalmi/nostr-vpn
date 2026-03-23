import test from 'node:test'
import assert from 'node:assert/strict'

import { lanPairingDeadlineFromSnapshot, remainingSecsFromDeadline } from './countdown.js'

test('remainingSecsFromDeadline changes only on second boundaries', () => {
  const deadlineMs = 6_000

  assert.equal(remainingSecsFromDeadline(deadlineMs, 1_000), 5)
  assert.equal(remainingSecsFromDeadline(deadlineMs, 1_999), 5)
  assert.equal(remainingSecsFromDeadline(deadlineMs, 2_000), 4)
})

test('lanPairingDeadlineFromSnapshot does not stretch countdown forward on poll jitter', () => {
  const previousDeadlineMs = 10_000
  const nowMs = 2_500

  assert.equal(
    lanPairingDeadlineFromSnapshot(previousDeadlineMs, true, 8, nowMs),
    previousDeadlineMs
  )
})

test('lanPairingDeadlineFromSnapshot resets when a new pairing session starts', () => {
  const previousDeadlineMs = 10_000
  const nowMs = 2_500

  assert.equal(
    lanPairingDeadlineFromSnapshot(previousDeadlineMs, true, 12, nowMs),
    14_500
  )
})

test('lanPairingDeadlineFromSnapshot clears when pairing stops', () => {
  assert.equal(lanPairingDeadlineFromSnapshot(10_000, false, 0, 2_500), null)
})
