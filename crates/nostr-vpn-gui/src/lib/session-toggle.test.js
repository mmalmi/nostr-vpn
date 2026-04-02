import test from 'node:test'
import assert from 'node:assert/strict'

import { sessionToggleVisualState } from './session-toggle.js'

test('sessionToggleVisualState uses the live session state when nothing is pending', () => {
  assert.deepEqual(sessionToggleVisualState(false), {
    active: false,
    pending: false,
    className: 'off',
    label: 'VPN Off',
  })
  assert.deepEqual(sessionToggleVisualState(true), {
    active: true,
    pending: false,
    className: 'on',
    label: 'VPN On',
  })
})

test('sessionToggleVisualState keeps the live daemon state while a toggle is in flight', () => {
  assert.deepEqual(sessionToggleVisualState(false, true), {
    active: false,
    pending: true,
    className: 'off',
    label: 'VPN Starting',
  })
  assert.deepEqual(sessionToggleVisualState(true, false), {
    active: true,
    pending: true,
    className: 'on',
    label: 'VPN Stopping',
  })
})
