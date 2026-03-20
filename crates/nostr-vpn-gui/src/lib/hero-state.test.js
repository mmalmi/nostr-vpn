import test from 'node:test'
import assert from 'node:assert/strict'

import { heroStateText, heroStatusDetailText } from './hero-state.js'

function baseState() {
  return {
    sessionActive: false,
    meshReady: false,
    relayConnected: false,
    autoDisconnectRelaysWhenMeshReady: true,
    sessionStatus: '',
  }
}

test('heroStateText reports service required before disconnected when service setup blocks startup', () => {
  const state = baseState()

  assert.equal(
    heroStateText(state, { serviceInstallRecommended: true }),
    'Service required'
  )
  assert.equal(
    heroStateText(state, { serviceEnableRecommended: true }),
    'Service required'
  )
})

test('heroStateText reports connected only when the mesh is ready', () => {
  const state = {
    ...baseState(),
    sessionActive: true,
    meshReady: true,
  }

  assert.equal(heroStateText(state), 'Connected')
})

test('heroStateText reports connecting for active sessions without a ready mesh', () => {
  const state = {
    ...baseState(),
    sessionActive: true,
  }

  assert.equal(heroStateText(state), 'Connecting')
})

test('heroStateText reports disconnected for inactive sessions without service blockers', () => {
  assert.equal(heroStateText(baseState()), 'Disconnected')
})

test('heroStatusDetailText hides steady-state paused-relay status based on runtime flags', () => {
  const state = {
    ...baseState(),
    sessionActive: true,
    meshReady: true,
    relayConnected: false,
    autoDisconnectRelaysWhenMeshReady: true,
    sessionStatus: 'Mesh ready (relays paused)',
  }

  assert.equal(heroStatusDetailText(state), '')
})

test('heroStatusDetailText keeps non-paused status details visible', () => {
  const state = {
    ...baseState(),
    sessionActive: true,
    meshReady: false,
    relayConnected: false,
    autoDisconnectRelaysWhenMeshReady: true,
    sessionStatus: 'Relay connect failed; retry in 5s',
  }

  assert.equal(heroStatusDetailText(state), 'Relay connect failed; retry in 5s')
})
