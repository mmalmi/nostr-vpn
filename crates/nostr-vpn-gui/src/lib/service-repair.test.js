import test from 'node:test'
import assert from 'node:assert/strict'

import {
  serviceRepairErrorText,
  serviceRepairRecommended,
  serviceRepairRetryRecovered,
  serviceRepairRetryRecommended,
} from './service-repair.js'

const currentServiceState = {
  serviceSupported: true,
  serviceInstalled: true,
  serviceRunning: true,
  daemonRunning: true,
  appVersion: '0.2.28',
  daemonBinaryVersion: '0.2.28',
  serviceBinaryVersion: '0.2.28',
}

const installedServiceState = {
  ...currentServiceState,
  daemonBinaryVersion: '',
  serviceBinaryVersion: '0.2.27',
}

const matchingServiceWithStaleDaemonState = {
  ...currentServiceState,
  daemonBinaryVersion: '0.2.27',
}

test('serviceRepairRecommended recommends repair when the daemon explicitly reports a stale binary', () => {
  assert.equal(
    serviceRepairRecommended(
      'nvpn resume failed stderr: Error: daemon did not acknowledge control request within 3s; restart the daemon with a newer nvpn binary',
      currentServiceState
    ),
    true
  )

  assert.equal(
    serviceRepairRecommended(
      'failed to resume VPN session: daemon acknowledged control request but did not reload; likely an older nvpn daemon binary is still running. restart or reinstall the app/service so the daemon matches the current CLI',
      currentServiceState
    ),
    true
  )
})

test('serviceRepairRetryRecommended only triggers on explicit daemon control errors', () => {
  assert.equal(
    serviceRepairRetryRecommended(
      'daemon did not acknowledge control request within 3s; restart the daemon with a newer nvpn binary'
    ),
    true
  )
  assert.equal(serviceRepairRetryRecommended(''), false)
})

test('serviceRepairRetryRecovered clears timeout errors once the daemon is active again', () => {
  assert.equal(
    serviceRepairRetryRecovered(
      'daemon did not report result for resume request within 3s',
      {
        ...currentServiceState,
        daemonRunning: true,
        sessionActive: true,
      }
    ),
    true
  )

  assert.equal(
    serviceRepairRetryRecovered(
      'daemon did not report result for resume request within 3s',
      {
        ...currentServiceState,
        daemonRunning: true,
        sessionActive: false,
      }
    ),
    false
  )
})

test('serviceRepairRecommended ignores daemon control errors when no service is installed', () => {
  assert.equal(
    serviceRepairRecommended(
      'daemon did not acknowledge control request within 3s; restart the daemon with a newer nvpn binary',
      {
        serviceSupported: true,
        serviceInstalled: false,
        serviceRunning: false,
        daemonRunning: false,
        appVersion: '0.2.28',
        daemonBinaryVersion: '',
        serviceBinaryVersion: '',
      }
    ),
    false
  )
})

test('serviceRepairRecommended detects daemon and app version mismatch at startup', () => {
  assert.equal(serviceRepairRecommended('', installedServiceState), true)
})

test('serviceRepairRecommended ignores stale daemon metadata once the installed service binary matches the app', () => {
  assert.equal(serviceRepairRecommended('', matchingServiceWithStaleDaemonState), false)
})

test('serviceRepairErrorText surfaces a generic timeout message for non-stale daemon control errors', () => {
  assert.equal(
    serviceRepairErrorText(
      'daemon did not report result for reload request within 3s',
      currentServiceState
    ),
    'Background service did not respond in time. Try turning VPN on again. If it keeps happening, restart or reinstall the service.'
  )
})

test('serviceRepairErrorText surfaces startup version mismatch without a raw error', () => {
  assert.equal(
    serviceRepairErrorText('', installedServiceState),
    'Background service version (0.2.27) does not match this app (0.2.28). Reinstall or update so both use the same version, then try turning VPN on again.'
  )
})

test('serviceRepairErrorText prefers a repair instruction when a control error also has a version mismatch', () => {
  assert.equal(
    serviceRepairErrorText(
      'daemon acknowledged control request but did not reload; likely an older nvpn daemon binary is still running. restart or reinstall the app/service so the daemon matches the current CLI',
      installedServiceState
    ),
    'Background service version (0.2.27) does not match this app (0.2.28). Reinstall or update so both use the same version, then try turning VPN on again.'
  )
})

test('serviceRepairErrorText leaves unrelated errors unchanged', () => {
  assert.equal(
    serviceRepairErrorText('Clipboard copy failed', installedServiceState),
    'Clipboard copy failed'
  )
})
