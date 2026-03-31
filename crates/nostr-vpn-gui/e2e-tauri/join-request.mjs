import { mkdtempSync, mkdirSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

import { encodeInvitePayload } from '../src/lib/invite-code.js'
import {
  assertExecutable,
  assertTunAvailable,
  captureScreenshot,
  clickSelector,
  createSession,
  deleteSession,
  extractJsonDocument,
  find,
  isPresent,
  log,
  npubFromConfig,
  runChecked,
  setWindowRect,
  source,
  spawnManaged,
  textForSelector,
  typeInto,
  waitForDriverReady,
  waitForProcessOutput,
  waitForSelectorText,
  waitUntil,
} from './harness.mjs'

const OWNER_DRIVER_PORT = Number(process.env.TAURI_OWNER_DRIVER_PORT || '4450')
const REQUESTER_DRIVER_PORT = Number(process.env.TAURI_REQUESTER_DRIVER_PORT || '4451')
const OWNER_NATIVE_DRIVER_PORT = Number(process.env.TAURI_OWNER_NATIVE_DRIVER_PORT || '4445')
const REQUESTER_NATIVE_DRIVER_PORT = Number(process.env.TAURI_REQUESTER_NATIVE_DRIVER_PORT || '4446')
const OWNER_DRIVER_BASE = `http://127.0.0.1:${OWNER_DRIVER_PORT}`
const REQUESTER_DRIVER_BASE = `http://127.0.0.1:${REQUESTER_DRIVER_PORT}`

const TAURI_DRIVER_BIN = process.env.TAURI_DRIVER_BIN || 'tauri-driver'
const APP_PATH = process.env.TAURI_APP || '/work/target/debug/nostr-vpn-gui'
const NATIVE_DRIVER = process.env.NATIVE_DRIVER_PATH || '/usr/bin/WebKitWebDriver'

const OWNER_SCREENSHOT_PATH =
  process.env.TAURI_JOIN_REQUEST_OWNER_SCREENSHOT ||
  '/work/artifacts/screenshots/tauri-driver-join-request-owner.png'
const REQUESTER_SCREENSHOT_PATH =
  process.env.TAURI_JOIN_REQUEST_REQUESTER_SCREENSHOT ||
  '/work/artifacts/screenshots/tauri-driver-join-request-requester.png'

const NVPN_BIN = process.env.NVPN_BIN || '/work/target/debug/nvpn'
const RELAY_BIN = process.env.NVPN_RELAY_BIN || '/work/target/debug/nostr-vpn-relay'

const RELAY_BIND = process.env.TAURI_JOIN_REQUEST_RELAY_BIND || '127.0.0.1:18081'
const RELAY_URL = process.env.TAURI_JOIN_REQUEST_RELAY_URL || `ws://${RELAY_BIND}`

const OWNER_ENDPOINT = process.env.TAURI_JOIN_REQUEST_OWNER_ENDPOINT || '127.0.0.1:51830'
const REQUESTER_ENDPOINT = process.env.TAURI_JOIN_REQUEST_REQUESTER_ENDPOINT || '127.0.0.1:51831'
const OWNER_TUNNEL_IP = process.env.TAURI_JOIN_REQUEST_OWNER_TUNNEL_IP || '10.55.0.10/32'
const REQUESTER_TUNNEL_IP = process.env.TAURI_JOIN_REQUEST_REQUESTER_TUNNEL_IP || '10.55.0.11/32'
const WINDOW_WIDTH = Number(process.env.TAURI_E2E_WINDOW_WIDTH || '1400')
const WINDOW_HEIGHT = Number(process.env.TAURI_E2E_WINDOW_HEIGHT || '1000')
const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

const processes = []

async function statusJson(configPath) {
  const output = await runChecked(
    NVPN_BIN,
    ['status', '--json', '--discover-secs', '0', '--config', configPath],
    { cwd: ROOT_DIR, timeoutMs: 30_000 },
  )
  return JSON.parse(extractJsonDocument(output.stdout))
}

async function waitForAppReady(base, sessionId, label) {
  await waitUntil(
    async () => {
      try {
        await find(base, sessionId, '[data-testid="active-network-title"]')
        await find(base, sessionId, '[data-testid="invite-input"]')
        return true
      } catch {
        return false
      }
    },
    `${label} app ready`,
  )

  const initialSource = await source(base, sessionId)
  if (/Failed to apply startup launch setting/i.test(initialSource)) {
    throw new Error(`${label} unexpectedly showed the startup launch error banner`)
  }
}

async function ensureVpnOn(base, sessionId, label) {
  await waitForSelectorText(
    base,
    sessionId,
    '[data-testid="session-toggle"]',
    /vpn (on|off)/i,
    `${label} session toggle ready`,
    30_000,
  )

  let lastError = null

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const toggleText = await textForSelector(base, sessionId, '[data-testid="session-toggle"]')
    log(`${label} toggle attempt ${attempt}: ${toggleText}`)
    if (/vpn on/i.test(toggleText)) {
      return
    }

    await clickSelector(base, sessionId, '[data-testid="session-toggle"]')
    try {
      await waitForSelectorText(
        base,
        sessionId,
        '[data-testid="session-toggle"]',
        /vpn on/i,
        `${label} vpn on`,
        12_000,
      )
      return
    } catch (error) {
      lastError = error
      try {
        const pageText = await source(base, sessionId)
        log(`${label} source after toggle attempt ${attempt}: ${pageText.slice(0, 1200)}`)
      } catch (sourceError) {
        log(`${label} source capture failed after toggle attempt ${attempt}: ${String(sourceError)}`)
      }
    }
  }

  throw lastError ?? new Error(`${label} vpn did not turn on`)
}

async function captureFailureScreenshots(ownerSessionId, requesterSessionId) {
  const ownerFailurePath = OWNER_SCREENSHOT_PATH.replace(/\.png$/i, '-failure.png')
  const requesterFailurePath = REQUESTER_SCREENSHOT_PATH.replace(/\.png$/i, '-failure.png')

  if (ownerSessionId) {
    try {
      await captureScreenshot(OWNER_DRIVER_BASE, ownerSessionId, ownerFailurePath)
      log(`owner failure screenshot written: ${ownerFailurePath}`)
    } catch (error) {
      log(`failed to capture owner failure screenshot: ${String(error)}`)
    }
  }

  if (requesterSessionId) {
    try {
      await captureScreenshot(REQUESTER_DRIVER_BASE, requesterSessionId, requesterFailurePath)
      log(`requester failure screenshot written: ${requesterFailurePath}`)
    } catch (error) {
      log(`failed to capture requester failure screenshot: ${String(error)}`)
    }
  }
}

async function main() {
  assertExecutable(NVPN_BIN)
  assertExecutable(RELAY_BIN)
  assertExecutable(TAURI_DRIVER_BIN)
  assertTunAvailable()

  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'nvpn-join-request-e2e-'))
  const ownerRoot = path.join(tempRoot, 'owner')
  const requesterRoot = path.join(tempRoot, 'requester')
  const ownerConfigHome = path.join(ownerRoot, 'config-home')
  const requesterConfigHome = path.join(requesterRoot, 'config-home')
  const ownerConfigPath = path.join(ownerConfigHome, 'nvpn', 'config.toml')
  const requesterConfigPath = path.join(requesterConfigHome, 'nvpn', 'config.toml')
  mkdirSync(path.dirname(ownerConfigPath), { recursive: true })
  mkdirSync(path.dirname(requesterConfigPath), { recursive: true })

  const networkId = `join-request-e2e-${Date.now()}`
  const ifaceSuffix = Date.now().toString(36).slice(-5)
  const ownerIface = `nvo${ifaceSuffix}`
  const requesterIface = `nvr${ifaceSuffix}`

  log(`temp root: ${tempRoot}`)
  log(`using relay ${RELAY_URL}`)
  log(`using network id ${networkId}`)
  log(`using owner iface ${ownerIface}`)
  log(`using requester iface ${requesterIface}`)

  await runChecked(NVPN_BIN, ['init', '--force', '--config', ownerConfigPath], { cwd: ROOT_DIR })
  await runChecked(NVPN_BIN, ['init', '--force', '--config', requesterConfigPath], {
    cwd: ROOT_DIR,
  })

  const ownerNpub = npubFromConfig(ownerConfigPath)
  const requesterNpub = npubFromConfig(requesterConfigPath)

  await runChecked(
    NVPN_BIN,
    [
      'set',
      '--config',
      ownerConfigPath,
      '--network-id',
      networkId,
      '--relay',
      RELAY_URL,
      '--endpoint',
      OWNER_ENDPOINT,
      '--tunnel-ip',
      OWNER_TUNNEL_IP,
      '--listen-port',
      String(Number(OWNER_ENDPOINT.split(':').pop() || '51830')),
      '--node-name',
      'owner-desk',
    ],
    { cwd: ROOT_DIR },
  )

  await runChecked(
    NVPN_BIN,
    [
      'set',
      '--config',
      requesterConfigPath,
      '--network-id',
      'placeholder-mesh',
      '--relay',
      RELAY_URL,
      '--endpoint',
      REQUESTER_ENDPOINT,
      '--tunnel-ip',
      REQUESTER_TUNNEL_IP,
      '--listen-port',
      String(Number(REQUESTER_ENDPOINT.split(':').pop() || '51831')),
      '--node-name',
      'requester-phone',
    ],
    { cwd: ROOT_DIR },
  )

  const invite = encodeInvitePayload({
    v: 1,
    networkName: 'Network 1',
    networkId,
    inviterNpub: ownerNpub,
    relays: [RELAY_URL],
  })

  const relay = spawnManaged('join-relay', RELAY_BIN, ['--bind', RELAY_BIND], { cwd: ROOT_DIR })
  processes.push(relay)
  await waitForProcessOutput(relay, /listening/i, 'join-request relay to start')

  const ownerDriver = spawnManaged('owner-driver', TAURI_DRIVER_BIN, [
    '--port',
    `${OWNER_DRIVER_PORT}`,
    '--native-port',
    `${OWNER_NATIVE_DRIVER_PORT}`,
    '--native-driver',
    NATIVE_DRIVER,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      TAURI_AUTOMATION: 'true',
      NVPN_GUI_IFACE: ownerIface,
      XDG_CONFIG_HOME: ownerConfigHome,
      HOME: ownerRoot,
    },
  })
  processes.push(ownerDriver)

  const requesterDriver = spawnManaged('requester-driver', TAURI_DRIVER_BIN, [
    '--port',
    `${REQUESTER_DRIVER_PORT}`,
    '--native-port',
    `${REQUESTER_NATIVE_DRIVER_PORT}`,
    '--native-driver',
    NATIVE_DRIVER,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      TAURI_AUTOMATION: 'true',
      NVPN_GUI_IFACE: requesterIface,
      XDG_CONFIG_HOME: requesterConfigHome,
      HOME: requesterRoot,
    },
  })
  processes.push(requesterDriver)

  await Promise.all([
    waitForDriverReady(OWNER_DRIVER_BASE),
    waitForDriverReady(REQUESTER_DRIVER_BASE),
  ])

  let ownerSessionId = null
  let requesterSessionId = null

  try {
    ownerSessionId = await createSession(OWNER_DRIVER_BASE, APP_PATH)
    requesterSessionId = await createSession(REQUESTER_DRIVER_BASE, APP_PATH)
    log(`owner webdriver session started: ${ownerSessionId}`)
    log(`requester webdriver session started: ${requesterSessionId}`)

    await Promise.all([
      setWindowRect(OWNER_DRIVER_BASE, ownerSessionId, WINDOW_WIDTH, WINDOW_HEIGHT),
      setWindowRect(REQUESTER_DRIVER_BASE, requesterSessionId, WINDOW_WIDTH, WINDOW_HEIGHT),
    ])

    await Promise.all([
      waitForAppReady(OWNER_DRIVER_BASE, ownerSessionId, 'owner'),
      waitForAppReady(REQUESTER_DRIVER_BASE, requesterSessionId, 'requester'),
    ])

    await typeInto(REQUESTER_DRIVER_BASE, requesterSessionId, '[data-testid="invite-input"]', invite)
    await clickSelector(REQUESTER_DRIVER_BASE, requesterSessionId, '[data-testid="invite-import"]')

    await waitForSelectorText(
      REQUESTER_DRIVER_BASE,
      requesterSessionId,
      '[data-testid="request-network-join"]',
      /request join/i,
      'requester request button after invite import',
      30_000,
    )

    await ensureVpnOn(REQUESTER_DRIVER_BASE, requesterSessionId, 'requester')

    await clickSelector(
      REQUESTER_DRIVER_BASE,
      requesterSessionId,
      '[data-testid="request-network-join"]',
    )

    await waitForSelectorText(
      REQUESTER_DRIVER_BASE,
      requesterSessionId,
      '[data-testid="request-network-join"]',
      /requested/i,
      'requester requested state',
      30_000,
    )

    await waitForSelectorText(
      OWNER_DRIVER_BASE,
      ownerSessionId,
      '[data-testid="join-request-row"]',
      /requested/i,
      'owner pending join request row',
      40_000,
    )

    const requesterButtonTextBeforeAccept = await textForSelector(
      REQUESTER_DRIVER_BASE,
      requesterSessionId,
      '[data-testid="request-network-join"]',
    )
    if (!/requested/i.test(requesterButtonTextBeforeAccept)) {
      throw new Error(
        `expected requester to stay in Requested state until accept, got: ${requesterButtonTextBeforeAccept}`,
      )
    }

    await clickSelector(
      OWNER_DRIVER_BASE,
      ownerSessionId,
      '[data-testid="accept-join-request"]',
    )

    const requesterButtonTextAfterAccept = await textForSelector(
      REQUESTER_DRIVER_BASE,
      requesterSessionId,
      '[data-testid="request-network-join"]',
    )
    if (!/requested/i.test(requesterButtonTextAfterAccept)) {
      throw new Error(
        `expected requester to remain Requested after owner accept until the mesh connects, got: ${requesterButtonTextAfterAccept}`,
      )
    }

    await ensureVpnOn(OWNER_DRIVER_BASE, ownerSessionId, 'owner')

    await Promise.all([
      waitForSelectorText(
        OWNER_DRIVER_BASE,
        ownerSessionId,
        '[data-testid="mesh-badge"]',
        /mesh\s*1\/1/i,
        'owner mesh 1/1 after join request accept',
        70_000,
      ),
      waitForSelectorText(
        REQUESTER_DRIVER_BASE,
        requesterSessionId,
        '[data-testid="mesh-badge"]',
        /mesh\s*1\/1/i,
        'requester mesh 1/1 after join request accept',
        70_000,
      ),
    ])

    await Promise.all([
      waitForSelectorText(
        OWNER_DRIVER_BASE,
        ownerSessionId,
        '[data-testid="participant-state"]',
        /online/i,
        'owner participant online',
        70_000,
      ),
      waitForSelectorText(
        REQUESTER_DRIVER_BASE,
        requesterSessionId,
        '[data-testid="participant-state"]',
        /online/i,
        'requester participant online',
        70_000,
      ),
      waitForSelectorText(
        REQUESTER_DRIVER_BASE,
        requesterSessionId,
        '[data-testid="request-network-join"]',
        /connected/i,
        'requester connected button state',
        70_000,
      ),
    ])

    await waitUntil(
      async () => !(await isPresent(OWNER_DRIVER_BASE, ownerSessionId, '[data-testid="join-request-row"]')),
      'owner pending join request row to clear after accept',
      30_000,
    )

    await clickSelector(
      OWNER_DRIVER_BASE,
      ownerSessionId,
      '[data-testid="participant-toggle-admin"]',
    )

    await Promise.all([
      waitForSelectorText(
        OWNER_DRIVER_BASE,
        ownerSessionId,
        '[data-testid="network-admin-summary"]',
        /2 admins configured/i,
        'owner admin summary after promotion',
        40_000,
      ),
      waitForSelectorText(
        OWNER_DRIVER_BASE,
        ownerSessionId,
        '[data-testid="participant-admin-badge"]',
        /admin/i,
        'owner promoted participant admin badge',
        40_000,
      ),
      waitForSelectorText(
        REQUESTER_DRIVER_BASE,
        requesterSessionId,
        '[data-testid="network-admin-summary"]',
        /you can manage members/i,
        'requester promoted to admin',
        70_000,
      ),
    ])

    const requesterStatusText = await source(REQUESTER_DRIVER_BASE, requesterSessionId)
    if (!/Mesh connection received/i.test(requesterStatusText)) {
      throw new Error('requester did not show "Mesh connection received" after the real connection arrived')
    }

    const ownerStatus = await statusJson(ownerConfigPath)
    const requesterStatus = await statusJson(requesterConfigPath)
    if ((ownerStatus?.daemon?.state?.connected_peer_count ?? 0) < 1) {
      throw new Error(`owner daemon did not report a connected peer: ${JSON.stringify(ownerStatus)}`)
    }
    if ((requesterStatus?.daemon?.state?.connected_peer_count ?? 0) < 1) {
      throw new Error(`requester daemon did not report a connected peer: ${JSON.stringify(requesterStatus)}`)
    }

    await captureScreenshot(OWNER_DRIVER_BASE, ownerSessionId, OWNER_SCREENSHOT_PATH)
    await captureScreenshot(REQUESTER_DRIVER_BASE, requesterSessionId, REQUESTER_SCREENSHOT_PATH)
    log(`owner screenshot written: ${OWNER_SCREENSHOT_PATH}`)
    log(`requester screenshot written: ${REQUESTER_SCREENSHOT_PATH}`)

    log(
      `tauri-driver join-request e2e passed: requester ${requesterNpub} stayed Requested until owner ${ownerNpub} accepted, the real mesh came up, and admin promotion propagated back into the UI`,
    )
  } catch (error) {
    await captureFailureScreenshots(ownerSessionId, requesterSessionId)

    if (ownerSessionId) {
      try {
        const html = await source(OWNER_DRIVER_BASE, ownerSessionId)
        log(`owner page source snippet: ${html.slice(0, 1200)}`)
      } catch (sourceError) {
        log(`failed to capture owner page source: ${String(sourceError)}`)
      }
    }
    if (requesterSessionId) {
      try {
        const html = await source(REQUESTER_DRIVER_BASE, requesterSessionId)
        log(`requester page source snippet: ${html.slice(0, 1200)}`)
      } catch (sourceError) {
        log(`failed to capture requester page source: ${String(sourceError)}`)
      }
    }

    throw error
  } finally {
    if (ownerSessionId) {
      await deleteSession(OWNER_DRIVER_BASE, ownerSessionId)
    }
    if (requesterSessionId) {
      await deleteSession(REQUESTER_DRIVER_BASE, requesterSessionId)
    }
  }
}

main()
  .catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
  .finally(async () => {
    for (const meta of processes) {
      if (!meta.exited) {
        meta.process.kill('SIGTERM')
      }
    }

    await delay(500)

    for (const meta of processes) {
      if (!meta.exited) {
        meta.process.kill('SIGKILL')
      }
    }
  })
