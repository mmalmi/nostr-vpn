import { mkdtempSync, mkdirSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

import {
  assertExecutable,
  assertTunAvailable,
  captureScreenshot,
  createSession,
  deleteSession,
  extractJsonDocument,
  find,
  getRect,
  log,
  npubFromConfig,
  runChecked,
  setWindowRect,
  source,
  spawnManaged,
  stopManaged,
  textForSelector,
  waitForDriverReady,
  waitForProcessOutput,
  waitForSelectorText,
  waitUntil,
} from './harness.mjs'

const DRIVER_PORT = Number(process.env.TAURI_DRIVER_PORT || '4444')
const DRIVER_BASE = `http://127.0.0.1:${DRIVER_PORT}`
const TAURI_DRIVER_BIN = process.env.TAURI_DRIVER_BIN || 'tauri-driver'
const APP_PATH = process.env.TAURI_APP || '/work/target/debug/nostr-vpn-gui'
const NATIVE_DRIVER = process.env.NATIVE_DRIVER_PATH || '/usr/bin/WebKitWebDriver'
const SCREENSHOT_PATH =
  process.env.TAURI_E2E_SCREENSHOT || '/work/artifacts/screenshots/tauri-driver-e2e.png'

const NVPN_BIN = process.env.NVPN_BIN || '/work/target/debug/nvpn'
const RELAY_BIN = process.env.NVPN_RELAY_BIN || '/work/target/debug/nostr-vpn-relay'

const RELAY_BIND = process.env.TAURI_E2E_RELAY_BIND || '127.0.0.1:18080'
const RELAY_URL = process.env.TAURI_E2E_RELAY_URL || `ws://${RELAY_BIND}`

const GUI_ENDPOINT = process.env.TAURI_E2E_GUI_ENDPOINT || '127.0.0.1:51820'
const PEER_ENDPOINT = process.env.TAURI_E2E_PEER_ENDPOINT || '127.0.0.1:51821'
const GUI_TUNNEL_IP = process.env.TAURI_E2E_GUI_TUNNEL_IP || '10.44.0.10/32'
const PEER_TUNNEL_IP = process.env.TAURI_E2E_PEER_TUNNEL_IP || '10.44.0.11/32'
const PEER_IFACE = process.env.TAURI_E2E_PEER_IFACE || 'utun101'
const WINDOW_WIDTH = Number(process.env.TAURI_E2E_WINDOW_WIDTH || '0')
const WINDOW_HEIGHT = Number(process.env.TAURI_E2E_WINDOW_HEIGHT || '0')
const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

const processes = []

async function main() {
  assertExecutable(NVPN_BIN)
  assertExecutable(RELAY_BIN)
  assertExecutable(TAURI_DRIVER_BIN)
  assertTunAvailable()

  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'nvpn-tauri-e2e-'))
  const guiConfigHome = path.join(tempRoot, 'gui-config')
  const guiConfigPath = path.join(guiConfigHome, 'nvpn', 'config.toml')
  const peerConfigPath = path.join(tempRoot, 'peer.toml')
  mkdirSync(path.dirname(guiConfigPath), { recursive: true })

  const networkId = `tauri-e2e-${Date.now()}`

  log(`temp root: ${tempRoot}`)
  log(`using relay ${RELAY_URL}`)
  log(`using network id ${networkId}`)

  await runChecked(NVPN_BIN, ['init', '--force', '--config', guiConfigPath], { cwd: ROOT_DIR })
  await runChecked(NVPN_BIN, ['init', '--force', '--config', peerConfigPath], { cwd: ROOT_DIR })

  const guiNpub = npubFromConfig(guiConfigPath)
  const peerNpub = npubFromConfig(peerConfigPath)

  log(`gui npub: ${guiNpub}`)
  log(`peer npub: ${peerNpub}`)

  await runChecked(
    NVPN_BIN,
    [
      'set',
      '--config',
      guiConfigPath,
      '--network-id',
      networkId,
      '--relay',
      RELAY_URL,
      '--participant',
      peerNpub,
      '--endpoint',
      GUI_ENDPOINT,
      '--tunnel-ip',
      GUI_TUNNEL_IP,
      '--listen-port',
      String(Number(GUI_ENDPOINT.split(':').pop() || '51820')),
    ],
    { cwd: ROOT_DIR },
  )

  await runChecked(
    NVPN_BIN,
    [
      'set',
      '--config',
      peerConfigPath,
      '--network-id',
      networkId,
      '--relay',
      RELAY_URL,
      '--participant',
      guiNpub,
      '--endpoint',
      PEER_ENDPOINT,
      '--tunnel-ip',
      PEER_TUNNEL_IP,
      '--listen-port',
      String(Number(PEER_ENDPOINT.split(':').pop() || '51821')),
    ],
    { cwd: ROOT_DIR },
  )

  const relay = spawnManaged('relay', RELAY_BIN, ['--bind', RELAY_BIND], { cwd: ROOT_DIR })
  processes.push(relay)
  await waitForProcessOutput(relay, /listening/i, 'relay to start')

  const peer = spawnManaged(
    'peer-connect',
    NVPN_BIN,
    [
      'connect',
      '--config',
      peerConfigPath,
      '--iface',
      PEER_IFACE,
      '--announce-interval-secs',
      '3',
    ],
    { cwd: ROOT_DIR },
  )
  processes.push(peer)
  await waitForProcessOutput(peer, /waiting for 1 configured peer/i, 'peer connect startup')

  log(`starting tauri-driver with ${TAURI_DRIVER_BIN}`)
  const driver = spawnManaged('tauri-driver', TAURI_DRIVER_BIN, [
    '--port',
    `${DRIVER_PORT}`,
    '--native-driver',
    NATIVE_DRIVER,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      TAURI_AUTOMATION: 'true',
      XDG_CONFIG_HOME: guiConfigHome,
      HOME: tempRoot,
    },
  })
  processes.push(driver)
  await waitForDriverReady(DRIVER_BASE)

  const sessionId = await createSession(DRIVER_BASE, APP_PATH)
  log(`webdriver session started: ${sessionId}`)
  if (WINDOW_WIDTH > 0 || WINDOW_HEIGHT > 0) {
    await setWindowRect(DRIVER_BASE, sessionId, WINDOW_WIDTH || 1280, WINDOW_HEIGHT || 900)
  }

  try {
    await waitUntil(
      async () => {
        try {
          await find(DRIVER_BASE, sessionId, '[data-testid="pubkey"]')
          return true
        } catch {
          return false
        }
      },
      'gui to render pubkey',
    )

    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="active-network-title"]',
      /network 1/i,
      'active network title',
    )

    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="saved-networks-title"]',
      /other networks/i,
      'networks title',
    )

    await waitUntil(
      async () => {
        const text = await textForSelector(DRIVER_BASE, sessionId, '[data-testid="pubkey"]')
        return text === guiNpub ? text : false
      },
      'full identity npub',
    )

    const identityCardId = await find(DRIVER_BASE, sessionId, '[data-testid="hero-identity-card"]')
    const copyButtonId = await find(DRIVER_BASE, sessionId, '[data-testid="copy-pubkey"]')
    await find(DRIVER_BASE, sessionId, '[data-testid="active-network-mesh-id-input"]')
    await find(DRIVER_BASE, sessionId, '[data-testid="copy-mesh-id"]')
    const identityCardRect = await getRect(DRIVER_BASE, sessionId, identityCardId)
    const copyButtonRect = await getRect(DRIVER_BASE, sessionId, copyButtonId)
    const copyButtonRight = copyButtonRect.x + copyButtonRect.width
    const identityCardRight = identityCardRect.x + identityCardRect.width

    if (copyButtonRight > identityCardRight + 1) {
      throw new Error(
        `identity copy button overflowed its card: buttonRight=${copyButtonRight}, cardRight=${identityCardRight}`,
      )
    }

    const initialSource = await source(DRIVER_BASE, sessionId)
    if (/Failed to apply startup launch setting/i.test(initialSource)) {
      throw new Error('unexpected startup launch error banner on initial render')
    }

    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="mesh-badge"]',
      /mesh\s*1\/1/i,
      'mesh to reach 1/1',
      70_000,
    )

    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="participant-state"]',
      /online/i,
      'participant state online',
      70_000,
    )

    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="participant-status-text"]',
      /nostr seen \d+(?:s|m|h|d|w|mo|y) ago/i,
      'participant presence text',
      30_000,
    )

    await waitForProcessOutput(peer, /mesh: 1\/1 peers with presence/i, 'peer connect mesh 1/1', 70_000)

    const guiStatusOutput = await runChecked(
      NVPN_BIN,
      ['status', '--json', '--discover-secs', '0', '--config', guiConfigPath],
      { cwd: ROOT_DIR, timeoutMs: 30_000 },
    )
    const guiStatus = JSON.parse(extractJsonDocument(guiStatusOutput.stdout))
    const daemonState = guiStatus?.daemon?.state
    if (!daemonState || daemonState.connected_peer_count < 1) {
      throw new Error(
        `expected gui daemon connected_peer_count >= 1, got: ${JSON.stringify(daemonState)}`,
      )
    }
    const reachablePeer = (daemonState.peers || []).find((entry) => entry.reachable)
    if (!reachablePeer) {
      throw new Error(
        `expected at least one reachable tunnel peer in daemon state: ${JSON.stringify(
          daemonState,
        )}`,
      )
    }

    await stopManaged(peer, 'SIGINT')
    await waitForSelectorText(
      DRIVER_BASE,
      sessionId,
      '[data-testid="mesh-badge"]',
      /mesh\s*0\/1/i,
      'mesh to drop to 0/1 after peer disconnect',
      40_000,
    )

    await captureScreenshot(DRIVER_BASE, sessionId, SCREENSHOT_PATH)
    log(`screenshot written: ${SCREENSHOT_PATH}`)
    log('tauri-driver e2e passed: GUI reached mesh 1/1 with real peer connect + wireguard handshake')
  } catch (error) {
    const failureScreenshotPath = SCREENSHOT_PATH.replace(/\.png$/i, '-failure.png')

    try {
      await captureScreenshot(DRIVER_BASE, sessionId, failureScreenshotPath)
      log(`failure screenshot written: ${failureScreenshotPath}`)
    } catch (screenshotError) {
      log(`failed to capture failure screenshot: ${String(screenshotError)}`)
    }

    try {
      const html = await source(DRIVER_BASE, sessionId)
      log(`page source snippet: ${html.slice(0, 1200)}`)
    } catch (sourceError) {
      log(`failed to capture page source: ${String(sourceError)}`)
    }

    throw error
  } finally {
    await deleteSession(DRIVER_BASE, sessionId)
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
