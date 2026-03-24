import { accessSync, constants, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'

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
const MOCK_OWN_NPUB = 'npub1akgu9lxldpt32lnjf97k005a4kgasewmvsrmkpzqeff39ssev0ssd6t3u'

const processes = []
let driver

function log(message) {
  console.log(`[tauri-e2e] ${message}`)
}

function assertExecutable(filePath) {
  try {
    accessSync(filePath, constants.X_OK)
  } catch (error) {
    throw new Error(`required executable missing or not executable: ${filePath} (${String(error)})`)
  }
}

function assertTunAvailable() {
  try {
    accessSync('/dev/net/tun', constants.R_OK | constants.W_OK)
  } catch (error) {
    throw new Error(`/dev/net/tun is unavailable; run with NET_ADMIN and tun device (${String(error)})`)
  }
}

async function runChecked(cmd, args, options = {}) {
  const {
    cwd = process.cwd(),
    env = process.env,
    timeoutMs = 20_000,
  } = options

  return await new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    let timedOut = false

    const timeout = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, timeoutMs)

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.on('error', (error) => {
      clearTimeout(timeout)
      reject(new Error(`failed to spawn ${cmd}: ${error.message}`))
    })
    child.on('exit', (code, signal) => {
      clearTimeout(timeout)
      if (timedOut) {
        reject(new Error(`command timed out: ${cmd} ${args.join(' ')}`))
        return
      }

      if (code !== 0) {
        reject(
          new Error(
            `command failed (${code ?? signal}): ${cmd} ${args.join(' ')}\nstdout:\n${stdout}\nstderr:\n${stderr}`,
          ),
        )
        return
      }

      resolve({ stdout, stderr })
    })
  })
}

function spawnManaged(name, cmd, args, options = {}) {
  const child = spawn(cmd, args, {
    cwd: options.cwd || process.cwd(),
    env: options.env || process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  const meta = {
    name,
    process: child,
    stdout: '',
    stderr: '',
    exited: false,
    exitCode: null,
    exitSignal: null,
  }

  child.stdout.on('data', (chunk) => {
    const text = chunk.toString()
    meta.stdout += text
    process.stdout.write(`[${name}] ${text}`)
  })

  child.stderr.on('data', (chunk) => {
    const text = chunk.toString()
    meta.stderr += text
    process.stderr.write(`[${name}] ${text}`)
  })

  child.on('exit', (code, signal) => {
    meta.exited = true
    meta.exitCode = code
    meta.exitSignal = signal
  })

  child.on('error', (error) => {
    meta.stderr += `\nspawn error: ${error.message}`
  })

  processes.push(meta)
  return meta
}

async function stopManaged(meta, signal = 'SIGINT', timeoutMs = 15_000) {
  if (meta.exited) {
    return
  }

  meta.process.kill(signal)
  const started = Date.now()
  while (!meta.exited && Date.now() - started < timeoutMs) {
    await delay(100)
  }

  if (!meta.exited) {
    meta.process.kill('SIGKILL')
    throw new Error(`failed to stop ${meta.name} via ${signal} within ${timeoutMs}ms`)
  }
}

async function waitForProcessOutput(meta, matcher, description, timeoutMs = 30_000) {
  const started = Date.now()

  while (Date.now() - started < timeoutMs) {
    if (meta.exited) {
      throw new Error(
        `${meta.name} exited before ${description} (code=${meta.exitCode}, signal=${meta.exitSignal})\nstdout:\n${meta.stdout}\nstderr:\n${meta.stderr}`,
      )
    }

    if (matcher.test(meta.stdout) || matcher.test(meta.stderr)) {
      return
    }

    await delay(200)
  }

  throw new Error(
    `timed out waiting for ${description} from ${meta.name}\nstdout:\n${meta.stdout}\nstderr:\n${meta.stderr}`,
  )
}

function npubFromConfig(configPath) {
  const content = readFileSync(configPath, 'utf8')
  const nostrSection = content.split('[node]')[0] || content
  const match = nostrSection.match(/^public_key\s*=\s*"([^"]+)"/m)
  if (!match) {
    throw new Error(`could not parse nostr public_key from ${configPath}`)
  }

  return match[1]
}

function extractJsonDocument(raw) {
  const start = raw.indexOf('{')
  const end = raw.lastIndexOf('}')
  if (start < 0 || end < start) {
    throw new Error(`command output did not include JSON document: ${raw}`)
  }
  return raw.slice(start, end + 1)
}

async function http(method, endpoint, body) {
  const response = await fetch(`${DRIVER_BASE}${endpoint}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })

  const json = await response.json().catch(() => ({}))
  if (!response.ok || json.value?.error) {
    const detail = json.value?.message || JSON.stringify(json)
    throw new Error(`${method} ${endpoint} failed: ${detail}`)
  }

  return json
}

async function waitForDriverReady(timeoutMs = 20_000) {
  const started = Date.now()

  while (Date.now() - started < timeoutMs) {
    try {
      const status = await fetch(`${DRIVER_BASE}/status`)
      if (status.ok) {
        return
      }
    } catch {
      // Keep polling.
    }

    await delay(250)
  }

  throw new Error('tauri-driver did not become ready')
}

function elementId(value) {
  return value['element-6066-11e4-a52e-4f735466cecf'] || value.ELEMENT
}

async function createSession() {
  const payload = {
    capabilities: {
      alwaysMatch: {
        browserName: 'wry',
        'tauri:options': {
          application: APP_PATH,
        },
      },
    },
  }

  const response = await http('POST', '/session', payload)
  const sessionId = response.value?.sessionId || response.sessionId
  if (!sessionId) {
    throw new Error(`missing webdriver session id: ${JSON.stringify(response)}`)
  }

  return sessionId
}

async function find(sessionId, selector) {
  const response = await http('POST', `/session/${sessionId}/element`, {
    using: 'css selector',
    value: selector,
  })

  const id = elementId(response.value)
  if (!id) {
    throw new Error(`missing element id for selector ${selector}`)
  }

  return id
}

async function findAll(sessionId, selector) {
  const response = await http('POST', `/session/${sessionId}/elements`, {
    using: 'css selector',
    value: selector,
  })

  return (response.value || []).map((entry) => elementId(entry)).filter(Boolean)
}

async function getText(sessionId, id) {
  const response = await http('GET', `/session/${sessionId}/element/${id}/text`)
  return String(response.value || '')
}

async function getRect(sessionId, id) {
  const response = await http('GET', `/session/${sessionId}/element/${id}/rect`)
  return response.value
}

async function textForSelector(sessionId, selector) {
  const id = await find(sessionId, selector)
  return await getText(sessionId, id)
}

async function screenshot(sessionId) {
  const response = await http('GET', `/session/${sessionId}/screenshot`)
  return response.value
}

async function setWindowRect(sessionId, width, height) {
  await http('POST', `/session/${sessionId}/window/rect`, {
    x: 0,
    y: 0,
    width,
    height,
  })
}

async function source(sessionId) {
  const response = await http('GET', `/session/${sessionId}/source`)
  return response.value || ''
}

async function waitUntil(fn, description, timeoutMs = 40_000) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    const value = await fn()
    if (value) {
      return value
    }

    await delay(250)
  }

  throw new Error(`timed out waiting for ${description}`)
}

async function pageContains(sessionId, pattern) {
  const html = (await source(sessionId)).replace(/\s+/g, ' ')
  return pattern.test(html)
}

async function waitForSelectorText(sessionId, selector, pattern, description, timeoutMs = 40_000) {
  return await waitUntil(
    async () => {
      try {
        const text = await textForSelector(sessionId, selector)
        return pattern.test(text) ? text : false
      } catch {
        return false
      }
    },
    description,
    timeoutMs,
  )
}

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

  await runChecked(NVPN_BIN, ['init', '--force', '--config', guiConfigPath])
  await runChecked(NVPN_BIN, ['init', '--force', '--config', peerConfigPath])

  const guiNpub = npubFromConfig(guiConfigPath)
  const peerNpub = npubFromConfig(peerConfigPath)

  log(`gui npub: ${guiNpub}`)
  log(`peer npub: ${peerNpub}`)

  await runChecked(NVPN_BIN, [
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
    '--auto-disconnect-relays-when-mesh-ready',
    'false',
  ])

  await runChecked(NVPN_BIN, [
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
    '--auto-disconnect-relays-when-mesh-ready',
    'false',
  ])

  const relay = spawnManaged('relay', RELAY_BIN, ['--bind', RELAY_BIND])
  await waitForProcessOutput(relay, /listening/i, 'relay to start')

  const peer = spawnManaged('peer-connect', NVPN_BIN, [
    'connect',
    '--config',
    peerConfigPath,
    '--iface',
    PEER_IFACE,
    '--announce-interval-secs',
    '3',
  ])
  await waitForProcessOutput(peer, /waiting for 1 configured peer/i, 'peer connect startup')

  log(`starting tauri-driver with ${TAURI_DRIVER_BIN}`)
  driver = spawn(TAURI_DRIVER_BIN, ['--port', `${DRIVER_PORT}`, '--native-driver', NATIVE_DRIVER], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      TAURI_AUTOMATION: 'true',
      XDG_CONFIG_HOME: guiConfigHome,
      HOME: tempRoot,
    },
  })

  driver.stdout.on('data', (chunk) => {
    process.stdout.write(`[tauri-driver] ${chunk}`)
  })
  driver.stderr.on('data', (chunk) => {
    process.stderr.write(`[tauri-driver] ${chunk}`)
  })

  await Promise.race([
    waitForDriverReady(),
    new Promise((_, reject) => {
      driver.once('error', (error) => {
        reject(new Error(`failed to start tauri-driver: ${error.message}`))
      })
    }),
  ])

  const sessionId = await createSession()
  log(`webdriver session started: ${sessionId}`)
  if (WINDOW_WIDTH > 0 || WINDOW_HEIGHT > 0) {
    await setWindowRect(sessionId, WINDOW_WIDTH || 1280, WINDOW_HEIGHT || 900)
  }

  try {
    await waitUntil(
      async () => {
        try {
          await find(sessionId, '[data-testid="pubkey"]')
          return true
        } catch {
          return false
        }
      },
      'gui to render pubkey',
    )

    await waitForSelectorText(
      sessionId,
      '[data-testid="active-network-title"]',
      /network 1/i,
      'active network title',
    )

    await waitForSelectorText(
      sessionId,
      '[data-testid="saved-networks-title"]',
      /other networks/i,
      'networks title',
    )

    await waitUntil(
      async () => {
        const text = await textForSelector(sessionId, '[data-testid="pubkey"]')
        return text === MOCK_OWN_NPUB ? text : false
      },
      'full identity npub',
    )

    const identityCardId = await find(sessionId, '[data-testid="hero-identity-card"]')
    const copyButtonId = await find(sessionId, '[data-testid="copy-pubkey"]')
    await find(sessionId, '[data-testid="active-network-mesh-id-input"]')
    await find(sessionId, '[data-testid="copy-mesh-id"]')
    const identityCardRect = await getRect(sessionId, identityCardId)
    const copyButtonRect = await getRect(sessionId, copyButtonId)
    const copyButtonRight = copyButtonRect.x + copyButtonRect.width
    const identityCardRight = identityCardRect.x + identityCardRect.width

    if (copyButtonRight > identityCardRight + 1) {
      throw new Error(
        `identity copy button overflowed its card: buttonRight=${copyButtonRight}, cardRight=${identityCardRight}`,
      )
    }

    const initialSource = await source(sessionId)
    if (/Failed to apply startup launch setting/i.test(initialSource)) {
      throw new Error('unexpected startup launch error banner on initial render')
    }

    await waitForSelectorText(
      sessionId,
      '[data-testid="mesh-badge"]',
      /mesh\s*1\/1/i,
      'mesh to reach 1/1',
      70_000,
    )

    await waitForSelectorText(
      sessionId,
      '[data-testid="participant-state"]',
      /online/i,
      'participant state online',
      70_000,
    )

    await waitForSelectorText(
      sessionId,
      '[data-testid="participant-status-text"]',
      /nostr seen \d+s ago/i,
      'participant presence text',
      30_000,
    )

    await waitForProcessOutput(peer, /mesh: 1\/1 peers with presence/i, 'peer connect mesh 1/1', 70_000)

    const guiStatusOutput = await runChecked(
      NVPN_BIN,
      ['status', '--json', '--discover-secs', '0', '--config', guiConfigPath],
      { timeoutMs: 30_000 },
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

    // Drop the peer process and verify GUI transitions to offline/mesh degraded.
    await stopManaged(peer, 'SIGINT')
    await waitForSelectorText(
      sessionId,
      '[data-testid="mesh-badge"]',
      /mesh\s*0\/1/i,
      'mesh to drop to 0/1 after peer disconnect',
      40_000,
    )
    await waitForSelectorText(
      sessionId,
      '[data-testid="participant-state"]',
      /offline/i,
      'participant state offline after peer disconnect',
      40_000,
    )

    const screenshotBase64 = await screenshot(sessionId)
    mkdirSync(path.dirname(SCREENSHOT_PATH), { recursive: true })
    writeFileSync(SCREENSHOT_PATH, Buffer.from(screenshotBase64, 'base64'))
    log(`screenshot written: ${SCREENSHOT_PATH}`)

    log('tauri-driver e2e passed: GUI reached mesh 1/1 with real peer connect + wireguard handshake')
  } catch (error) {
    const failureScreenshotPath = SCREENSHOT_PATH.replace(/\.png$/i, '-failure.png')

    try {
      const screenshotBase64 = await screenshot(sessionId)
      mkdirSync(path.dirname(failureScreenshotPath), { recursive: true })
      writeFileSync(failureScreenshotPath, Buffer.from(screenshotBase64, 'base64'))
      log(`failure screenshot written: ${failureScreenshotPath}`)
    } catch (screenshotError) {
      log(`failed to capture failure screenshot: ${String(screenshotError)}`)
    }

    try {
      const html = await source(sessionId)
      log(`page source snippet: ${html.slice(0, 1200)}`)
    } catch (sourceError) {
      log(`failed to capture page source: ${String(sourceError)}`)
    }

    throw error
  } finally {
    await http('DELETE', `/session/${sessionId}`).catch(() => {})
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

    if (driver && !driver.killed) {
      driver.kill('SIGTERM')
      await delay(500)
      if (!driver.killed) {
        driver.kill('SIGKILL')
      }
    }
  })
