import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

type ParticipantView = {
  npub: string;
  pubkeyHex: string;
  alias: string;
  isAdmin: boolean;
  magicDnsAlias: string;
  magicDnsName: string;
};

type NetworkView = {
  id: string;
  name: string;
  enabled: boolean;
  networkId: string;
  onlineCount: number;
  expectedCount: number;
  participants: ParticipantView[];
};

type UiState = {
  platform: string;
  ownNpub: string;
  daemonRunning: boolean;
  vpnEnabled: boolean;
  vpnActive: boolean;
  serviceSupported: boolean;
  serviceStatusDetail: string;
  vpnStatus: string;
  internetSource: string;
  exitNodeStatusText: string;
  exitNodeBlocked: boolean;
  exitNodeLeakProtection: boolean;
  wireguardExitEnabled: boolean;
  wireguardExitConfigured: boolean;
  wireguardExitConfig: string;
  nodeName: string;
  selfMagicDnsName: string;
  autoconnect: boolean;
  networks: NetworkView[];
};

type QrMatrix = {
  width: number;
  cells: boolean[];
};

test.describe.configure({ mode: 'serial', timeout: 60_000 });

const TEST_WG_PRIVATE_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';
const TEST_WG_PUBLIC_KEY = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=';
const DAEMON_RELOAD_TIMEOUT_MS = 15_000;

function wireGuardConfig(endpoint = '198.51.100.20:51820'): string {
  return `
[Interface]
PrivateKey = ${TEST_WG_PRIVATE_KEY}
Address = 10.64.70.195/32
DNS = 10.64.0.1
MTU = 1380

[Peer]
PublicKey = ${TEST_WG_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}
PersistentKeepalive = 20
`;
}

async function postJson<T>(
  request: APIRequestContext,
  path: string,
  data?: unknown,
): Promise<T> {
  const response = await request.post(path, data === undefined ? undefined : { data });
  expect(response.ok(), `${path} returned ${response.status()}`).toBeTruthy();
  return (await response.json()) as T;
}

async function tryPostJson<T>(
  request: APIRequestContext,
  path: string,
  data?: unknown,
): Promise<T | null> {
  return postJson<T>(request, path, data).catch(() => null);
}

function activeNetwork(state: UiState): NetworkView {
  const network = state.networks.find((candidate) => candidate.enabled) ?? state.networks[0];
  expect(network, 'expected at least one network').toBeTruthy();
  return network;
}

function byName(state: UiState, name: string): NetworkView {
  const network = state.networks.find((candidate) => candidate.name === name);
  expect(network, `expected network named ${name}`).toBeTruthy();
  return network!;
}

async function expectNoConsoleErrors(
  page: Page,
  action: () => Promise<void>,
  allowedErrors: RegExp[] = [],
) {
  const errors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(message.text());
    }
  });
  page.on('pageerror', (error) => errors.push(error.message));

  await action();

  expect(
    errors.filter((error) => !allowedErrors.some((allowed) => allowed.test(error))),
  ).toEqual([]);
}

async function expectModalClosesWithEscape(page: Page, openerName: string, modalName: string) {
  await page.getByRole('button', { name: openerName }).click();
  const modal = page.getByRole('dialog', { name: modalName });
  await expect(modal).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(modal).toBeHidden();
}

async function expectModalClosesOnBackdrop(page: Page, openerName: string, modalName: string) {
  await page.getByRole('button', { name: openerName }).click();
  const modal = page.getByRole('dialog', { name: modalName });
  await expect(modal).toBeVisible();
  const backdrop = page.locator('.modal-backdrop');
  const box = await backdrop.boundingBox();
  expect(box, 'expected modal backdrop').toBeTruthy();
  await page.mouse.click(box!.x + 8, box!.y + 8);
  await expect(modal).toBeHidden();
}

test('bundled UI loads, navigates, renders QR, and stays responsive', async ({ page, request }) => {
  await expectNoConsoleErrors(page, async () => {
    const initialState = await postJson<UiState>(request, '/api/tick');
    expect(initialState.selfMagicDnsName).toMatch(/\.nvpn$/);
    const initialNetwork = activeNetwork(initialState);
    expect(initialNetwork.onlineCount).toBe(0);

    await page.goto('/');
    await expect(page).toHaveTitle('Nostr VPN');
    await expect(page.locator('.app-header')).toBeVisible();
    await expect(page.locator('.devices-layout')).toBeVisible();
    await expect(page.locator('.device-list-column')).toBeVisible();
    await expect(page.locator('.device-detail-column')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Back to Devices' })).toBeHidden();
    await expect(page.getByRole('button', { name: 'Add Network' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add Device' })).toBeVisible();
    await expect(page.locator('.vpn-switch')).toBeVisible();
    await expect(page.getByText('Daemon not running', { exact: true })).toHaveCount(0);
    await expect(page.locator('.header-vpn-text')).toHaveText('VPN off');
    await expect(page.locator('.device-list-column .list-header p')).toContainText(
      `${initialNetwork.onlineCount}/${initialNetwork.expectedCount} online`,
    );
    await expect(page.locator('.sidebar-summary')).toContainText(
      `${initialNetwork.onlineCount}/${initialNetwork.expectedCount} online`,
    );
    await expect(page.locator('.device-list-row').first()).toContainText(
      initialState.selfMagicDnsName,
    );
    await expect(page.locator('.device-list-row').first()).toContainText('Self');

    await page.getByRole('button', { name: 'Add Device' }).click();
    await expect(page.getByRole('heading', { name: 'Add Device' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Link Device' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Add by Device ID' })).toBeVisible();
    await expect(page.locator('.qr-frame')).toHaveCount(0);
    await page.getByRole('button', { name: 'Done' }).click();
    await expectModalClosesWithEscape(page, 'Add Device', 'Add Device');
    await expectModalClosesOnBackdrop(page, 'Add Device', 'Add Device');

    await page.getByRole('button', { name: 'Add Network' }).click();
    await expect(page.getByRole('heading', { name: 'Add Network' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create Network', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Join Network', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Done' }).click();
    await expectModalClosesWithEscape(page, 'Add Network', 'Add Network');
    await expectModalClosesOnBackdrop(page, 'Add Network', 'Add Network');

    await page.getByRole('button', { name: 'Exit Nodes' }).click();
    await expect(page.getByRole('heading', { name: 'Route' })).toBeVisible();
    await expect(page.getByTestId('internet-source-status')).not.toBeEmpty();
    await expect(page.locator('.choice-row').filter({ hasText: 'WireGuard upstream' })).toBeVisible();
    await expect(page.getByLabel('Block internet if exit node disconnects')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'WireGuard Upstream' })).toBeVisible();
    await expect(page.getByLabel('Config')).toBeVisible();
    const exitToggleBox = await page.getByRole('checkbox', { name: 'Offer exit' }).boundingBox();
    expect(exitToggleBox?.width).toBeLessThanOrEqual(40);
    expect(exitToggleBox?.height).toBeLessThanOrEqual(24);

    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('heading', { name: 'This Device' })).toBeVisible();
    await expect(page.getByLabel('DNS Suffix')).toHaveCount(0);
    await expect(page.getByLabel('Start VPN automatically')).toBeVisible();
    await expect(page.getByLabel('Route npub.fips outside VPN')).toBeVisible();
    await expect(page.getByLabel('Your public FIPS address')).toBeDisabled();
    await expect(page.getByLabel('Public .fips inbound TCP ports')).toBeDisabled();
    await expect(page.getByLabel('Connect to non-roster FIPS peers')).toBeVisible();
    const diagnosticsPanel = page.locator('.diagnostics-panel');
    const diagnosticsToggle = page.getByRole('button', { name: /Diagnostics/ });
    await expect(diagnosticsPanel).toBeVisible();
    await expect(diagnosticsToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(diagnosticsPanel.getByText('Roster FIPS')).toBeHidden();
    await diagnosticsToggle.click();
    await expect(diagnosticsToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(diagnosticsPanel.getByText('Roster FIPS')).toBeVisible();
    await expect(diagnosticsPanel.getByText('Other FIPS')).toBeVisible();

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await expect(page.locator('.app-header')).toBeVisible();
    await expect(page.locator('.devices-layout')).toBeVisible();
    await expect(page.locator('.device-detail-column')).toBeHidden();
    const deviceRows = page.locator('.device-list-row');
    await expect(deviceRows).not.toHaveCount(0);
    await deviceRows.first().click();
    await expect(page.locator('.device-list-column')).toBeHidden();
    await expect(page.locator('.device-detail-column')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Back to Devices' })).toBeVisible();
    await expect(page.locator('.device-detail-column .detail-header h2')).toHaveText(
      initialState.selfMagicDnsName,
    );
    await expect(page.locator('.device-detail-column .detail-header h2')).not.toHaveText(
      /^[0-9a-f]{12,64}(\.nvpn)?$/,
    );
    await page.getByRole('button', { name: 'Back to Devices' }).click();
    await expect(page.locator('.device-list-column')).toBeVisible();
    await expect(page.locator('.device-detail-column')).toBeHidden();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
  });
});

test('WireGuard exit settings import, save, toggle, and reject bad config from the UI', async ({
  page,
  request,
}) => {
  await expectNoConsoleErrors(
    page,
    async () => {
      const validConfig = wireGuardConfig();

      await page.goto('/');
      await page.getByRole('button', { name: 'Exit Nodes' }).click();

      const wireGuardPanel = page.locator('form.panel.wide').filter({
        has: page.getByRole('heading', { name: 'WireGuard Upstream' }),
      });
      await expect(wireGuardPanel).toBeVisible();

      const configField = wireGuardPanel.getByLabel('Config');
      await expect(configField).toBeVisible();

      await wireGuardPanel.locator('input[type="file"]').setInputFiles({
        name: 'wg-upstream.conf',
        mimeType: 'text/plain',
        buffer: Buffer.from(validConfig),
      });

      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).wireguardExitConfigured)
        .toBe(true);
      let state = await postJson<UiState>(request, '/api/tick');
      expect(state.wireguardExitConfig).toBe('');
      expect(JSON.stringify(state)).not.toContain(TEST_WG_PRIVATE_KEY);
      await expect(configField).toHaveValue('');
      await expect(configField).toHaveAttribute('placeholder', 'Configured (hidden)');

      const enabled = wireGuardPanel.getByRole('checkbox', { name: 'Enabled' });
      await expect(enabled).toBeEnabled();
      await enabled.click();
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).wireguardExitEnabled, {
          timeout: DAEMON_RELOAD_TIMEOUT_MS,
        })
        .toBe(true);
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).internetSource)
        .toBe('wireguard');
      await expect(page.getByTestId('internet-source-status')).toContainText(/WireGuard/i);
      await expect(enabled).toBeChecked();
      await enabled.click();
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).wireguardExitEnabled, {
          timeout: DAEMON_RELOAD_TIMEOUT_MS,
        })
        .toBe(false);
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).internetSource)
        .toBe('direct');
      await expect(page.getByTestId('internet-source-status')).toContainText(/Direct/i);

      await configField.fill(`
[Interface]
PrivateKey = not-a-wireguard-key
Address = 10.64.70.200/32

[Peer]
PublicKey = also-bad
AllowedIPs = 0.0.0.0/0
Endpoint = bad.example.test:51820
`);
      await wireGuardPanel.getByRole('button', { name: 'Save' }).click();
      await expect(page.locator('.notice-row.error')).toContainText('PrivateKey');
      state = await postJson<UiState>(request, '/api/tick');
      expect(state.wireguardExitConfig).toBe('');
      expect(state.wireguardExitEnabled).toBe(false);

      await configField.fill(validConfig);
      await wireGuardPanel.getByRole('button', { name: 'Save' }).click();
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).wireguardExitConfigured)
        .toBe(true);
      expect((await postJson<UiState>(request, '/api/tick')).wireguardExitConfig).toBe('');
      await expect(page.locator('.notice-row.error')).toHaveCount(0);
    },
    [/Failed to load resource: the server responded with a status of 400 \(Bad Request\)/],
  );
});

test('API supports the Umbrel web config action surface', async ({ request }) => {
  const peerNpub = process.env.NVPN_UMBREL_WEB_PEER_NPUB;
  test.skip(!peerNpub, 'NVPN_UMBREL_WEB_PEER_NPUB is required for participant actions');

  let state = await postJson<UiState>(request, '/api/tick');
  expect(state.platform).toBe('umbrel');
  expect(state.serviceSupported).toBeFalsy();
  expect(state.serviceStatusDetail).toBe('Managed directly by the Umbrel app');
  expect(state.vpnEnabled).toBeFalsy();
  expect(state.vpnActive).toBeFalsy();
  expect(state.vpnStatus).not.toContain('Daemon');
  expect(state.vpnStatus.toLowerCase()).not.toContain('failed');
  expect(state.vpnStatus.toLowerCase()).not.toContain('error');
  const originalNetwork = activeNetwork(state);
  expect(originalNetwork.networkId).not.toBe('nostr-vpn');
  expect(originalNetwork.networkId).toMatch(/^[0-9a-f]{8,16}$/);

  const qr = await postJson<QrMatrix>(request, '/api/qr_matrix', { text: 'public test value' });
  expect(qr.width).toBeGreaterThan(0);
  expect(qr.cells.length).toBe(qr.width * qr.width);
  expect(qr.cells.some(Boolean)).toBeTruthy();

  state = await postJson<UiState>(request, '/api/update_settings', {
    nodeName: 'Umbrel Web E2E',
    autoconnect: true,
    exitNodeLeakProtection: false,
  });
  expect(state.nodeName).toBe('Umbrel Web E2E');
  expect(state.autoconnect).toBeTruthy();
  expect(state.exitNodeLeakProtection).toBeFalsy();

  state = await postJson<UiState>(request, '/api/update_settings', {
    exitNodeLeakProtection: true,
  });
  expect(state.exitNodeLeakProtection).toBeTruthy();

  state = await postJson<UiState>(request, '/api/add_network', { name: 'E2E Work' });
  let workNetwork = byName(state, 'E2E Work');

  state = await postJson<UiState>(request, '/api/rename_network', {
    networkId: workNetwork.id,
    name: 'E2E Renamed',
  });
  workNetwork = byName(state, 'E2E Renamed');

  state = await postJson<UiState>(request, '/api/set_network_mesh_id', {
    networkId: workNetwork.id,
    meshId: 'umbrel-web-e2e',
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.networkId).toBe('umbrel-web-e2e');

  state = await postJson<UiState>(request, '/api/set_network_enabled', {
    networkId: workNetwork.id,
    enabled: true,
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.enabled).toBeTruthy();

  state = await postJson<UiState>(request, '/api/add_participant', {
    networkId: workNetwork.id,
    npub: peerNpub,
    alias: 'Peer One',
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.participants.some((participant) => participant.npub === peerNpub)).toBeTruthy();

  state = await postJson<UiState>(request, '/api/set_participant_alias', {
    npub: peerNpub,
    alias: 'Peer Renamed',
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(
    workNetwork.participants.find((participant) => participant.npub === peerNpub)?.magicDnsAlias,
  ).toBe('peer-renamed');

  state = await postJson<UiState>(request, '/api/add_admin', {
    networkId: workNetwork.id,
    npub: peerNpub,
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.participants.find((participant) => participant.npub === peerNpub)?.isAdmin).toBeTruthy();

  state = await postJson<UiState>(request, '/api/remove_admin', {
    networkId: workNetwork.id,
    npub: peerNpub,
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.participants.find((participant) => participant.npub === peerNpub)?.isAdmin).toBeFalsy();

  state = await postJson<UiState>(request, '/api/remove_participant', {
    networkId: workNetwork.id,
    npub: peerNpub,
  });
  workNetwork = byName(state, 'E2E Renamed');
  expect(workNetwork.participants.some((participant) => participant.npub === peerNpub)).toBeFalsy();

  state = await postJson<UiState>(request, '/api/set_network_enabled', {
    networkId: originalNetwork.id,
    enabled: true,
  });
  expect(activeNetwork(state).id).toBe(originalNetwork.id);

  state = await postJson<UiState>(request, '/api/remove_network', {
    networkId: workNetwork.id,
  });
  expect(state.networks.some((network) => network.id === workNetwork.id)).toBeFalsy();
});

test('manual join admin and joiner actions persist through the shipped web UI', async ({
  page,
  request,
}) => {
  const peerNpub = process.env.NVPN_UMBREL_WEB_PEER_NPUB;
  test.skip(!peerNpub, 'NVPN_UMBREL_WEB_PEER_NPUB is required for manual join');

  const initialState = await postJson<UiState>(request, '/api/tick');
  const originalNetwork = activeNetwork(initialState);

  await page.goto('/');
  await page.getByRole('button', { name: 'Add Device' }).click();
  const adminForm = page.locator('form.modal-section').filter({
    has: page.getByRole('heading', { name: 'Add by Device ID' }),
  });
  await adminForm.getByLabel('Device ID').fill(peerNpub!);
  await adminForm.getByLabel('Name').fill('Manual web joiner');
  await adminForm.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(adminForm).toBeHidden({ timeout: 20_000 });

  await expect
    .poll(async () => {
      const state = await postJson<UiState>(request, '/api/tick');
      return byName(state, originalNetwork.name).participants.some(
        (participant) =>
          participant.npub === peerNpub &&
          participant.magicDnsAlias === 'manual-web-joiner',
      );
    })
    .toBe(true);

  await postJson<UiState>(request, '/api/remove_participant', {
    networkId: originalNetwork.id,
    npub: peerNpub,
  });

  const manualNetworkId = 'a1b2c3d4e5f60708';
  await page.getByRole('button', { name: 'Add Network' }).click();
  await page.getByRole('button', { name: 'Join Network', exact: true }).click();
  const joinerForm = page.locator('form.modal-section').filter({
    has: page.getByRole('heading', { name: 'Manual join' }),
  });
  await joinerForm.getByLabel('Admin Device ID').fill(peerNpub!);
  await joinerForm.getByLabel('Network ID').fill('a1b2-c3d4-e5f6-0708');
  await joinerForm.getByRole('button', { name: 'Add manually' }).click();
  await expect(joinerForm).toBeHidden({ timeout: 20_000 });

  let manualNetwork: NetworkView | undefined;
  await expect
    .poll(async () => {
      const state = await postJson<UiState>(request, '/api/tick');
      manualNetwork = state.networks.find(
        (network) => network.networkId === manualNetworkId,
      );
      return {
        enabled: manualNetwork?.enabled ?? false,
        adminPresent:
          manualNetwork?.participants.some(
            (participant) => participant.npub === peerNpub && participant.isAdmin,
          ) ?? false,
      };
    })
    .toEqual({ enabled: true, adminPresent: true });

  expect(manualNetwork, 'manual network should have persisted').toBeTruthy();
  await postJson<UiState>(request, '/api/set_network_enabled', {
    networkId: originalNetwork.id,
    enabled: true,
  });
  await postJson<UiState>(request, '/api/remove_network', {
    networkId: manualNetwork!.id,
  });
});

test('VPN switch starts the Umbrel daemon without tunnel setup errors', async ({ page, request }) => {
  await expectNoConsoleErrors(page, async () => {
    await page.goto('/');
    await expect(page.locator('.app-header')).toBeVisible();
    await expect(page.locator('.vpn-switch')).toBeVisible();

    const initialState = await postJson<UiState>(request, '/api/tick');
    if (initialState.vpnEnabled) {
      await page.getByRole('button', { name: 'Turn VPN off' }).click();
      await expect
        .poll(async () => (await postJson<UiState>(request, '/api/tick')).vpnEnabled)
        .toBe(false);
    }

    await page.getByRole('button', { name: 'Turn VPN on' }).click();
    await expect
      .poll(
        async () => {
          const state = await tryPostJson<UiState>(request, '/api/tick');
          if (!state) {
            return null;
          }
          return {
            vpnEnabled: state.vpnEnabled,
            daemonRunning: state.daemonRunning,
            vpnStatus: state.vpnStatus,
          };
        },
        { timeout: 20_000 },
      )
      .toEqual({
        vpnEnabled: true,
        daemonRunning: true,
        vpnStatus: 'Waiting for participants',
      });
    await expect(page.locator('.header-vpn-text')).toHaveText('Waiting for participants');
    await expect(page.locator('.notice-row.error')).toHaveCount(0);

    await page.getByRole('button', { name: 'Turn VPN off' }).click();
    await expect
      .poll(
        async () => {
          const state = await tryPostJson<UiState>(request, '/api/tick');
          if (!state) {
            return null;
          }
          return {
            vpnEnabled: state.vpnEnabled,
            vpnActive: state.vpnActive,
          };
        },
        { timeout: 20_000 },
      )
      .toEqual({
        vpnEnabled: false,
        vpnActive: false,
      });
    const pausedState = await postJson<UiState>(request, '/api/tick');
    expect(pausedState.vpnStatus.toLowerCase()).not.toContain('failed');
    expect(pausedState.vpnStatus.toLowerCase()).not.toContain('error');
    await expect(page.locator('.header-vpn-text')).toHaveText(pausedState.vpnStatus);
  });
});
