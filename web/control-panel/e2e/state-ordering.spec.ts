import { expect, test, type Page, type Route } from '@playwright/test';
import type { UiState } from '../src/lib/types';

import { state } from './fixtures';

async function controlledApi(page: Page) {
  const polls: Route[] = [];
  const actions: Route[] = [];
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.route('**/api/**', (route) => {
    if (new URL(route.request().url()).pathname === '/api/tick') {
      polls.push(route);
    } else {
      expect(['/api/connect_vpn', '/api/update_settings']).toContain(new URL(route.request().url()).pathname);
      actions.push(route);
    }
  });
  // Observe body consumption so assertions cannot pass before a stale reply is processed.
  await page.addInitScript(() => {
    const json = Response.prototype.json;
    Response.prototype.json = async function () {
      const body = await json.call(this);
      document.documentElement.dataset.apiResponsesRead = String(
        Number(document.documentElement.dataset.apiResponsesRead ?? 0) + 1,
      );
      return body;
    };
  });
  const now = new Date('2026-01-01T00:00:00Z');
  await page.clock.install({ time: now });
  await page.clock.pauseAt(now);
  await page.goto('/');
  await expect.poll(() => polls.length).toBe(1);

  let replies = 0;
  async function reply(route: Route, body: UiState | string) {
    await route.fulfill({
      status: typeof body === 'string' ? 503 : 200,
      json: typeof body === 'string' ? { error: body } : body,
    });
    await expect(page.locator('html')).toHaveAttribute('data-api-responses-read', String(++replies));
    expect(pageErrors).toEqual([]);
  }
  async function poll() {
    const count = polls.length;
    await page.clock.runFor(2500);
    await expect.poll(() => polls.length).toBe(count + 1);
    return polls[count];
  }
  async function connect() {
    const count = actions.length;
    await page.getByRole('button', { name: 'Turn VPN on' }).click();
    await expect.poll(() => actions.length).toBe(count + 1);
    return actions[count];
  }
  return { polls, actions, reply, poll, connect };
}

for (const staleFails of [false, true]) {
  const staleResult = staleFails ? 'failure' : 'success';

  test(`late poll ${staleResult} cannot overwrite a successful action`, async ({ page }) => {
    const api = await controlledApi(page);
    await api.reply(api.polls[0], state('VPN off'));
    const stale = await api.poll();
    const action = await api.connect();
    await api.reply(action, state('VPN on', true));
    await expect(page.getByRole('button', { name: 'Turn VPN off' })).toBeEnabled();

    await api.reply(stale, staleFails ? 'Old poll failed' : state('Stale VPN off'));
    await expect(page.locator('.header-vpn-text')).toHaveText('VPN on');
    await expect(page.getByRole('button', { name: 'Turn VPN off' })).toBeEnabled();
    await expect(page.locator('.notice-row.error')).toHaveCount(0);

    await api.reply(await api.poll(), state('Fresh VPN status', true));
    await expect(page.locator('.header-vpn-text')).toHaveText('Fresh VPN status');
  });

  test(`action errors survive late poll ${staleResult} and normal polling`, async ({ page }) => {
    const api = await controlledApi(page);
    await api.reply(api.polls[0], state('VPN off'));
    const stale = await api.poll();
    await api.reply(await api.connect(), 'Unable to connect');
    await expect(page.locator('.notice-row.error')).toHaveText('Unable to connect');

    await api.reply(stale, staleFails ? 'Old poll failed' : state('Stale VPN off'));
    await expect(page.locator('.header-vpn-text')).toHaveText('VPN off');
    await expect(page.locator('.notice-row.error')).toHaveText('Unable to connect');

    await api.reply(await api.poll(), 'Current poll failed');
    await expect(page.locator('.notice-row.error')).toHaveText('Unable to connect');
    await api.reply(await api.poll(), state('Fresh VPN status'));
    await expect(page.locator('.header-vpn-text')).toHaveText('Fresh VPN status');
    await expect(page.locator('.notice-row.error')).toHaveText('Unable to connect');

    await api.reply(await api.connect(), state('VPN on', true));
    await expect(page.locator('.header-vpn-text')).toHaveText('VPN on');
    await expect(page.locator('.notice-row.error')).toHaveCount(0);
  });

  for (const newerFails of [false, true]) {
    test(`late initial poll ${staleResult} cannot replace newer poll ${newerFails ? 'failure' : 'success'}`, async ({ page }) => {
      const api = await controlledApi(page);
      const newer = await api.poll();
      await api.reply(newer, newerFails ? 'Latest poll failed' : state('Latest VPN status'));
      await api.reply(api.polls[0], staleFails ? 'Old poll failed' : state('Stale VPN off'));

      if (newerFails) {
        await expect(page.locator('.center-state.error-state')).toHaveText('Latest poll failed');
        await expect(page.locator('.header-vpn-text')).toHaveCount(0);
      } else {
        await expect(page.locator('.header-vpn-text')).toHaveText('Latest VPN status');
        await expect(page.locator('.notice-row.error')).toHaveCount(0);
      }

      await api.reply(await api.poll(), state('Recovered VPN status'));
      await expect(page.locator('.header-vpn-text')).toHaveText('Recovered VPN status');
      await expect(page.locator('.notice-row.error')).toHaveCount(0);
    });
  }
}

test('polling makes progress while newer polls are pending and recovers after errors', async ({ page }) => {
  const api = await controlledApi(page);
  const pending = await api.poll();
  await api.reply(api.polls[0], state('Initial VPN status'));
  await expect(page.locator('.header-vpn-text')).toHaveText('Initial VPN status');
  await api.reply(pending, 'Poll failed');
  await expect(page.locator('.notice-row.error')).toHaveText('Poll failed');

  await api.reply(await api.poll(), state('Recovered VPN status'));
  await expect(page.locator('.header-vpn-text')).toHaveText('Recovered VPN status');
  await expect(page.locator('.notice-row.error')).toHaveCount(0);
});

for (const editor of ['settings', 'WireGuard', 'WireGuard import'] as const) {
  for (const fails of [false, true]) {
    test(`${editor} preserves newer edits after a save ${fails ? 'failure' : 'success'}`, async ({ page }, testInfo) => {
      const api = await controlledApi(page);
      await api.reply(api.polls[0], state('VPN off'));
      const settings = editor === 'settings';
      await page.getByRole('button', { name: settings ? 'Settings' : 'Exit Nodes', exact: true }).click();
      const form = settings ? page.locator('.settings-form') : page.locator('form').filter({
        has: page.getByRole('heading', { name: 'WireGuard Upstream' }),
      });
      const field = form.getByLabel(settings ? 'Name' : 'Config', { exact: true });
      const save = form.getByRole('button', { name: settings ? 'Save settings' : 'Save', exact: true });
      const submitted = settings ? '  Device A  ' : '# Config A';
      const edited = settings ? 'Device B' : '# Config B';
      if (editor === 'WireGuard import') {
        await form.locator('input[type="file"]').setInputFiles({
          name: 'test.conf', mimeType: 'text/plain', buffer: Buffer.from(submitted),
        });
      } else {
        await field.fill(submitted);
        await save.click();
      }
      await expect.poll(() => api.actions.length).toBe(1);
      expect(api.actions[0].request().postDataJSON()[settings ? 'nodeName' : 'wireguardExitConfig']).toBe(submitted);
      await expect(save).toBeDisabled();
      await field.fill(edited);

      const savedState = {
        ...state('Saved'), nodeName: 'Device A', wireguardExitConfigured: true,
      };
      await api.reply(api.actions[0], fails ? 'Save failed' : savedState);
      await expect(field).toHaveValue(edited);
      await expect(save).toBeEnabled();
      if (fails) await expect(page.locator('.notice-row.error')).toHaveText('Save failed');

      await api.reply(await api.poll(), { ...savedState, vpnStatus: 'Fresh poll' });
      await expect(page.locator('.header-vpn-text')).toHaveText('Fresh poll');
      await expect(field).toHaveValue(edited);
      await expect(save).toBeEnabled();
      if (!fails) {
        await page.setViewportSize({ width: 1280, height: 1800 });
        await form.screenshot({ path: testInfo.outputPath('retained-draft.png') });
      }

      // An untouched retry accepts the server's normalized (or hidden) value.
      await save.click();
      await expect.poll(() => api.actions.length).toBe(2);
      expect(api.actions[1].request().postDataJSON()[settings ? 'nodeName' : 'wireguardExitConfig']).toBe(edited);
      await api.reply(api.actions[1], { ...savedState, nodeName: 'Normalized Device B' });
      await expect(field).toHaveValue(settings ? 'Normalized Device B' : '');
      await expect(save).toBeDisabled();
      await expect(page.locator('.notice-row.error')).toHaveCount(0);
      await api.reply(await api.poll(), { ...savedState, nodeName: 'Polled device' });
      await expect(field).toHaveValue(settings ? 'Polled device' : '');
      await expect(save).toBeDisabled();
    });
  }
}

test('WireGuard file reading does not replace edits made while the import is pending', async ({ page }) => {
  await page.addInitScript(() => {
    const text = File.prototype.text;
    File.prototype.text = async function () {
      const value = await text.call(this);
      document.documentElement.dataset.fileReadPending = 'true';
      await new Promise<void>((resolve) => document.addEventListener('finish-file-read', () => resolve(), { once: true }));
      document.documentElement.dataset.fileReadReady = 'true';
      return value;
    };
  });
  const api = await controlledApi(page);
  await api.reply(api.polls[0], state('VPN off'));
  await page.getByRole('button', { name: 'Exit Nodes', exact: true }).click();
  const form = page.locator('form').filter({ has: page.getByRole('heading', { name: 'WireGuard Upstream' }) });
  const field = form.getByLabel('Config', { exact: true });
  const save = form.getByRole('button', { name: 'Save', exact: true });
  const input = form.locator('input[type="file"]');
  await input.setInputFiles({ name: 'test.conf', mimeType: 'text/plain', buffer: Buffer.from('# Imported config') });
  await expect(page.locator('html')).toHaveAttribute('data-file-read-pending', 'true');
  await field.fill('# Newer edit');
  await page.evaluate(() => document.dispatchEvent(new Event('finish-file-read')));
  await expect(page.locator('html')).toHaveAttribute('data-file-read-ready', 'true');
  await expect(field).toHaveValue('# Newer edit');
  await expect(input).toHaveValue('');
  await expect(save).toBeEnabled();
  expect(api.actions).toHaveLength(0);
  await api.reply(await api.poll(), state('Fresh poll'));
  await expect(field).toHaveValue('# Newer edit');
  await expect(save).toBeEnabled();
});

async function copyScenario(page: Page, modern: 'success' | 'reject' | 'pending', fallback: 'success' | 'false' | 'throw') {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(({ modern, fallback }) => {
    Object.defineProperty(navigator, 'clipboard', { value: {
      writeText(value: string) {
        const data = document.documentElement.dataset;
        data.copyAttempt = value;
        const mode = data.clipboardMode || modern;
        if (mode === 'pending') return new Promise<void>((resolve, reject) => {
          document.addEventListener('finish-copy', () => {
            data.copyCompleted = 'true';
            if (data.clipboardResult === 'reject') reject(new Error('Clipboard denied'));
            else resolve();
          }, { once: true });
        });
        return mode === 'reject' ? Promise.reject(new Error('Clipboard denied')) : Promise.resolve();
      },
    } });
    document.execCommand = (command: string) => {
      const data = document.documentElement.dataset;
      data.fallbackCommand = command;
      data.fallbackValue = (document.activeElement as HTMLTextAreaElement).value;
      if (fallback === 'throw') throw new Error('Fallback failed');
      return fallback === 'success';
    };
  }, { modern, fallback });
  const api = await controlledApi(page);
  function networkState(id: string) {
    const next = state('VPN off');
    next.networks[0].networkId = id;
    return next;
  }
  await api.reply(api.polls[0], networkState('network-a'));
  await page.getByRole('button', { name: 'Add Device', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Add Device' });
  const copy = dialog.locator('.detail-list > div').filter({
    has: page.getByText('Network ID', { exact: true }),
  }).getByRole('button');
  return { api, networkState, dialog, copy, errors };
}

for (const modern of ['success', 'reject'] as const) {
  test(`copy reports ${modern === 'success' ? 'modern' : 'fallback'} clipboard success`, async ({ page }, testInfo) => {
    const { dialog, copy, errors } = await copyScenario(page, modern, 'success');
    await copy.click();
    await expect(copy).toHaveAccessibleName('Network ID copied');
    await expect(copy).toHaveClass(/copied/);
    await expect(page.locator('.notice-row')).toHaveText('Network ID copied');
    await expect(page.locator('html')).toHaveAttribute('data-copy-attempt', 'network-a');
    if (modern === 'reject') {
      await expect(page.locator('html')).toHaveAttribute('data-fallback-command', 'copy');
      await expect(page.locator('html')).toHaveAttribute('data-fallback-value', 'network-a');
    } else {
      await expect(page.locator('html')).not.toHaveAttribute('data-fallback-command');
    }
    await expect(page.locator('body > textarea')).toHaveCount(0);
    await dialog.screenshot({ path: testInfo.outputPath('copy-success.png') });
    await page.clock.runFor(2000);
    await expect(copy).toHaveAccessibleName('Copy Network ID');
    expect(errors).toEqual([]);
  });
}

for (const fallback of ['false', 'throw'] as const) {
  test(`copy fallback ${fallback} shows failure and supports retry`, async ({ page }, testInfo) => {
    const { dialog, copy, errors } = await copyScenario(page, 'reject', fallback);
    await copy.click();
    await expect(page.locator('html')).toHaveAttribute('data-fallback-value', 'network-a');
    await expect(page.locator('body > textarea')).toHaveCount(0);
    await expect(dialog.getByRole('status')).toHaveText('Copy failed. Retry');
    await expect(copy).toHaveAccessibleName('Copy Network ID failed. Try again');
    await expect(copy).toBeEnabled();
    await expect(copy).toBeFocused();
    await expect(copy).not.toHaveClass(/copied/);
    await expect(page.locator('.notice-row')).toHaveCount(0);
    expect(errors).toEqual([]);
    await dialog.screenshot({ path: testInfo.outputPath('copy-failure.png') });

    await page.evaluate(() => { document.documentElement.dataset.clipboardMode = 'success'; });
    await page.keyboard.press('Enter');
    await expect(copy).toHaveAccessibleName('Network ID copied');
    await expect(dialog.getByRole('status')).toHaveCount(0);
    await expect(page.locator('.notice-row')).toHaveText('Network ID copied');
    await expect(page.locator('body > textarea')).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}

for (const result of ['success', 'reject'] as const) {
  test(`copy ignores a pending ${result} result for a replaced value`, async ({ page }) => {
    const { api, networkState, dialog, copy, errors } = await copyScenario(page, 'pending', 'false');
    await copy.click();
    await expect(page.locator('html')).toHaveAttribute('data-copy-attempt', 'network-a');
    await api.reply(await api.poll(), networkState('network-b'));
    await expect(dialog.getByText('network-b', { exact: true })).toBeVisible();
    await page.evaluate((result) => {
      document.documentElement.dataset.clipboardResult = result;
      document.dispatchEvent(new Event('finish-copy'));
    }, result);
    await expect(page.locator('html')).toHaveAttribute('data-copy-completed', 'true');
    await expect(copy).toBeEnabled();
    await expect(copy).toHaveAccessibleName('Copy Network ID');
    await expect(copy).not.toHaveClass(/copied/);
    await expect(dialog.getByRole('status')).toHaveCount(0);
    await expect(page.locator('.notice-row')).toHaveCount(0);

    await page.evaluate(() => { document.documentElement.dataset.clipboardMode = 'success'; });
    await copy.click();
    await expect(page.locator('html')).toHaveAttribute('data-copy-attempt', 'network-b');
    await expect(copy).toHaveAccessibleName('Network ID copied');
    await api.reply(await api.poll(), networkState('network-c'));
    await expect(copy).toHaveAccessibleName('Copy Network ID');
    expect(errors).toEqual([]);
  });
}
