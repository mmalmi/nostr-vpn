import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { state } from './fixtures';
import type { FileTransfer, ParticipantView } from '../src/lib/types';

test('files can be offered, accepted, resumed and saved', async ({ page }) => {
  const current = state('Connected', true);
  current.ownNpub = 'npub-self';
  current.networks[0].participants = [{
    npub: 'npub-peer', pubkeyHex: 'peer', alias: 'Laptop', magicDnsAlias: 'laptop',
    magicDnsName: 'laptop.nvpn', tunnelIp: '', isAdmin: false,
    reachable: true, offersExitNode: false, fipsEndpointHints: [], advertisedRoutes: [],
    txBytes: 0, rxBytes: 0, fipsEndpointNpub: '', fipsTransportAddr: '', fipsTransportType: '',
    fipsPacketsSent: 0, fipsPacketsRecv: 0, fipsBytesSent: 0, fipsBytesRecv: 0,
    state: 'connected', meshState: '', statusText: 'Online', lastSeenText: '',
  } as ParticipantView];
  const incoming: FileTransfer = {
    id: 'incoming', peerNpub: 'npub-peer', peerName: 'Laptop', isSender: false,
    files: [{ name: 'photo.jpg', sizeBytes: 1024, localPath: null }], status: 'offered',
    transferredBytes: 0, totalBytes: 1024, error: null,
  };
  current.fileTransfers = [incoming];
  const actions: string[] = [];
  const uploads: { peer: string | null; name: string | null; bytes: string }[] = [];
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === '/api/files/send') {
      uploads.push({ peer: url.searchParams.get('npub'), name: url.searchParams.get('name'), bytes: request.postData() ?? '' });
      return route.fulfill({ json: { id: 'outgoing' } });
    }
    if (url.pathname.startsWith('/api/files/incoming/')) {
      actions.push(url.pathname.split('/').at(-1)!);
      incoming.status = actions.at(-1) === 'accept' ? 'paused' : 'completed';
      incoming.transferredBytes = incoming.status === 'completed' ? 1024 : 512;
      return route.fulfill({ json: {} });
    }
    await route.fulfill({ json: current });
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Send files', exact: true })).toBeEnabled();
  await page.getByLabel('Files to send').setInputFiles([
    { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello from nvpn') },
    { name: 'another.txt', mimeType: 'text/plain', buffer: Buffer.from('second file') },
  ]);
  await expect.poll(() => uploads.length).toBe(2);
  expect(uploads).toEqual([
    { peer: 'npub-peer', name: 'notes.txt', bytes: 'hello from nvpn' },
    { peer: 'npub-peer', name: 'another.txt', bytes: 'second file' },
  ]);
  const transfers = page.getByRole('region', { name: 'File transfers' });
  await expect(transfers.getByText('Wants to send you files')).toBeVisible();
  await transfers.getByRole('button', { name: 'Accept', exact: true }).click();
  await expect(transfers.getByRole('button', { name: 'Resume', exact: true })).toBeVisible();
  await transfers.getByRole('button', { name: 'Resume', exact: true }).click();
  const download = transfers.getByRole('link', { name: 'Save photo.jpg' });
  await expect(download).toHaveAttribute('href', '/api/files/incoming/0');
  expect(actions).toEqual(['accept', 'resume']);
  expect(errors).toEqual([]);
  await mkdir('../../artifacts/file-transfers', { recursive: true });
  await page.screenshot({ path: '../../artifacts/file-transfers/web-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(download).toBeVisible();
  const navigation = await page.getByRole('navigation', { name: 'Primary' }).boundingBox();
  const transferBounds = await transfers.boundingBox();
  expect(transferBounds!.y - navigation!.y - navigation!.height).toBeLessThan(48);
  await page.screenshot({ path: '../../artifacts/file-transfers/web-mobile.png', fullPage: true });
});

test('offline transfers explain connection requirement and service errors', async ({ page }) => {
  const current = state('Disconnected', false);
  current.fileTransfers = [
    { id: 'service', peerNpub: '', peerName: '', isSender: false, files: [], status: 'unavailable', transferredBytes: 0, totalBytes: 0, error: 'File storage is unavailable.' },
    { id: 'offer', peerNpub: 'npub-peer', peerName: 'Laptop', isSender: false, files: [{ name: 'notes.txt', sizeBytes: 10, localPath: null }], status: 'offered', transferredBytes: 0, totalBytes: 10, error: null },
  ];
  await page.route('**/api/**', route => route.fulfill({ json: current }));
  await page.goto('/');
  const transfers = page.getByRole('region', { name: 'File transfers' });
  await expect(transfers.getByText('Files unavailable', { exact: true })).toBeVisible();
  await expect(transfers.getByText('File storage is unavailable.')).toBeVisible();
  await expect(transfers.getByText('Connect VPN to continue transfers.')).toBeVisible();
  await expect(transfers.getByRole('button', { name: 'Accept', exact: true })).toBeDisabled();
  await expect(transfers.getByText('From · 0 B', { exact: true })).toHaveCount(0);
});
