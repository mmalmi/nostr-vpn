import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.NVPN_UMBREL_WEB_BASE_URL ?? 'http://127.0.0.1:38080';
const workers = Number.parseInt(process.env.PLAYWRIGHT_WORKERS ?? '1', 10);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: Number.isFinite(workers) && workers > 0 ? workers : 1,
  forbidOnly: Boolean(process.env.CI),
  reporter: process.env.CI
    ? [['list'], ['html', { open: 'never', outputFolder: '../../artifacts/playwright-report/control-panel' }]]
    : 'list',
  use: {
    baseURL,
    headless: true,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        browserName: 'chromium',
      },
    },
  ],
});
