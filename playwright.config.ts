import { defineConfig, devices } from '@playwright/test';

/**
 * E2E config for the Nginx Log Analyzer dashboard (branch new-ui2).
 *
 * The dev server is a container (`sysadmin-toolkit-app-dev`) that is already
 * running on :3001. We deliberately do NOT use `webServer` here — the container
 * owns its own lifecycle and re-running `npm run dev` would fight it.
 * Specs reuse the fixture so a full run costs zero tokens.
 */
const BASE_URL = process.env.E2E_BASE_URL ?? 'http://localhost:3001';
const NGINX_PATH = '/nginx';

export default defineConfig({
  testDir: './tests/e2e',
  outputDir: './test-results',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // Each worker drives a headless Chromium *and* triggers a server-side
  // analysis on the dev container. On a 4-core box, one worker per core
  // oversubscribes and the dashboard fails to un-hide within its timeout.
  // 2 keeps the suite fast without the flakes.
  workers: process.env.CI ? 1 : 2,
  retries: process.env.CI ? 2 : 1,
  // The dashboard runs long JS passes over 100k-char logs; give it room.
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],

  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    viewport: { width: 1440, height: 1080 },
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
