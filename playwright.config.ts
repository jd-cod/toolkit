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

// The per-tool suites (tests/e2e/tools) generate their inputs from this seed.
// Setting it here, before workers start, gives every worker the same value and
// lets a failed run be replayed with `E2E_SEED=<value>`.
if (!process.env.E2E_SEED) process.env.E2E_SEED = String(1 + Math.floor(Math.random() * 2_000_000_000));

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
      testIgnore: '**/tools/**',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      // Deep per-tool suites: every value a tool shows is checked against an
      // expected value computed by the test. See tests/e2e/tools/README.md.
      name: 'tools',
      testDir: './tests/e2e/tools',
      // No retries by default: a check that fails once is a finding to look
      // at, not noise to retry away. Inputs are seeded, so a rerun is exact.
      retries: Number(process.env.E2E_RETRIES ?? 0),
      timeout: 120_000,
      expect: { timeout: 15_000 },
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 1080 },
        permissions: ['clipboard-read', 'clipboard-write'],
        acceptDownloads: true,
        timezoneId: process.env.E2E_TIMEZONE ?? 'America/New_York',
        locale: 'en-US',
      },
    },
  ],
});
