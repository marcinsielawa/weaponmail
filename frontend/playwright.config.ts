import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E configuration for WeaponMail.
 *
 * Tests are run sequentially (workers: 1) so that the two-user
 * SSE flow executes in a predictable, realistic order.
 *
 * The webServer block starts the Angular dev server automatically
 * when tests are launched.  In CI the backend is expected to already
 * be running on port 8080; the Angular proxy.conf.json forwards all
 * /api/* traffic there.
 */
export default defineConfig({
  testDir: './tests',

  /* Run tests sequentially – the messaging flow is inherently ordered */
  fullyParallel: false,
  workers: 1,

  /* Fail the build on CI if test.only was accidentally left in */
  forbidOnly: Boolean(process.env['CI']),

  /* One retry on CI to absorb transient flakiness */
  retries: process.env['CI'] ? 1 : 0,

  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'html',

  /* Generous timeout – Argon2id key derivation + SSE delivery can be slow */
  timeout: 120_000,
  expect: { timeout: 30_000 },

  use: {
    baseURL: 'http://localhost:4200',
    trace: 'on-first-retry',
    video: process.env['CI'] ? 'on-first-retry' : 'off',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  /* Start the Angular dev server before running tests.
     In CI the server is started by the workflow so we reuse it. */
  webServer: {
    command: 'npm start',
    url: 'http://localhost:4200',
    reuseExistingServer: true,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
