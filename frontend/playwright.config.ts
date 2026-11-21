import { defineConfig, devices } from '@playwright/test';

// Browser workflows against the Vite dev server. Each spec serves the API it
// needs from page.route, so no osctrl-api or database is involved; the Go
// tests cover the server side.
export default defineConfig({
  testDir: 'tests/e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev -- --strictPort',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    // The dev server answers from fixtures unless told not to.
    env: { VITE_USE_MOCK_DATA: 'false' },
  },
});
