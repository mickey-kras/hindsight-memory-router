import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "*.spec.ts",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  webServer: {
    command: "node tests/e2e/server.mjs",
    url: "http://127.0.0.1:4173/version",
    reuseExistingServer: false,
    timeout: 15_000,
  },
  use: {
    baseURL: "http://127.0.0.1:4173",
    // Defaults to Playwright's own chromium; set CHROMIUM_PATH to use a system one.
    launchOptions: process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {},
  },
  projects: [
    {
      name: "laptop",
      use: { viewport: { width: 1512, height: 945 } },
    },
    {
      name: "phone",
      use: {
        viewport: { width: 402, height: 874 },
        isMobile: true,
        hasTouch: true,
        userAgent:
          "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
      },
    },
  ],
});
