import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:3300",
    browserName: "chromium",
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    headless: true,
  },
  webServer: {
    command: "npm run start -- --hostname 127.0.0.1 --port 3300",
    url: "http://127.0.0.1:3300/login",
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
