import { test, expect } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { dashboardMock } from "../src/lib/mock-data";

const screenshotDir = path.resolve(__dirname, "../../docs/screenshots");
const dashboard = {
  ...dashboardMock,
  recentScans: dashboardMock.recentScans.map((scan, index) => ({
    ...scan,
    target: [
      "registry.example.com/api:1.4",
      "git.example.com/team/gateway",
      "Dockerfile (demo-service)",
      "registry.example.com/web:2.1",
    ][index],
  })),
};

test("desktop dashboard renders sample data and supports navigation", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    localStorage.setItem("rootsecops_access_token", "synthetic-screenshot-session");
    localStorage.setItem("rootsecops_last_activity", String(Date.now()));
  });
  await page.route("**/api/v1/**", async (route) => {
    if (new URL(route.request().url()).pathname === "/api/v1/dashboard/") {
      await route.fulfill({ json: dashboard });
    } else {
      await route.fulfill({ status: 404, json: { detail: "Not part of the screenshot fixture" } });
    }
  });
  await mkdir(screenshotDir, { recursive: true });
  await page.setViewportSize({ width: 1600, height: 1120 });
  await page.goto("/dashboard");
  await expect(page).toHaveTitle("RootSecOps | Security Orchestration");
  await expect(page.getByRole("heading", { name: "RootSecOps", exact: true })).toBeVisible();
  await expect(page.getByText("482", { exact: true })).toBeVisible();
  await expect(page.getByText(dashboard.recentScans[0].target, { exact: true })).toBeVisible();
  await expect(page.locator(".recharts-sector").first()).toBeVisible();
  // Recharts animates SVG geometry independently of CSS animation settings.
  await page.waitForTimeout(1800);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
  await page.screenshot({ path: path.join(screenshotDir, "dashboard.png"), fullPage: true, animations: "disabled" });

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Activity Log" }).click();
  expect((await downloadPromise).suggestedFilename()).toBe("rootsecops-activity.json");

  await page.getByRole("button", { name: "New Orchestrated Scan" }).click();
  await expect(page.getByText("Docker Image", { exact: true }).first()).toBeVisible();
  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  await expect(page.getByText("482", { exact: true })).toBeVisible();

  expect(errors).toEqual([]);
});

test("unauthenticated dashboard redirects to login", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page).toHaveTitle("RootSecOps | Security Orchestration");
  await expect(page.getByText("RootSecOps Login", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  const icon = await page.request.get("/icon");
  expect(icon.ok()).toBe(true);
  expect(icon.headers()["content-type"]).toContain("image/png");
});
