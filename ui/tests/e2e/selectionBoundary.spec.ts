import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type ViteDevServer } from "vite";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let devServer: ViteDevServer;
let harnessUrl: string;

test.beforeAll(async () => {
  // Serve the real component in a parent that observes the layout/passive boundary.
  devServer = await createServer({ root: ROOT, server: { host: "127.0.0.1", port: 0 } });
  await devServer.listen();
  harnessUrl = devServer.resolvedUrls!.local[0]! + "tests/e2e/selectionBoundary.html";
});
test.afterAll(async () => { await devServer?.close(); });

test("selection clears old plaintext before passive effects can run", async ({ page, request }) => {
  await request.post(`http://127.0.0.1:${process.env.MOCK_PORT ?? "8899"}/__reset`);
  await page.goto(harnessUrl);
  await page.getByTestId("key-input").fill(readFileSync(path.join(ROOT, "tests/fixtures/quarantine-private.pem"), "utf8"));
  await page.getByTestId("import-key").click();
  await page.getByTestId("decrypt").click();
  await expect(page.getByTestId("payload")).toContainText("q_retain_0123456789abcdef");
  await page.evaluate(() => window.selectBoundaryItem());
  await page.waitForFunction(() => window.boundarySnapshot !== undefined);
  const snapshot = await page.evaluate(() => window.boundarySnapshot);
  expect(snapshot).toEqual({ item: "q_recall_aaaabbbbccccdddd", payload: null });
  // The imported key still belongs to the detail session across item selection.
  await expect(page.getByTestId("key-input")).toHaveCount(0);
  await page.getByTestId("decrypt").click();
  await expect(page.getByTestId("payload")).toContainText("q_recall_aaaabbbbccccdddd");
});
