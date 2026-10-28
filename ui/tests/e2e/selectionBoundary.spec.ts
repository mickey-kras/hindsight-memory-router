import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type ViteDevServer } from "vite";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const MOCK_ORIGIN = `http://127.0.0.1:${process.env.MOCK_PORT ?? "8899"}`;
let devServer: ViteDevServer;
let harnessUrl: string;

test.beforeAll(async () => {
  // Serve the real component in a parent that observes the layout/passive boundary.
  devServer = await createServer({
    root: ROOT,
    server: { host: "127.0.0.1", port: 0, proxy: { "/admin": MOCK_ORIGIN } },
  });
  await devServer.listen();
  harnessUrl = devServer.resolvedUrls!.local[0]! + "tests/e2e/selectionBoundary.html";
});
test.afterAll(async () => { await devServer?.close(); });

test("selection clears old plaintext before passive effects can run", async ({ page, request }) => {
  await request.post(`${MOCK_ORIGIN}/__reset`);
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

for (const outcome of ["success", "error"] as const) {
  test(`selection clears agent credentials and ignores late agent ${outcome}`, async ({ page, request }) => {
    await request.post(`${MOCK_ORIGIN}/__reset`);
    const fixture = (id: string) => JSON.parse(readFileSync(path.join(ROOT, `tests/fixtures/${id}.decrypted.json`), "utf8"));
    const retain = fixture("q_retain_0123456789abcdef");
    const recall = fixture("q_recall_aaaabbbbccccdddd");
    let startOld!: () => void;
    let releaseOld!: () => void;
    const started = new Promise<void>((resolve) => { startOld = resolve; });
    const released = new Promise<void>((resolve) => { releaseOld = resolve; });
    await page.route("http://127.0.0.1:8765/decrypt", async (route) => {
      const id = route.request().postDataJSON().envelope.quarantine_id;
      if (id === retain.quarantine_id) {
        expect(route.request().headers().authorization).toBe(`Bearer ${"a".repeat(32)}`);
        startOld();
        await released;
        await route.fulfill({
          status: outcome === "success" ? 200 : 422,
          json: outcome === "success" ? { decrypted: retain } : { error: "review_decrypt_failed" },
          headers: { "Access-Control-Allow-Origin": "*" },
        });
      } else {
        expect(id).toBe(recall.quarantine_id);
        expect(route.request().headers().authorization).toBe(`Bearer ${"b".repeat(32)}`);
        await route.fulfill({ json: { decrypted: recall }, headers: { "Access-Control-Allow-Origin": "*" } });
      }
    });
    await page.goto(harnessUrl);
    await page.evaluate(() => {
      const state = window as typeof window & { reviewedDigests: number };
      state.reviewedDigests = 0;
      const original = crypto.subtle.digest.bind(crypto.subtle);
      crypto.subtle.digest = async (algorithm, data) => {
        const result = await original(algorithm, data);
        state.reviewedDigests += 1;
        return result;
      };
    });
    await page.getByTestId("use-agent").check();
    await page.getByTestId("agent-credential").fill("a".repeat(32));
    await page.getByTestId("decrypt-agent").click();
    await started;
    await page.evaluate(() => window.selectBoundaryItem());
    await expect(page.getByTestId("agent-credential")).toHaveValue("");
    await expect(page.getByTestId("decrypt-agent")).toBeDisabled();
    await expect(page.getByTestId("payload")).toHaveCount(0);
    await page.getByTestId("agent-credential").fill("b".repeat(32));
    await page.getByTestId("decrypt-agent").click();
    await expect(page.getByTestId("payload")).toContainText(recall.quarantine_id);
    const oldResponse = page.waitForResponse((response) =>
      response.url() === "http://127.0.0.1:8765/decrypt" &&
      response.request().postDataJSON().envelope.quarantine_id === retain.quarantine_id,
    );
    releaseOld();
    await (await oldResponse).finished();
    if (outcome === "success") {
      await page.waitForFunction(() => (window as typeof window & { reviewedDigests: number }).reviewedDigests === 2);
    }
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(page.getByTestId("payload")).toContainText(recall.quarantine_id);
    await expect(page.getByTestId("payload")).not.toContainText(retain.quarantine_id);
    await expect(page.getByRole("alert")).toHaveCount(0);
  });
}
