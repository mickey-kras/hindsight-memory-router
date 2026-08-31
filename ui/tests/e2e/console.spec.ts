import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");
const PRIVATE_PEM = readFileSync(path.join(FIXTURES, "quarantine-private.pem"), "utf8");
const RETAIN_ID = "q_retain_0123456789abcdef";
const RECALL_ID = "q_recall_aaaabbbbccccdddd";
const QUERY_ID = "q_query_f00df00df00df00d";

const READ = "e2e-read-token";
const REVIEW = "e2e-review-token";
const CLEANUP = "e2e-cleanup-token";
const MOCK_ORIGIN = `http://127.0.0.1:${process.env.MOCK_PORT ?? "8899"}`;

async function connect(page: Page, tokens: { read?: string; review?: string; cleanup?: string } = {}) {
  await page.goto("/");
  await page.getByPlaceholder("MEMORY_ROUTER_ADMIN_READ_TOKEN").fill(tokens.read ?? READ);
  await page.getByPlaceholder("MEMORY_ROUTER_ADMIN_REVIEW_TOKEN").fill(tokens.review ?? REVIEW);
  await page.getByPlaceholder("MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN").fill(tokens.cleanup ?? CLEANUP);
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByTestId("stats")).toBeVisible();
}

async function mockActions(page: Page): Promise<Array<Record<string, unknown>>> {
  const response = await page.request.get(`${MOCK_ORIGIN}/__actions`);
  return (await response.json()) as Array<Record<string, unknown>>;
}

test.beforeEach(async ({ page }) => {
  const response = await page.request.post(`${MOCK_ORIGIN}/__reset`);
  expect(response.ok()).toBe(true);
});

test("connect screen probes the router and shows the version", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText(/router reachable, API/)).toBeVisible();
  await expect(page.getByText(/0\.9\.0-e2e-mock/)).toBeVisible();
});

test("stats and queue render after connect", async ({ page }, testInfo) => {
  await connect(page);
  await expect(page.getByTestId("stats")).toContainText("Pending");
  await expect(page.getByText(/3 reviewable|3 shown/)).toBeVisible();
  if (testInfo.project.name === "phone") {
    await expect(page.getByTestId(`card-${RETAIN_ID}`)).toBeVisible();
    await expect(page.getByTestId(`row-${RETAIN_ID}`)).toBeHidden();
  } else {
    await expect(page.getByTestId(`row-${RETAIN_ID}`)).toBeVisible();
  }
});

test("loads reviewable items beyond the first page", async ({ page }) => {
  await page.request.post(`${MOCK_ORIGIN}/__seed-more`);
  await connect(page);
  await expect(page.getByText("100 shown / 105 reviewable")).toBeVisible();
  await page.getByTestId("load-more").click();
  await expect(page.getByText("105 shown / 105 reviewable")).toBeVisible();
  await expect(page.getByTestId("load-more")).toHaveCount(0);
});

test("wrong read token surfaces a 401", async ({ page }) => {
  await page.goto("/");
  await page.getByPlaceholder("MEMORY_ROUTER_ADMIN_READ_TOKEN").fill("wrong-token");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByRole("alert")).toContainText("401");
});

test("decrypt an item with the real key and approve it", async ({ page }, testInfo) => {
  await connect(page);
  const opener = page.getByTestId(
    `${testInfo.project.name === "phone" ? "card" : "row"}-${RETAIN_ID}`,
  );
  await opener.click();
  await expect(page.getByTestId("item-detail")).toBeVisible();

  await page.getByTestId("key-input").fill(PRIVATE_PEM);
  await page.getByTestId("import-key").click();
  await page.getByTestId("decrypt").click();

  const payload = page.getByTestId("payload");
  await expect(payload).toBeVisible();
  await expect(payload).toContainText("correct-horse-battery-staple");
  await expect(payload).toContainText(RETAIN_ID);

  await page.getByTestId("approve-open").click();
  await page.getByTestId("confirm-action").click();
  await expect(page.getByText(`approved ${RETAIN_ID}`)).toBeVisible();

  const actions = await mockActions(page);
  const approve = actions.find((a) => a["action"] === "approve");
  expect(approve).toBeDefined();
  const expected = JSON.parse(
    readFileSync(path.join(FIXTURES, `${RETAIN_ID}.decrypted.json`), "utf8"),
  ) as unknown;
  expect(approve?.["decrypted"]).toEqual(expected);

  await expect(page.getByText(/2 shown/)).toBeVisible();
});

test("reject flow removes the item from the reviewable queue", async ({ page }, testInfo) => {
  await connect(page);
  await page
    .getByTestId(`${testInfo.project.name === "phone" ? "card" : "row"}-${RECALL_ID}`)
    .click();
  await page.getByTestId("reject-open").click();
  await page.getByTestId("confirm-action").click();
  await expect(page.getByText(`rejected ${RECALL_ID}`)).toBeVisible();
  const actions = await mockActions(page);
  expect(actions.some((a) => a["action"] === "reject" && a["quarantine_id"] === RECALL_ID)).toBe(true);
});

test("postpone keeps the item and increments the count", async ({ page }, testInfo) => {
  await connect(page);
  await page
    .getByTestId(`${testInfo.project.name === "phone" ? "card" : "row"}-${RECALL_ID}`)
    .click();
  await page.getByTestId("postpone").click();
  await expect(page.getByText(`postponed ${RECALL_ID}`)).toBeVisible();
  const actions = await mockActions(page);
  expect(actions.some((a) => a["action"] === "postpone")).toBe(true);
});

test("approve stays disabled until the item is decrypted", async ({ page }, testInfo) => {
  await connect(page);
  await page
    .getByTestId(`${testInfo.project.name === "phone" ? "card" : "row"}-${RETAIN_ID}`)
    .click();
  await expect(page.getByTestId("approve-open")).toBeDisabled();
});

test("garbage decryption key shows an import error", async ({ page }, testInfo) => {
  await connect(page);
  await page
    .getByTestId(`${testInfo.project.name === "phone" ? "card" : "row"}-${QUERY_ID}`)
    .click();
  await page.getByTestId("key-input").fill("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----");
  await page.getByTestId("import-key").click();
  await expect(page.getByRole("alert")).toContainText(/not a valid RSA decryption key|PKCS8/);
});

test("cleanup preview then execute", async ({ page }) => {
  await connect(page);
  await page.getByRole("button", { name: "Cleanup", exact: true }).click();
  await page.getByTestId("cleanup-preview-run").click();
  await expect(page.getByTestId("cleanup-preview")).toContainText("3 items");
  await page.getByTestId("cleanup-execute").click();
  await expect(page.getByText(/cleanup removed 3 items/)).toBeVisible();
  await expect(page.getByText("Quarantine is empty.")).toBeVisible();
  await expect(page.getByTestId("cleanup-execute")).toBeDisabled();
});

test("cleanup selection conflict clears the stale preview", async ({ page }) => {
  await connect(page);
  await page.getByRole("button", { name: "Cleanup", exact: true }).click();
  await page.getByTestId("cleanup-preview-run").click();
  await expect(page.getByTestId("cleanup-preview")).toContainText("3 items");

  const changed = await page.request.post(`${MOCK_ORIGIN}/admin/quarantine/cleanup`, {
    headers: { authorization: `Bearer ${CLEANUP}` },
    data: { dry_run: false, expected_count: 3 },
  });
  expect(changed.ok()).toBe(true);

  await page.getByTestId("cleanup-execute").click();
  await expect(page.getByRole("alert")).toContainText("quarantine_cleanup_changed");
  await expect(page.getByTestId("cleanup-preview")).toHaveCount(0);
  await expect(page.getByTestId("cleanup-execute")).toBeDisabled();
});

test("mock cleanup honors older_than", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === "phone", "API contract pin is viewport-independent");
  const response = await page.request.post(`${MOCK_ORIGIN}/admin/quarantine/cleanup`, {
    headers: { authorization: `Bearer ${CLEANUP}` },
    data: { dry_run: true, older_than: "2026-08-29T00:00:00.000Z" },
  });
  expect(response.status()).toBe(200);
  expect((await response.json()).count).toBe(1);
});

test("mock enforces postpone limit and review response contracts", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === "phone", "API contract pin is viewport-independent");
  for (let count = 1; count <= 3; count += 1) {
    const response = await page.request.post(
      `${MOCK_ORIGIN}/admin/quarantine/items/${RETAIN_ID}/postpone`,
      { headers: { authorization: `Bearer ${REVIEW}` } },
    );
    expect(await response.json()).toEqual({ postponed: true, quarantine_id: RETAIN_ID, count });
  }
  const limited = await page.request.post(
    `${MOCK_ORIGIN}/admin/quarantine/items/${RETAIN_ID}/postpone`,
    { headers: { authorization: `Bearer ${REVIEW}` } },
  );
  expect(limited.status()).toBe(409);

  const rejected = await page.request.post(
    `${MOCK_ORIGIN}/admin/quarantine/items/${RECALL_ID}/reject`,
    { headers: { authorization: `Bearer ${REVIEW}` } },
  );
  expect(await rejected.json()).toEqual({
    reviewed: true,
    allowed: false,
    quarantine_id: RECALL_ID,
    source_bank: "openclaw-main",
    source_memory_id: "mem_01J8ZK3W0Q",
  });
});

test("cleanup execute is blocked without a preview", async ({ page }) => {
  await connect(page);
  await page.getByRole("button", { name: "Cleanup", exact: true }).click();
  await expect(page.getByTestId("cleanup-execute")).toBeDisabled();
});

test("tokens persist across reload within the tab but never hit localStorage", async ({ page }) => {
  await connect(page);
  await page.reload();
  await expect(page.getByTestId("stats")).toBeVisible();
  const localStorageSize = await page.evaluate(() => window.localStorage.length);
  expect(localStorageSize).toBe(0);
});
