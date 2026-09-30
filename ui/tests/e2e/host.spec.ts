import { expect, test, type Page } from "@playwright/test";

const MOCK = `http://127.0.0.1:${process.env.MOCK_PORT ?? "8899"}`;
const ITEM = "q_recall_aaaabbbbccccdddd";
const STALE = JSON.stringify({ read: "stale-read", review: "stale-review", cleanup: "stale-cleanup" });

async function host(page: Page, session = "operator") {
  if (session) await page.context().addCookies([{ name: "host-session", value: session, url: `http://127.0.0.1:${process.env.UI_PORT ?? "4173"}` }]);
  await page.addInitScript((stale) => {
    sessionStorage.setItem("mr-admin-tokens", stale);
    const storageAccess: string[] = [];
    Object.assign(window, { hostTokenStorageAccess: storageAccess });
    const get = Storage.prototype.getItem;
    const set = Storage.prototype.setItem;
    const remove = Storage.prototype.removeItem;
    // Record reads even when session helpers swallow storage exceptions.
    Storage.prototype.getItem = function (key: string) { if (key === "mr-admin-tokens") storageAccess.push("get"); return get.call(this, key); };
    Storage.prototype.setItem = function (key: string, value: string) { if (key === "mr-admin-tokens") storageAccess.push("set"); set.call(this, key, value); };
    Storage.prototype.removeItem = function (key: string) { if (key === "mr-admin-tokens") storageAccess.push("remove"); remove.call(this, key); };
    window.__MEMORY_ROUTER_UI_CONFIG__ = { auth: "host", baseUrl: `${location.origin}/host`, chrome: { embed: true, header: false } };
  }, STALE);
  await page.goto("/");
}

async function openItem(page: Page, phone: boolean, item = ITEM) {
  await page.getByTestId(`${phone ? "card" : "row"}-${item}`).click();
  await expect(page.getByTestId("postpone")).toBeVisible();
}

test.beforeEach(async ({ request }) => { expect((await request.post(`${MOCK}/__reset`)).ok()).toBe(true); });

test("host proxy injects scoped credentials for read, review and cleanup without browser tokens", async ({ page }, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const auth: Array<string | undefined> = [];
  page.on("request", (request) => { if (request.url().includes("/host/admin/")) auth.push(request.headers()["authorization"]); });
  await host(page);
  await expect(page.getByTestId("stats")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Memory Router - Quarantine" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Connect", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Disconnect" })).toHaveCount(0);
  await expect(page.getByTestId("console")).not.toHaveClass(/min-h-dvh/);
  await page.getByTestId("refresh").click();
  await openItem(page, info.project.name === "phone");
  await page.getByTestId("postpone").click();
  await expect(page.getByText(`postponed ${ITEM}`)).toBeVisible();
  await page.getByRole("button", { name: "Cleanup", exact: true }).click();
  await page.getByTestId("cleanup-preview-run").click();
  await expect(page.getByTestId("cleanup-preview")).toContainText("3 items");
  await page.getByTestId("cleanup-execute").click();
  await expect(page.getByText(/cleanup removed 3 items/)).toBeVisible();
  expect(auth.length).toBeGreaterThan(4);
  expect(auth.every((value) => value === undefined)).toBe(true);
  expect(errors).toEqual([]);
  expect(await page.evaluate(() => Reflect.get(window, "hostTokenStorageAccess"))).toEqual([]);
  expect(await page.evaluate(() => Object.fromEntries(Object.entries(sessionStorage))["mr-admin-tokens"])).toBe(STALE);
});

for (const session of ["", "expired"]) {
  test(`absent or expired session (${session}) stays in host mode without token fallback`, async ({ page }) => {
    await host(page, session);
    await expect(page.getByRole("alert")).toContainText("sign in through the host");
    await expect(page.getByTestId("stats")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Connect", exact: true })).toHaveCount(0);
  });
}

test("read-only host operator cannot review or clean up", async ({ page }, info) => {
  await host(page, "reader");
  await expect(page.getByTestId("stats")).toBeVisible();
  await openItem(page, info.project.name === "phone");
  await page.getByTestId("postpone").click();
  await expect(page.getByRole("alert")).toContainText("host_permission_denied");
  await page.getByRole("button", { name: "Cleanup", exact: true }).click();
  await page.getByTestId("cleanup-preview-run").click();
  await expect(page.getByTestId("cleanup").getByRole("alert")).toContainText("host_permission_denied");
  expect(await (await page.request.get(`${MOCK}/__actions`)).json()).toEqual([]);
});

for (const operation of ["refresh", "review", "cleanup"]) {
  test(`session expiration during ${operation} clears sensitive and actionable stale state`, async ({ page }, info) => {
    await host(page);
    await expect(page.getByTestId("stats")).toBeVisible();
    await openItem(page, info.project.name === "phone");
    await page.getByRole("button", { name: "Cleanup", exact: true }).click();
    await page.getByTestId("cleanup-preview-run").click();
    await expect(page.getByTestId("cleanup-preview")).toBeVisible();
    await page.context().clearCookies();
    await page.getByTestId(operation === "review" ? "postpone" : operation === "cleanup" ? "cleanup-execute" : "refresh").click();
    await expect(page.getByRole("alert")).toContainText("sign in through the host");
    await expect(page.getByTestId("item-detail")).toHaveCount(0);
    await expect(page.getByTestId("cleanup")).toHaveCount(0);
    await expect(page.getByTestId("stats")).toHaveCount(0);
  });
}

test("host rejects CSRF mutations with missing, foreign or opaque Origin", async ({ page }) => {
  await host(page);
  await expect(page.getByTestId("stats")).toBeVisible();
  for (const origin of [undefined, "https://attacker.example", "null"]) {
    const response = await page.request.post(`/host/admin/quarantine/items/${ITEM}/postpone`, { headers: origin ? { origin } : {} });
    expect(response.status()).toBe(403);
    expect(await response.text()).toContain("host_csrf_rejected");
  }
  expect(await (await page.request.get(`${MOCK}/__actions`)).json()).toEqual([]);
});

test("token embed preserves session restoration and Disconnect", async ({ page }) => {
  await page.addInitScript(() => {
    window.__MEMORY_ROUTER_UI_CONFIG__ = { chrome: { embed: true, header: false } };
    sessionStorage.setItem("mr-admin-tokens", JSON.stringify({ read: "e2e-read-token", review: "", cleanup: "" }));
  });
  await page.goto("/");
  await expect(page.getByTestId("stats")).toBeVisible();
  await expect(page.getByTestId("console")).not.toHaveClass(/min-h-dvh/);
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByRole("button", { name: "Connect", exact: true })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("mr-admin-tokens"))).toBeNull();
});

test("expiration during pagination clears the queue", async ({ page }) => {
  await page.request.post(`${MOCK}/__seed-more`);
  await host(page);
  await expect(page.getByText("100 shown / 105 reviewable")).toBeVisible();
  await page.context().clearCookies();
  await page.getByTestId("load-more").click();
  await expect(page.getByRole("alert")).toContainText("sign in through the host");
  await expect(page.getByTestId("stats")).toHaveCount(0);
  await expect(page.getByTestId("load-more")).toHaveCount(0);
});

for (const chrome of [{ header: false }, { branding: false }, {}]) {
  test(`standalone chrome contract remains unchanged: ${JSON.stringify(chrome)}`, async ({ page }) => {
    await page.addInitScript((flags) => {
      window.__MEMORY_ROUTER_UI_CONFIG__ = { chrome: flags };
      sessionStorage.setItem("mr-admin-tokens", JSON.stringify({ read: "e2e-read-token", review: "", cleanup: "" }));
    }, chrome);
    await page.goto("/");
    await expect(page.getByTestId("stats")).toBeVisible();
    await expect(page.getByTestId("console")).toHaveClass(/min-h-dvh/);
    await expect(page.getByTestId("refresh")).toHaveCount(chrome.header === false ? 0 : 1);
    await expect(page.getByRole("heading", { name: "Memory Router - Quarantine" })).toHaveCount(chrome.header === false || chrome.branding === false ? 0 : 1);
  });
}

for (const pending of ["refresh", "load-more"]) {
  test(`late ${pending} success cannot restore data after a concurrent 401`, async ({ page }, info) => {
    if (pending === "load-more") await page.request.post(`${MOCK}/__seed-more`);
    await host(page);
    await expect(page.getByTestId("stats")).toBeVisible();
    const selectedId = pending === "load-more" ? "q_retain_0123456789abcdef" : ITEM;
    await openItem(page, info.project.name === "phone", selectedId);
    let releaseResponse: (() => void) | undefined;
    let markCaptured: (() => void) | undefined;
    const captured = new Promise<void>((resolve) => { markCaptured = resolve; });
    const delayed = new Promise<void>((resolve) => { releaseResponse = resolve; });
    await page.route("**/host/admin/quarantine/queue?*", async (route) => {
      const response = await route.fetch();
      markCaptured?.();
      await delayed;
      await route.fulfill({ response });
    });
    await page.getByTestId(pending).click();
    await captured;
    await page.context().clearCookies();
    await page.getByTestId("postpone").click();
    await expect(page.getByRole("alert")).toContainText("sign in through the host");
    const delivered = page.waitForResponse((response) => response.url().includes("/host/admin/quarantine/queue?"));
    releaseResponse?.();
    await (await delivered).finished();
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await expect(page.getByTestId("refresh")).toBeEnabled();
    await expect(page.getByTestId("stats")).toHaveCount(0);
    await expect(page.getByTestId(`row-${selectedId}`)).toHaveCount(0);
    await expect(page.getByTestId(`card-${selectedId}`)).toHaveCount(0);
  });
}
