// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  CleanupResponse,
  QuarantineItemSummary,
  QuarantineQueueResponse,
  QuarantineStats,
} from "../../src/lib/types";

vi.mock("../../src/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/lib/api")>()),
  listQueue: vi.fn(),
  fetchStats: vi.fn(),
  fetchItem: vi.fn(),
  runCleanup: vi.fn(),
  fetchLiveness: vi.fn(),
}));

const api = await import("../../src/lib/api");
const { CONFIG_KEY } = await import("../../src/lib/config");
const { default: App } = await import("../../src/App");
const { Banner } = await import("../../src/components/Banner");
const { CleanupPanel } = await import("../../src/components/CleanupPanel");
const { ConnectScreen } = await import("../../src/components/ConnectScreen");
const { QueueView } = await import("../../src/components/QueueView");
const { StatsBar } = await import("../../src/components/StatsBar");

const host = globalThis as Record<string, unknown>;
const TOKENS = { read: "r", review: "rv", cleanup: "c" };
const UNAUTHORIZED = new api.ApiError(401, "unauthorized", "expired");

const STATS: QuarantineStats = {
  total_items: 9,
  pending_items: 3,
  postponed_items: 1,
  review_side_effect_started_items: 1,
  review_side_effect_completed_items: 1,
  reviewed_allowed_items: 2,
  reviewed_blocked_items: 1,
  encrypted_bytes: 2048,
  event_count: 42,
  banks: [],
};

function item(id: string, overrides: Partial<QuarantineItemSummary> = {}): QuarantineItemSummary {
  return {
    quarantine_id: id,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    kind: "retain_request",
    reason: "suspicious_content",
    sha256: "hash",
    status: "pending",
    postpone_count: 0,
    requarantine_count: 0,
    ...overrides,
  };
}

function queue(items: QuarantineItemSummary[], total = items.length): QuarantineQueueResponse {
  return { items, total };
}

function deferred<T>() {
  let resolve: (value: T) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  vi.resetAllMocks();
  sessionStorage.clear();
  vi.mocked(api.fetchLiveness).mockResolvedValue({ status: "alive" });
  vi.mocked(api.fetchStats).mockResolvedValue(STATS);
  vi.mocked(api.listQueue).mockResolvedValue(queue([item("q_1")]));
  vi.mocked(api.fetchItem).mockReturnValue(new Promise(() => {}));
});
afterEach(() => {
  cleanup();
  delete host[CONFIG_KEY];
});

describe("Banner", () => {
  it("announces errors as alerts and other kinds through <output>", () => {
    const { container } = render(createElement("div", null,
      createElement(Banner, { kind: "error", text: "broken" }),
      createElement(Banner, { kind: "ok", text: "done" }),
    ));
    expect(screen.getByRole("alert").textContent).toContain("broken");
    expect(container.querySelector("output")?.textContent).toContain("done");
    expect(screen.queryByLabelText("dismiss")).toBeNull();
  });
});

describe("StatsBar", () => {
  it("sums stuck items and formats sizes", () => {
    render(createElement(StatsBar, { stats: STATS }));
    const text = screen.getByTestId("stats").textContent ?? "";
    expect(text).toContain("Stuck2");
    expect(text).toContain("Events42");
    expect(text).toContain("2.0 KiB");
  });
});

describe("QueueView", () => {
  const base = { selectedId: null, loadingMore: false, onSelect: vi.fn(), onLoadMore: vi.fn() };

  it("shows the empty state", () => {
    render(createElement(QueueView, { ...base, items: [], total: 0 }));
    expect(screen.getByText("Quarantine is empty.")).toBeTruthy();
  });

  it("selects rows and cards and loads more", () => {
    const onSelect = vi.fn();
    const onLoadMore = vi.fn();
    const first = item("q_1", { writer_id: "w1", postpone_count: 2 });
    render(createElement(QueueView, {
      ...base, items: [first, item("q_2")], total: 5, selectedId: "q_1", onSelect, onLoadMore,
    }));
    expect(screen.getByTestId("card-q_1").textContent).toContain("w1 - postponed x2");
    fireEvent.click(screen.getByTestId("row-q_2"));
    fireEvent.click(screen.getByTestId("card-q_1"));
    expect(onSelect.mock.calls.map(([selected]) => (selected as QuarantineItemSummary).quarantine_id))
      .toEqual(["q_2", "q_1"]);
    fireEvent.click(screen.getByText("Load more (3 remaining)"));
    expect(onLoadMore).toHaveBeenCalledOnce();
  });

  it("disables load more while loading", () => {
    render(createElement(QueueView, { ...base, items: [item("q_1")], total: 2, loadingMore: true }));
    expect(screen.getByTestId<HTMLButtonElement>("load-more").disabled).toBe(true);
    expect(screen.getByText("Loading...")).toBeTruthy();
  });
});

describe("ConnectScreen", () => {
  it("reports a reachable router and submits trimmed tokens", async () => {
    const onConnect = vi.fn();
    render(createElement(ConnectScreen, { onConnect }));
    expect(await screen.findByText("router reachable")).toBeTruthy();
    fireEvent.submit(screen.getByText("Connect").closest("form") as HTMLFormElement);
    expect(onConnect).not.toHaveBeenCalled();
    fireEvent.change(screen.getByPlaceholderText("MEMORY_ROUTER_ADMIN_READ_TOKEN"), { target: { value: " r " } });
    fireEvent.change(screen.getByPlaceholderText("MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"), { target: { value: " rv " } });
    fireEvent.change(screen.getByPlaceholderText("MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN"), { target: { value: " c " } });
    fireEvent.click(screen.getByText("Connect"));
    expect(onConnect).toHaveBeenCalledWith(TOKENS);
  });

  it("reports an unreachable router and hides branding when embedded", async () => {
    vi.mocked(api.fetchLiveness).mockRejectedValue(new Error("down"));
    render(createElement(ConnectScreen, { onConnect: vi.fn(), embed: true }));
    expect(await screen.findByText("router not reachable on this origin")).toBeTruthy();
    expect(screen.queryByText("Memory Router")).toBeNull();
  });
});

describe("CleanupPanel", () => {
  const preview: CleanupResponse = { dry_run: true, count: 2, encrypted_bytes: 1024 };

  it("previews the selected filters, then executes with the previewed count", async () => {
    vi.mocked(api.runCleanup)
      .mockResolvedValueOnce(preview)
      .mockResolvedValueOnce({ dry_run: false, count: 2, encrypted_bytes: 1024 });
    const onDone = vi.fn();
    render(createElement(CleanupPanel, { tokens: TOKENS, onDone, onUnauthorized: vi.fn() }));
    fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Older than"), { target: { value: "2026-01-01T00:00" } });
    fireEvent.click(screen.getByLabelText("unknown_writer"));
    fireEvent.click(screen.getByLabelText("denied_endpoint"));
    fireEvent.click(screen.getByLabelText("denied_endpoint"));
    fireEvent.click(screen.getByTestId("cleanup-preview-run"));
    expect((await screen.findByTestId("cleanup-preview")).textContent).toContain("2 items");
    expect(api.runCleanup).toHaveBeenLastCalledWith(TOKENS, {
      scope: "all",
      reasons: ["unknown_writer"],
      older_than: new Date("2026-01-01T00:00").toISOString(),
      dry_run: true,
    });
    fireEvent.click(screen.getByTestId("cleanup-execute"));
    await waitFor(() => expect(onDone).toHaveBeenCalledWith("cleanup removed 2 items (1.0 KiB)"));
    expect(api.runCleanup).toHaveBeenLastCalledWith(TOKENS, expect.objectContaining({
      dry_run: false, expected_count: 2,
    }));
    expect(screen.queryByTestId("cleanup-preview")).toBeNull();
  });

  it("requires a cleanup token", () => {
    render(createElement(CleanupPanel, {
      tokens: { ...TOKENS, cleanup: "" }, onDone: vi.fn(), onUnauthorized: vi.fn(),
    }));
    const button = screen.getByTestId<HTMLButtonElement>("cleanup-preview-run");
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("cleanup token required");
  });

  it("drops a stale preview on 409 and signs out a host session on 401", async () => {
    vi.mocked(api.runCleanup)
      .mockResolvedValueOnce(preview)
      .mockRejectedValueOnce(new api.ApiError(409, "conflict", "selection changed"))
      .mockRejectedValueOnce(UNAUTHORIZED);
    const onUnauthorized = vi.fn();
    render(createElement(CleanupPanel, { tokens: "host", onDone: vi.fn(), onUnauthorized }));
    fireEvent.click(screen.getByTestId("cleanup-preview-run"));
    await screen.findByTestId("cleanup-preview");
    fireEvent.click(screen.getByTestId("cleanup-execute"));
    expect(await screen.findByText("conflict: selection changed")).toBeTruthy();
    expect(screen.queryByTestId("cleanup-preview")).toBeNull();
    fireEvent.click(screen.getByTestId("cleanup-preview-run"));
    expect(await screen.findByText("unauthorized: expired")).toBeTruthy();
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("reports unexpected failures generically", async () => {
    vi.mocked(api.runCleanup).mockRejectedValue(new Error("network"));
    render(createElement(CleanupPanel, { tokens: TOKENS, onDone: vi.fn(), onUnauthorized: vi.fn() }));
    fireEvent.click(screen.getByTestId("cleanup-preview-run"));
    expect(await screen.findByText("cleanup failed")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("dismiss"));
    expect(screen.queryByText("cleanup failed")).toBeNull();
  });
});

describe("App", () => {
  it("shows invalid host configuration", () => {
    host[CONFIG_KEY] = { auth: "bogus" };
    render(createElement(App));
    expect(screen.getByRole("alert").textContent).toContain("auth must be token or host");
  });

  it("connects with tokens, loads the queue, and disconnects", async () => {
    render(createElement(App));
    fireEvent.change(screen.getByPlaceholderText("MEMORY_ROUTER_ADMIN_READ_TOKEN"), { target: { value: "r" } });
    fireEvent.click(screen.getByText("Connect"));
    expect(await screen.findByTestId("row-q_1")).toBeTruthy();
    expect(screen.getByTestId("stats")).toBeTruthy();
    expect(sessionStorage.length).toBe(1);
    expect(screen.getByText(/Tokens in sessionStorage only/)).toBeTruthy();
    fireEvent.click(screen.getByText("Disconnect"));
    expect(screen.getByText("Connect")).toBeTruthy();
    expect(sessionStorage.length).toBe(0);
  });

  it("resumes a saved token session and explains a 401", async () => {
    sessionStorage.setItem("mr-admin-tokens", JSON.stringify(TOKENS));
    vi.mocked(api.listQueue).mockRejectedValue(UNAUTHORIZED);
    render(createElement(App));
    expect(await screen.findByText("401 unauthorized - check the read token and its scope")).toBeTruthy();
  });

  it("reports other refresh failures and refreshes on demand", async () => {
    sessionStorage.setItem("mr-admin-tokens", JSON.stringify(TOKENS));
    vi.mocked(api.listQueue).mockRejectedValueOnce(new api.ApiError(500, "internal", "boom"));
    render(createElement(App));
    expect(await screen.findByText("internal: boom")).toBeTruthy();
    vi.mocked(api.listQueue).mockRejectedValueOnce(new Error("network"));
    fireEvent.click(screen.getByTestId("refresh"));
    expect(await screen.findByText("refresh failed")).toBeTruthy();
    fireEvent.click(screen.getByTestId("refresh"));
    expect(await screen.findByTestId("row-q_1")).toBeTruthy();
    expect(screen.queryByText("refresh failed")).toBeNull();
  });

  it("uses host auth with theme, embed chrome, and host 401 expiry", async () => {
    host[CONFIG_KEY] = { auth: "host", theme: { accent: "#123456" }, chrome: { embed: true } };
    vi.mocked(api.listQueue).mockRejectedValue(UNAUTHORIZED);
    render(createElement(App));
    expect(await screen.findByText("401 unauthorized - sign in through the host, then refresh")).toBeTruthy();
    expect(document.documentElement.style.getPropertyValue("--mr-accent")).toBe("#123456");
    expect(screen.queryByText("Disconnect")).toBeNull();
    expect(screen.getByText(/Authentication is managed by the host/)).toBeTruthy();
    expect(screen.queryByText(/- Quarantine$/)).toBeNull();
  });

  it("toggles cleanup, selects items, and pages through the queue", async () => {
    sessionStorage.setItem("mr-admin-tokens", JSON.stringify(TOKENS));
    vi.mocked(api.listQueue)
      .mockResolvedValueOnce(queue([item("q_1")], 3))
      .mockResolvedValueOnce(queue([item("q_1"), item("q_2")], 3))
      .mockRejectedValueOnce(new Error("network"))
      .mockRejectedValueOnce(new api.ApiError(503, "unavailable", "busy"));
    render(createElement(App));
    expect(await screen.findByText("Memory Router - Quarantine")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cleanup" }));
    expect(screen.getByTestId("cleanup")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cleanup" }));
    expect(screen.queryByTestId("cleanup")).toBeNull();

    fireEvent.click(await screen.findByTestId("row-q_1"));
    expect(await screen.findByTestId("item-detail")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("close detail"));
    expect(screen.queryByTestId("item-detail")).toBeNull();
    fireEvent.click(screen.getByTestId("row-q_1"));
    fireEvent.click(screen.getByTestId("row-q_1"));
    expect(screen.queryByTestId("item-detail")).toBeNull();

    fireEvent.click(screen.getByTestId("load-more"));
    expect(await screen.findByTestId("row-q_2")).toBeTruthy();
    fireEvent.click(screen.getByTestId("load-more"));
    expect(await screen.findByText("load more failed")).toBeTruthy();
    fireEvent.click(screen.getByTestId("load-more"));
    expect(await screen.findByText("unavailable: busy")).toBeTruthy();
  });

  it("expires a host session on a 401 while loading more", async () => {
    host[CONFIG_KEY] = { auth: "host" };
    vi.mocked(api.listQueue)
      .mockResolvedValueOnce(queue([item("q_1")], 2))
      .mockRejectedValueOnce(UNAUTHORIZED);
    render(createElement(App));
    fireEvent.click(await screen.findByTestId("load-more"));
    expect(await screen.findByText("401 unauthorized - sign in through the host, then refresh")).toBeTruthy();
    expect(screen.queryByTestId("row-q_1")).toBeNull();
  });

  it("ignores host results that arrive after the session expired", async () => {
    host[CONFIG_KEY] = { auth: "host" };
    const first = deferred<QuarantineQueueResponse>();
    const second = deferred<QuarantineQueueResponse>();
    vi.mocked(api.listQueue)
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce(queue([item("q_1")], 2))
      .mockReturnValueOnce(second.promise);
    vi.mocked(api.fetchStats).mockRejectedValueOnce(UNAUTHORIZED).mockResolvedValue(STATS);
    render(createElement(App));
    expect(await screen.findByText("401 unauthorized - sign in through the host, then refresh")).toBeTruthy();
    first.resolve(queue([item("q_stale")]));
    fireEvent.click(screen.getByTestId("refresh"));
    fireEvent.click(await screen.findByTestId("load-more"));
    vi.mocked(api.fetchStats).mockRejectedValueOnce(UNAUTHORIZED);
    fireEvent.click(screen.getByTestId("refresh"));
    await screen.findByText("401 unauthorized - sign in through the host, then refresh");
    second.reject(new Error("late"));
    second.resolve(queue([item("q_late")]));
    await Promise.resolve();
    expect(screen.queryByTestId("row-q_stale")).toBeNull();
    expect(screen.queryByTestId("row-q_late")).toBeNull();
    expect(screen.queryByText("load more failed")).toBeNull();
  });

  it("shows a notice after cleanup and refreshes the queue", async () => {
    sessionStorage.setItem("mr-admin-tokens", JSON.stringify(TOKENS));
    vi.mocked(api.runCleanup)
      .mockResolvedValueOnce({ dry_run: true, count: 1, encrypted_bytes: 10 })
      .mockResolvedValueOnce({ dry_run: false, count: 1, encrypted_bytes: 10 });
    render(createElement(App));
    await screen.findByTestId("row-q_1");
    fireEvent.click(screen.getByRole("button", { name: "Cleanup" }));
    fireEvent.click(screen.getByTestId("cleanup-preview-run"));
    fireEvent.click(await screen.findByTestId("cleanup-execute"));
    expect(await screen.findByText("cleanup removed 1 items (10 B)")).toBeTruthy();
    expect(api.listQueue).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByLabelText("dismiss"));
    expect(screen.queryByText("cleanup removed 1 items (10 B)")).toBeNull();
  });
});
