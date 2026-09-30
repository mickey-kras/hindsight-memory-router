import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CONFIG_KEY, ConfigError, resolveUiConfig } from "../../src/lib/config";
import { fetchStats, rejectItem, runCleanup, type AdminTokens } from "../../src/lib/api";

const globalConfig = globalThis as Record<string, unknown>;
const staleTokens: AdminTokens = { read: "stale-read", review: "stale-review", cleanup: "stale-cleanup" };

beforeEach(() => {
  vi.stubGlobal("location", new URL("https://console.example/"));
  globalConfig[CONFIG_KEY] = { auth: "host" };
});
afterEach(() => {
  delete globalConfig[CONFIG_KEY];
  vi.unstubAllGlobals();
});

describe("host authentication boundary", () => {
  it("accepts same-origin prefixes and embed mode", () => {
    globalConfig[CONFIG_KEY] = { auth: "host", baseUrl: "https://console.example/proxy/", chrome: { embed: true } };
    expect(resolveUiConfig()).toMatchObject({ auth: "host", baseUrl: "https://console.example/proxy", chrome: { embed: true } });
  });

  it.each([
    { auth: "cookie" }, { auth: null }, { auth: false },
    { auth: "host", baseUrl: "https://other.example" },
    { auth: "host", baseUrl: "http://console.example" },
    { auth: "host", baseUrl: "https://console.example:444" },
    { auth: "host", chrome: { embed: "true" } },
  ])("rejects invalid configuration before sending requests: %j", async (config) => {
    globalConfig[CONFIG_KEY] = config;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(() => resolveUiConfig()).toThrow(ConfigError);
    await expect(fetchStats(staleTokens)).rejects.toThrow(ConfigError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("omits all supplied tokens and restricts transport for every scope", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}"));
    vi.stubGlobal("fetch", fetchMock);
    for (const operation of [() => fetchStats(staleTokens), () => rejectItem(staleTokens, "q_test"), () => runCleanup(staleTokens, { scope: "pending", dry_run: true })]) {
      fetchMock.mockResolvedValueOnce(new Response("{}"));
      await operation();
    }
    expect(fetchMock).toHaveBeenCalledTimes(3);
    for (const call of fetchMock.mock.calls) {
      const init = call[1] as RequestInit;
      expect(new Headers(init.headers).has("authorization")).toBe(false);
      expect(init).toMatchObject({ credentials: "same-origin", mode: "same-origin", redirect: "error" });
      expect(JSON.stringify(init)).not.toContain("stale-");
    }
  });

  it.each([401, 403])("does not retry or fall back after HTTP %i", async (status) => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(fetchStats(staleTokens)).rejects.toMatchObject({ status });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("preserves scoped token mode and rejects a host session in token mode", async () => {
    delete globalConfig[CONFIG_KEY];
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}"));
    vi.stubGlobal("fetch", fetchMock);
    await rejectItem(staleTokens, "q_test");
    expect(new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers).get("authorization")).toBe("Bearer stale-review");
    await expect(fetchStats("host")).rejects.toMatchObject({ code: "token_missing" });
  });
});
