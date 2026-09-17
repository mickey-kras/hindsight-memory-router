// Host configuration contract: same-origin by default, injected base URL is
// opt-in, and anything malformed fails closed before any request is made.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  apiUrl,
  CONFIG_KEY,
  ConfigError,
  DEFAULT_PRODUCT_NAME,
  resolveUiConfig,
  THEME_VARS,
} from "../../src/lib/config";
import { fetchVersion, type AdminTokens } from "../../src/lib/api";

const host = globalThis as Record<string, unknown>;

afterEach(() => {
  delete host[CONFIG_KEY];
  vi.unstubAllGlobals();
});

describe("resolveUiConfig", () => {
  it("defaults to same-origin when the host injects nothing", () => {
    expect(resolveUiConfig()).toEqual({
      baseUrl: "",
      productName: DEFAULT_PRODUCT_NAME,
      theme: {},
      chrome: { header: true, branding: true },
    });
    expect(apiUrl("/admin/quarantine/queue")).toBe("/admin/quarantine/queue");
  });

  it("accepts an absolute https base URL and strips trailing slashes", () => {
    host[CONFIG_KEY] = { baseUrl: "https://router.example.com/hmr/" };
    expect(resolveUiConfig().baseUrl).toBe("https://router.example.com/hmr");
    expect(apiUrl("/version")).toBe("https://router.example.com/hmr/version");
  });

  it("accepts a base URL without a path prefix", () => {
    host[CONFIG_KEY] = { baseUrl: "http://127.0.0.1:8890" };
    expect(resolveUiConfig().baseUrl).toBe("http://127.0.0.1:8890");
  });

  it("overrides the product name only when it is a non-empty string", () => {
    host[CONFIG_KEY] = { productName: "Acme Memory" };
    expect(resolveUiConfig().productName).toBe("Acme Memory");
  });

  it("accepts hex theme overrides and maps them to theme slots", () => {
    host[CONFIG_KEY] = { theme: { accent: "#38bdf8", background: "#09090b", foreground: "#f4f4f5" } };
    expect(resolveUiConfig().theme).toEqual({
      accent: "#38bdf8",
      background: "#09090b",
      foreground: "#f4f4f5",
    });
  });

  it("maps every theme slot onto a documented CSS variable", () => {
    expect(THEME_VARS).toEqual({
      accent: "--mr-accent",
      background: "--mr-bg",
      foreground: "--mr-fg",
    });
  });

  it("defaults chrome flags to visible and accepts boolean overrides", () => {
    expect(resolveUiConfig().chrome).toEqual({ header: true, branding: true });
    host[CONFIG_KEY] = { chrome: { header: false, branding: false } };
    expect(resolveUiConfig().chrome).toEqual({ header: false, branding: false });
    host[CONFIG_KEY] = { chrome: { branding: false } };
    expect(resolveUiConfig().chrome).toEqual({ header: true, branding: false });
  });

  it.each([
    ["a relative base URL", { baseUrl: "/proxy" }],
    ["a protocol-relative base URL", { baseUrl: "//router.example.com" }],
    ["a non-http base URL", { baseUrl: "ftp://router.example.com" }],
    ["a base URL with credentials", { baseUrl: "https://user:pass@router.example.com" }],
    ["a base URL with a query", { baseUrl: "https://router.example.com/?x=1" }],
    ["a base URL with a fragment", { baseUrl: "https://router.example.com/#frag" }],
    ["an empty base URL", { baseUrl: "" }],
    ["a non-string base URL", { baseUrl: 42 }],
    ["an empty product name", { productName: "  " }],
    ["an unknown option", { favicon: "https://x.example/i.ico" }],
    ["a non-object config", "https://router.example.com"],
    ["a non-object theme", { theme: "dark" }],
    ["an unknown theme key", { theme: { linkColor: "#fff" } }],
    ["a non-hex theme color", { theme: { accent: "url(https://evil.example)" } }],
    ["a named theme color", { theme: { accent: "red" } }],
    ["a non-string theme color", { theme: { accent: 123 } }],
    ["a non-object chrome", { chrome: true }],
    ["an unknown chrome flag", { chrome: { footer: true } }],
    ["a non-boolean chrome flag", { chrome: { header: "false" } }],
  ])("fails closed on %s", (_label, injected) => {
    host[CONFIG_KEY] = injected;
    expect(() => resolveUiConfig()).toThrow(ConfigError);
    expect(() => apiUrl("/version")).toThrow(ConfigError);
  });
});

describe("api client base URL", () => {
  const tokens: AdminTokens = { read: "r", review: "", cleanup: "" };

  it("requests the injected origin instead of same-origin", async () => {
    host[CONFIG_KEY] = { baseUrl: "https://router.example.com" };
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        calls.push(String(input));
        return new Response(JSON.stringify({ version: "0.9.0" }), { status: 200 });
      }),
    );
    await fetchVersion();
    expect(calls).toEqual(["https://router.example.com/version"]);
  });

  it("keeps same-origin requests when nothing is injected", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        calls.push(String(input));
        return new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 });
      }),
    );
    const { listQueue } = await import("../../src/lib/api");
    await listQueue(tokens);
    expect(calls).toEqual(["/admin/quarantine/queue?limit=100&offset=0"]);
  });
});
