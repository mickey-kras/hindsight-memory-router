// Host-injected runtime configuration. Without it the UI is same-origin with
// the router admin API (the nginx proxy deployment). A host embedding the
// published package may set window.__MEMORY_ROUTER_UI_CONFIG__ before the app
// script loads to point the UI at a different router origin and to override
// the product name. Configuration is read-only and never persisted.

export const CONFIG_KEY = "__MEMORY_ROUTER_UI_CONFIG__";

export const DEFAULT_PRODUCT_NAME = "Memory Router";

export interface UiConfig {
  baseUrl?: string;
  productName?: string;
}

export interface ResolvedUiConfig {
  // Empty means same-origin; otherwise an absolute http(s) origin plus
  // optional path prefix, without a trailing slash.
  baseUrl: string;
  productName: string;
}

declare global {
  var __MEMORY_ROUTER_UI_CONFIG__: UiConfig | undefined;
}

export class ConfigError extends Error {}

function resolveBaseUrl(raw: unknown): string {
  if (raw === undefined) return "";
  if (typeof raw !== "string" || raw === "") {
    throw new ConfigError(`${CONFIG_KEY}.baseUrl must be an absolute http(s) URL`);
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`${CONFIG_KEY}.baseUrl must be an absolute http(s) URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ConfigError(`${CONFIG_KEY}.baseUrl must use http(s)`);
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new ConfigError(`${CONFIG_KEY}.baseUrl must not carry credentials, query, or fragment`);
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

function resolveProductName(raw: unknown): string {
  if (raw === undefined) return DEFAULT_PRODUCT_NAME;
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new ConfigError(`${CONFIG_KEY}.productName must be a non-empty string`);
  }
  return raw;
}

export function resolveUiConfig(): ResolvedUiConfig {
  const raw: unknown = globalThis[CONFIG_KEY];
  if (raw === undefined) return { baseUrl: "", productName: DEFAULT_PRODUCT_NAME };
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${CONFIG_KEY} must be an object`);
  }
  const config = raw as Record<string, unknown>;
  for (const key of Object.keys(config)) {
    if (key !== "baseUrl" && key !== "productName") {
      throw new ConfigError(`${CONFIG_KEY}.${key} is not a supported option`);
    }
  }
  return {
    baseUrl: resolveBaseUrl(config["baseUrl"]),
    productName: resolveProductName(config["productName"]),
  };
}

export function apiUrl(path: string): string {
  return `${resolveUiConfig().baseUrl}${path}`;
}
