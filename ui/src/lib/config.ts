// Host-injected runtime configuration. Without it the UI is same-origin with
// the router admin API (the nginx proxy deployment). A host embedding the
// published package may set window.__MEMORY_ROUTER_UI_CONFIG__ before the app
// script loads to point the UI at a different router origin and to override
// the product name. Configuration is read-only and never persisted.

export const CONFIG_KEY = "__MEMORY_ROUTER_UI_CONFIG__";

export const DEFAULT_PRODUCT_NAME = "Memory Router";

export interface UiTheme {
  accent?: string;
  background?: string;
  foreground?: string;
}

export interface UiChrome {
  header?: boolean;
  branding?: boolean;
}

export interface UiConfig {
  baseUrl?: string;
  productName?: string;
  theme?: UiTheme;
  chrome?: UiChrome;
}

export interface ResolvedUiConfig {
  // Empty means same-origin; otherwise an absolute http(s) origin plus
  // optional path prefix, without a trailing slash.
  baseUrl: string;
  productName: string;
  // CSS variable overrides, hex colors only (CSP-safe, no url()/expression).
  theme: UiTheme;
  chrome: Required<UiChrome>;
}

// Theme keys map 1:1 onto the CSS variables declared in index.css.
export const THEME_VARS: Record<keyof UiTheme, string> = {
  accent: "--mr-accent",
  background: "--mr-bg",
  foreground: "--mr-fg",
};

const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

declare global {
  var __MEMORY_ROUTER_UI_CONFIG__: UiConfig | undefined;
}

export class ConfigError extends Error {}

function resolveTheme(raw: unknown): UiTheme {
  if (raw === undefined) return {};
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${CONFIG_KEY}.theme must be an object of color overrides`);
  }
  const theme: UiTheme = {};
  for (const [key, value] of Object.entries(raw)) {
    // Own keys only: `in` would also accept Object.prototype members such as
    // "constructor" or "toString" as theme overrides.
    if (!Object.hasOwn(THEME_VARS, key)) {
      throw new ConfigError(`${CONFIG_KEY}.theme.${key} is not a supported override`);
    }
    if (typeof value !== "string" || !HEX_COLOR_RE.test(value)) {
      throw new ConfigError(`${CONFIG_KEY}.theme.${key} must be a hex color`);
    }
    theme[key as keyof UiTheme] = value;
  }
  return theme;
}

function resolveChrome(raw: unknown): Required<UiChrome> {
  const chrome: Required<UiChrome> = { header: true, branding: true };
  if (raw === undefined) return chrome;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${CONFIG_KEY}.chrome must be an object of boolean flags`);
  }
  for (const [key, value] of Object.entries(raw)) {
    if (key !== "header" && key !== "branding") {
      throw new ConfigError(`${CONFIG_KEY}.chrome.${key} is not a supported flag`);
    }
    if (typeof value !== "boolean") {
      throw new ConfigError(`${CONFIG_KEY}.chrome.${key} must be a boolean`);
    }
    chrome[key] = value;
  }
  return chrome;
}

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
  if (raw === undefined) {
    return { baseUrl: "", productName: DEFAULT_PRODUCT_NAME, theme: {}, chrome: { header: true, branding: true } };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${CONFIG_KEY} must be an object`);
  }
  const config = raw as Record<string, unknown>;
  for (const key of Object.keys(config)) {
    if (!["baseUrl", "productName", "theme", "chrome"].includes(key)) {
      throw new ConfigError(`${CONFIG_KEY}.${key} is not a supported option`);
    }
  }
  return {
    baseUrl: resolveBaseUrl(config["baseUrl"]),
    productName: resolveProductName(config["productName"]),
    theme: resolveTheme(config["theme"]),
    chrome: resolveChrome(config["chrome"]),
  };
}

export function apiUrl(path: string): string {
  return `${resolveUiConfig().baseUrl}${path}`;
}
