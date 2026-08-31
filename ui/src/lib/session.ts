// Tokens live in sessionStorage only: they survive a tab reload but die with
// the tab. Nothing is ever written to localStorage or cookies.

import type { AdminTokens } from "./api";

const KEY = "mr-admin-tokens";

export function loadTokens(): AdminTokens | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<AdminTokens>;
    if (typeof parsed.read !== "string") return null;
    return {
      read: parsed.read,
      review: typeof parsed.review === "string" ? parsed.review : "",
      cleanup: typeof parsed.cleanup === "string" ? parsed.cleanup : "",
    };
  } catch {
    return null;
  }
}

export function saveTokens(tokens: AdminTokens): void {
  sessionStorage.setItem(KEY, JSON.stringify(tokens));
}

export function clearTokens(): void {
  sessionStorage.removeItem(KEY);
}
