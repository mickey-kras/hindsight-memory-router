import type { QuarantineKind, QuarantineStatus, ReviewReason } from "./types";

export function formatBytes(value: number | undefined): string {
  if (value === undefined) return "-";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
}

export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export const REASON_STYLE: Record<ReviewReason, string> = {
  unknown_writer: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  suspicious_content: "bg-red-500/15 text-red-300 border-red-500/30",
  suspicious_query: "bg-red-500/15 text-red-300 border-red-500/30",
  recalled_suspicious_memory: "bg-red-500/15 text-red-300 border-red-500/30",
  denied_endpoint: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  auth_failed: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
};

export const STATUS_STYLE: Record<QuarantineStatus, string> = {
  pending: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  postponed: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  reviewed_allowed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  reviewed_blocked: "bg-red-500/15 text-red-300 border-red-500/30",
};

export const KIND_LABEL: Record<QuarantineKind, string> = {
  retain_request: "retain",
  recall_request: "recall",
  recalled_memory: "recalled memory",
  security_event: "security event",
};
