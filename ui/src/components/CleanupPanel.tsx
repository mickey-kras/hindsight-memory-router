import { useState } from "react";
import { ApiError, runCleanup, type AdminTokens } from "../lib/api";
import type { CleanupResponse, ReviewReason } from "../lib/types";
import { formatBytes } from "../lib/format";
import { Banner } from "./Banner";

const REASONS: ReviewReason[] = [
  "unknown_writer",
  "suspicious_content",
  "suspicious_query",
  "recalled_suspicious_memory",
  "denied_endpoint",
  "auth_failed",
];

interface Props {
  tokens: AdminTokens;
  onDone: (message: string) => void;
}

export function CleanupPanel({ tokens, onDone }: Props) {
  const [scope, setScope] = useState<"pending" | "all">("pending");
  const [reasons, setReasons] = useState<ReviewReason[]>([]);
  const [olderThan, setOlderThan] = useState("");
  const [preview, setPreview] = useState<CleanupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const toggleReason = (reason: ReviewReason) => {
    setReasons((current) =>
      current.includes(reason) ? current.filter((r) => r !== reason) : [...current, reason],
    );
    setPreview(null);
  };

  const body = () => ({
    scope,
    ...(reasons.length > 0 ? { reasons } : {}),
    ...(olderThan ? { older_than: new Date(olderThan).toISOString() } : {}),
  });

  const run = async (dryRun: boolean) => {
    setBusy(true);
    setError(null);
    try {
      if (dryRun) {
        setPreview(await runCleanup(tokens, { ...body(), dry_run: true }));
      } else {
        if (!preview) throw new Error("run a preview first");
        const result = await runCleanup(tokens, {
          ...body(),
          dry_run: false,
          expected_count: preview.count,
        });
        setPreview(null);
        onDone(`cleanup removed ${result.count} items (${formatBytes(result.encrypted_bytes)})`);
      }
    } catch (err) {
      if (!dryRun && err instanceof ApiError && err.status === 409) setPreview(null);
      setError(err instanceof ApiError ? `${err.code}: ${err.message}` : "cleanup failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section data-testid="cleanup" className="flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <h2 className="text-sm font-semibold text-zinc-200">Cleanup</h2>

      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2 text-zinc-300">
          Scope
          <select
            disabled={busy}
            value={scope}
            onChange={(e) => {
              setScope(e.target.value as "pending" | "all");
              setPreview(null);
            }}
            className="rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm outline-none focus:border-sky-500"
          >
            <option value="pending">pending</option>
            <option value="all">all</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-zinc-300">
          Older than
          <input
            disabled={busy}
            type="datetime-local"
            value={olderThan}
            onChange={(e) => {
              setOlderThan(e.target.value);
              setPreview(null);
            }}
            className="rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm outline-none focus:border-sky-500 [color-scheme:dark]"
          />
        </label>
      </div>

      <div className="flex flex-wrap gap-2">
        {REASONS.map((reason) => (
          <label
            key={reason}
            className={`cursor-pointer rounded-md border px-2 py-1 text-xs transition ${
              reasons.includes(reason)
                ? "border-sky-500/50 bg-sky-500/15 text-sky-200"
                : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            <input
              disabled={busy}
              type="checkbox"
              className="sr-only"
              checked={reasons.includes(reason)}
              onChange={() => toggleReason(reason)}
            />
            {reason}
          </label>
        ))}
      </div>

      {error && <Banner kind="error" text={error} onDismiss={() => setError(null)} />}

      {preview && (
        <div data-testid="cleanup-preview" className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
          Preview: {preview.count} items, {formatBytes(preview.encrypted_bytes)} would be removed.
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={() => void run(true)}
          disabled={busy || !tokens.cleanup}
          data-testid="cleanup-preview-run"
          title={!tokens.cleanup ? "cleanup token required" : ""}
          className="rounded-lg border border-zinc-600 px-4 py-2 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
        >
          Preview
        </button>
        <button
          onClick={() => void run(false)}
          disabled={busy || !preview || preview.count === 0}
          data-testid="cleanup-execute"
          className="rounded-lg bg-red-600/80 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-40"
        >
          {busy ? "working..." : "Execute"}
        </button>
      </div>
      <p className="text-xs text-zinc-500">
        Execution replays the preview count; the router rejects with 409 if the selection changed.
        Reviewed items are decision state and are never purged.
      </p>
    </section>
  );
}
