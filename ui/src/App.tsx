import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  fetchStats,
  listQueue,
  type AdminTokens,
} from "./lib/api";
import { clearTokens, loadTokens, saveTokens } from "./lib/session";
import type { QuarantineItemSummary, QuarantineStats } from "./lib/types";
import { ConnectScreen } from "./components/ConnectScreen";
import { StatsBar } from "./components/StatsBar";
import { QueueView } from "./components/QueueView";
import { ItemDetail } from "./components/ItemDetail";
import { CleanupPanel } from "./components/CleanupPanel";
import { Banner } from "./components/Banner";

const QUEUE_PAGE_SIZE = 100;

export default function App() {
  const [tokens, setTokens] = useState<AdminTokens | null>(() => loadTokens());
  const [stats, setStats] = useState<QuarantineStats | null>(null);
  const [items, setItems] = useState<QuarantineItemSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<QuarantineItemSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [showCleanup, setShowCleanup] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  const refresh = useCallback(async () => {
    if (!tokens) return;
    setLoading(true);
    setError(null);
    try {
      const [queue, nextStats] = await Promise.all([
        listQueue(tokens, QUEUE_PAGE_SIZE),
        fetchStats(tokens),
      ]);
      setItems(queue.items);
      setTotal(queue.total);
      setStats(nextStats);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("401 unauthorized - check the read token and its scope");
      } else {
        setError(err instanceof ApiError ? `${err.code}: ${err.message}` : "refresh failed");
      }
    } finally {
      setLoading(false);
    }
  }, [tokens]);

  const loadMore = useCallback(async () => {
    if (!tokens || loadingMore || items.length >= total) return;
    setLoadingMore(true);
    setError(null);
    try {
      const queue = await listQueue(tokens, QUEUE_PAGE_SIZE, items.length);
      setItems((current) => [...current, ...queue.items]);
      setTotal(queue.total);
    } catch (err) {
      setError(err instanceof ApiError ? `${err.code}: ${err.message}` : "load more failed");
    } finally {
      setLoadingMore(false);
    }
  }, [items.length, loadingMore, tokens, total]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const connect = (next: AdminTokens) => {
    saveTokens(next);
    setTokens(next);
  };

  const disconnect = () => {
    clearTokens();
    setTokens(null);
    setSelected(null);
    setStats(null);
    setItems([]);
  };

  const onAction = (message: string) => {
    setNotice(message);
    setSelected(null);
    void refresh();
  };

  if (!tokens) return <ConnectScreen onConnect={connect} />;

  return (
    <div className="mx-auto flex min-h-dvh max-w-6xl flex-col gap-4 px-3 py-4 sm:px-5 sm:py-6">
      <header className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-emerald-400" />
          <h1 className="text-base font-semibold tracking-tight">Memory Router - Quarantine</h1>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => setShowCleanup((v) => !v)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
              showCleanup
                ? "border-sky-500/50 bg-sky-500/15 text-sky-200"
                : "border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            }`}
          >
            Cleanup
          </button>
          <button
            onClick={() => void refresh()}
            disabled={loading}
            data-testid="refresh"
            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
          >
            {loading ? "loading..." : "Refresh"}
          </button>
          <button
            onClick={disconnect}
            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-800"
          >
            Disconnect
          </button>
        </div>
      </header>

      {error && <Banner kind="error" text={error} onDismiss={() => setError(null)} />}
      {notice && <Banner kind="ok" text={notice} onDismiss={() => setNotice(null)} />}

      {stats && <StatsBar stats={stats} />}

      {showCleanup && <CleanupPanel tokens={tokens} onDone={onAction} />}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <QueueView
          items={items}
          total={total}
          selectedId={selected?.quarantine_id ?? null}
          loadingMore={loadingMore}
          onLoadMore={() => void loadMore()}
          onSelect={(item) =>
            setSelected((current) =>
              current?.quarantine_id === item.quarantine_id ? null : item,
            )
          }
        />
        {selected && (
          <ItemDetail
            item={selected}
            tokens={tokens}
            onAction={onAction}
            onClose={() => setSelected(null)}
          />
        )}
      </div>

      <footer className="mt-auto pt-4 text-center text-[11px] text-zinc-600">
        Tokens in sessionStorage only. Decryption is local (WebCrypto); the router never sees the
        decryption key.
      </footer>
    </div>
  );
}
