import { useEffect, useState } from "react";
import { fetchVersion, type AdminTokens } from "../lib/api";

interface Props {
  onConnect: (tokens: AdminTokens) => void;
}

export function ConnectScreen({ onConnect }: Props) {
  const [read, setRead] = useState("");
  const [review, setReview] = useState("");
  const [cleanup, setCleanup] = useState("");
  const [version, setVersion] = useState<string | null>(null);
  const [probeFailed, setProbeFailed] = useState(false);

  useEffect(() => {
    fetchVersion()
      .then((body) => setVersion(typeof body.version === "string" ? body.version : "unknown"))
      .catch(() => setProbeFailed(true));
  }, []);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!read.trim()) return;
    onConnect({ read: read.trim(), review: review.trim(), cleanup: cleanup.trim() });
  };

  return (
    <div className="mx-auto flex min-h-dvh max-w-md flex-col justify-center px-4 py-10">
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-6 shadow-xl">
        <div className="mb-1 flex items-center gap-2">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-emerald-400" />
          <h1 className="text-lg font-semibold tracking-tight">Memory Router</h1>
        </div>
        <p className="mb-5 text-sm text-zinc-400">
          Quarantine review console. Tokens stay in this tab (sessionStorage), never in
          localStorage or cookies.
        </p>

        <div className="mb-5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs">
          {version !== null && (
            <span className="text-emerald-300">
              router reachable, API <span className="mono">{version}</span>
            </span>
          )}
          {probeFailed && <span className="text-amber-300">router not reachable on this origin</span>}
          {version === null && !probeFailed && <span className="text-zinc-500">probing router...</span>}
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-zinc-300">
              Read token <span className="text-red-400">*</span>
            </span>
            <input
              type="password"
              required
              autoComplete="off"
              value={read}
              onChange={(e) => setRead(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-sm outline-none focus:border-sky-500"
              placeholder="MEMORY_ROUTER_ADMIN_READ_TOKEN"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-zinc-300">Review token (approve / reject / postpone)</span>
            <input
              type="password"
              autoComplete="off"
              value={review}
              onChange={(e) => setReview(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-sm outline-none focus:border-sky-500"
              placeholder="MEMORY_ROUTER_ADMIN_REVIEW_TOKEN"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-zinc-300">Cleanup token</span>
            <input
              type="password"
              autoComplete="off"
              value={cleanup}
              onChange={(e) => setCleanup(e.target.value)}
              className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-sm outline-none focus:border-sky-500"
              placeholder="MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN"
            />
          </label>
          <button
            type="submit"
            className="mt-2 rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-sky-500 active:bg-sky-700"
          >
            Connect
          </button>
        </form>
        <p className="mt-4 text-xs text-zinc-500">
          The quarantine decryption key is requested later, only when you open an item. It is
          imported as a non-extractable CryptoKey and never leaves the browser.
        </p>
      </div>
    </div>
  );
}
