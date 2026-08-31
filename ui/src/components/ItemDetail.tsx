import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  approveItem,
  fetchItem,
  postponeItem,
  rejectItem,
  type AdminTokens,
} from "../lib/api";
import {
  DecryptError,
  decryptEnvelope,
  importDecryptionKeyPem,
} from "../lib/quarantineCrypto";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
} from "../lib/types";
import { formatBytes, formatTime, KIND_LABEL, REASON_STYLE, STATUS_STYLE } from "../lib/format";
import { Banner } from "./Banner";

interface Props {
  item: QuarantineItemSummary;
  tokens: AdminTokens;
  onAction: (message: string) => void;
  onClose: () => void;
}

type PendingAction = "approve" | "reject" | null;

export function ItemDetail({ item, tokens, onAction, onClose }: Props) {
  const [detail, setDetail] = useState<QuarantineItemResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [keyPem, setKeyPem] = useState("");
  const keyRef = useRef<CryptoKey | null>(null);
  const [keyLoaded, setKeyLoaded] = useState(false);
  const [decrypted, setDecrypted] = useState<DecryptedQuarantineObject | null>(null);
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setDetail(null);
    setDecrypted(null);
    setDecryptError(null);
    setPendingAction(null);
    setLoadError(null);
    let active = true;
    fetchItem(tokens, item.quarantine_id)
      .then((response) => {
        if (active) setDetail(response);
      })
      .catch((error: unknown) => {
        if (active) {
          setLoadError(error instanceof ApiError ? `${error.code}: ${error.message}` : "load failed");
        }
      });
    return () => {
      active = false;
    };
  }, [item.quarantine_id, tokens]);

  const importKey = useCallback(async () => {
    setDecryptError(null);
    try {
      keyRef.current = await importDecryptionKeyPem(keyPem);
      setKeyLoaded(true);
      setKeyPem(""); // drop the PEM text immediately; the CryptoKey is non-extractable
    } catch (error) {
      setDecryptError(error instanceof DecryptError ? error.message : "key import failed");
    }
  }, [keyPem]);

  const decrypt = useCallback(async () => {
    if (!detail || !keyRef.current) return;
    setDecryptError(null);
    try {
      setDecrypted(await decryptEnvelope(detail.encrypted, keyRef.current));
    } catch (error) {
      setDecrypted(null);
      setDecryptError(error instanceof DecryptError ? error.message : "decryption failed");
    }
  }, [detail]);

  const runAction = useCallback(
    async (action: "approve" | "reject" | "postpone") => {
      setBusy(true);
      try {
        if (action === "approve") {
          if (!decrypted) throw new Error("decrypt the item before approving");
          await approveItem(tokens, item.quarantine_id, decrypted);
          onAction(`approved ${item.quarantine_id}`);
        } else if (action === "reject") {
          await rejectItem(tokens, item.quarantine_id);
          onAction(`rejected ${item.quarantine_id}`);
        } else {
          await postponeItem(tokens, item.quarantine_id);
          onAction(`postponed ${item.quarantine_id}`);
        }
      } catch (error) {
        setBusy(false);
        setPendingAction(null);
        setDecryptError(
          error instanceof ApiError ? `${error.code}: ${error.message}` : "action failed",
        );
        return;
      }
    },
    [decrypted, item.quarantine_id, tokens, onAction],
  );

  const record = detail?.record ?? item;
  const meta: Array<[string, string]> = [
    ["Kind", KIND_LABEL[item.kind]],
    ["Created", formatTime(item.created_at)],
    ["Updated", formatTime(item.updated_at)],
    ["SHA-256", item.sha256],
    ["Postponed", String(item.postpone_count)],
    ["Requarantined", String(item.requarantine_count)],
  ];
  if (item.writer_id) meta.push(["Writer", item.writer_id]);
  if (item.source) meta.push(["Source", item.source]);
  if (item.source_bank) meta.push(["Source bank", item.source_bank]);
  if (item.source_memory_id) meta.push(["Source memory", item.source_memory_id]);
  if (record.encrypted_bytes !== undefined)
    meta.push(["Encrypted size", formatBytes(record.encrypted_bytes)]);
  if (record.expires_at) meta.push(["Expires", formatTime(record.expires_at)]);

  const canReview = item.status === "pending" || item.status === "postponed";

  return (
    <section
      data-testid="item-detail"
      className="flex flex-col gap-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="mono text-sm text-zinc-200">{item.quarantine_id}</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <span className={`rounded-md border px-1.5 py-0.5 text-[11px] ${REASON_STYLE[item.reason]}`}>
              {item.reason}
            </span>
            <span className={`rounded-md border px-1.5 py-0.5 text-[11px] ${STATUS_STYLE[item.status]}`}>
              {item.status}
            </span>
          </div>
        </div>
        <button
          onClick={onClose}
          aria-label="close detail"
          className="rounded-lg border border-zinc-700 px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-800"
        >
          close
        </button>
      </div>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
        {meta.map(([label, value]) => (
          <div key={label} className="flex gap-2">
            <dt className="w-28 shrink-0 text-zinc-500">{label}</dt>
            <dd className="mono break-all text-zinc-300">{value}</dd>
          </div>
        ))}
      </dl>

      {loadError && <Banner kind="error" text={loadError} />}
      {detail && !decrypted && (
        <div className="flex flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
          <div className="text-xs text-zinc-400">
            Encrypted envelope loaded ({formatBytes(JSON.stringify(detail.encrypted).length)}).
            {keyLoaded
              ? " Decryption key imported (non-extractable)."
              : " Paste the quarantine decryption key. It never leaves this browser tab."}
          </div>
          {!keyLoaded && (
            <>
              <textarea
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
                rows={4}
                spellCheck={false}
                data-testid="key-input"
                placeholder="Paste PKCS8 PEM here"
                className="mono rounded-lg border border-zinc-700 bg-zinc-900 p-2 text-xs outline-none focus:border-sky-500"
              />
              <button
                onClick={() => void importKey()}
                disabled={!keyPem.trim()}
                data-testid="import-key"
                className="self-start rounded-lg border border-zinc-600 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Import key
              </button>
            </>
          )}
          {keyLoaded && (
            <button
              onClick={() => void decrypt()}
              data-testid="decrypt"
              className="self-start rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500"
            >
              Decrypt item
            </button>
          )}
        </div>
      )}

      {decryptError && <Banner kind="error" text={decryptError} onDismiss={() => setDecryptError(null)} />}

      {decrypted && (
        <div className="rounded-lg border border-emerald-500/30 bg-zinc-950 p-3">
          <div className="mb-2 text-xs font-medium text-emerald-300">
            Decrypted locally - digest verified against the stored envelope
          </div>
          <pre
            data-testid="payload"
            className="mono max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-zinc-200"
          >
            {JSON.stringify(decrypted, null, 2)}
          </pre>
        </div>
      )}

      {canReview && (
        <div className="sticky bottom-0 -mx-4 -mb-4 border-t border-zinc-800 bg-zinc-900/95 px-4 py-3 backdrop-blur">
          {pendingAction === null && (
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setPendingAction("approve")}
                disabled={!decrypted || busy || !tokens.review}
                data-testid="approve-open"
                title={!decrypted ? "decrypt first" : !tokens.review ? "review token required" : ""}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
              >
                Approve
              </button>
              <button
                onClick={() => setPendingAction("reject")}
                disabled={busy || !tokens.review}
                data-testid="reject-open"
                className="rounded-lg bg-red-600/80 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-40"
              >
                Reject
              </button>
              <button
                onClick={() => void runAction("postpone")}
                disabled={busy || !tokens.review}
                data-testid="postpone"
                className="rounded-lg border border-zinc-600 px-4 py-2 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
              >
                Postpone
              </button>
            </div>
          )}
          {pendingAction !== null && (
            <div className="flex flex-wrap items-center gap-2" data-testid="confirm-bar">
              <span className="text-sm text-zinc-300">
                {pendingAction === "approve"
                  ? "Approve into memory? The exact decrypted object is submitted for hash verification."
                  : "Reject this item?"}
              </span>
              <button
                onClick={() => void runAction(pendingAction)}
                disabled={busy}
                data-testid="confirm-action"
                className={`rounded-lg px-4 py-2 text-sm font-medium text-white ${
                  pendingAction === "approve"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                } disabled:opacity-40`}
              >
                {busy ? "working..." : `Confirm ${pendingAction}`}
              </button>
              <button
                onClick={() => setPendingAction(null)}
                disabled={busy}
                className="rounded-lg border border-zinc-600 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
