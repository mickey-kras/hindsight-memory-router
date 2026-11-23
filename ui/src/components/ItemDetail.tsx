import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { ApiError, fetchItem, type AdminSession } from "../lib/api";
import { DecryptError, importDecryptionKeyPem } from "../lib/quarantineCrypto";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
} from "../lib/types";
import { formatBytes, formatTime, KIND_LABEL, REASON_STYLE, STATUS_STYLE } from "../lib/format";
import { Banner } from "./Banner";
import {
  approveLabel,
  approveTitle,
  confirmButtonClass,
  confirmLabel,
  confirmPrompt,
  decryptItem,
  executeAction,
  extractJoinedText,
  extractOrderedPayload,
  needsReviewAgent,
  rejectLabel,
  reviewTokenTitle,
  type OpenAction,
  type PendingAction,
  type RunnableAction,
} from "./itemDetailLogic";

interface Props {
  readonly item: QuarantineItemSummary;
  readonly tokens: AdminSession;
  readonly onUnauthorized: () => void;
  readonly onAction: (message: string) => void;
  readonly onClose: () => void;
}

export function ItemDetail({ item, tokens, onAction, onClose, onUnauthorized }: Props) {
  const [detail, setDetail] = useState<QuarantineItemResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [keyPem, setKeyPem] = useState("");
  const keyRef = useRef<CryptoKey | null>(null);
  const [keyLoaded, setKeyLoaded] = useState(false);
  const [useAgent, setUseAgent] = useState(false);
  const [agentCredential, setAgentCredential] = useState("");
  const [decrypted, setDecrypted] = useState<DecryptedQuarantineObject | null>(null);
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [busy, setBusy] = useState(false);
  const selectionGeneration = useRef(0);

  // Invalidate old crypto completions and clear plaintext before selection can paint.
  useLayoutEffect(() => {
    selectionGeneration.current += 1;
    setDetail(null);
    setDecrypted(null);
    setDecryptError(null);
    setPendingAction(null);
    setLoadError(null);
    setAgentCredential("");
    let active = true;
    fetchItem(tokens, item.quarantine_id)
      .then((response) => {
        if (active) setDetail(response);
      })
      .catch((error: unknown) => {
        if (active) {
          if (tokens === "host" && error instanceof ApiError && error.status === 401) onUnauthorized();
          setLoadError(error instanceof ApiError ? `${error.code}: ${error.message}` : "load failed");
        }
      });
    return () => {
      active = false;
      selectionGeneration.current += 1;
    };
  }, [item.quarantine_id, tokens, onUnauthorized]);

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
    if (!detail) return;
    const generation = selectionGeneration.current;
    setDecryptError(null);
    try {
      const plaintext = await decryptItem(detail, {
        useAgent,
        agentCredential,
        tokens,
        localKey: keyRef.current,
      });
      if (plaintext && generation === selectionGeneration.current) setDecrypted(plaintext);
    } catch (error) {
      if (generation !== selectionGeneration.current) return;
      setDecrypted(null);
      setDecryptError(error instanceof DecryptError ? error.message : "decryption failed");
    }
  }, [detail, useAgent, agentCredential, tokens]);

  const runAction = useCallback(
    async (action: RunnableAction) => {
      setBusy(true);
      try {
        await executeAction(action, { tokens, item, detail, decrypted, onAction });
      } catch (error) {
        if (tokens === "host" && error instanceof ApiError && error.status === 401) onUnauthorized();
        setBusy(false);
        setPendingAction(null);
        setDecryptError(
          error instanceof ApiError ? `${error.code}: ${error.message}` : "action failed",
        );
        return;
      }
    },
    [decrypted, detail, item, tokens, onAction, onUnauthorized],
  );

  // importKey/decrypt/runAction handle their own errors internally; the catch is
  // only a safety net so the fire-and-forget call sites below stay lint-clean.
  const handleImport = useCallback(() => {
    importKey().catch(() => undefined);
  }, [importKey]);

  const handleDecrypt = useCallback(() => {
    decrypt().catch(() => undefined);
  }, [decrypt]);

  const handleRunAction = useCallback(
    (action: RunnableAction) => {
      runAction(action).catch(() => undefined);
    },
    [runAction],
  );

  const record = detail?.record ?? item;
  const canFinalize = record.status === "review_side_effect_completed";
  const canApprove = canFinalize && record.kind === "retain_request";
  const canReject = canFinalize && record.kind === "recalled_memory";
  const canReview = record.status === "pending" || record.status === "postponed";
  const reviewOnly = record.kind === "blocked_content";
  const supportsApproval = ["retain_request", "recalled_memory", "blocked_content"].includes(record.kind);
  const joinedText = extractJoinedText(decrypted);
  const orderedPayload = extractOrderedPayload(decrypted);
  const canReconcile = record.status === "review_side_effect_started";
  const needsAgent = detail ? needsReviewAgent(detail, useAgent) : useAgent;
  const authorized = tokens === "host" || Boolean(tokens.review);

  return (
    <section
      data-testid="item-detail"
      className="flex flex-col gap-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
    >
      <ItemMetadata item={item} record={record} onClose={onClose} />

      {record.audit_summary && (
        <p data-testid="audit-summary" className="break-words text-sm text-zinc-300">
          {record.audit_summary}
        </p>
      )}
      {reviewOnly && (
        <Banner kind="info" text="False-positive approval can permit this exact content on later calls with the same identity, operation, banks, sources, and policy. Neither decision changes source memories or repeats a provider operation." />
      )}

      {loadError && <Banner kind="error" text={loadError} />}
      {detail && !decrypted && (
        <DecryptControls
          detail={detail}
          needsAgent={needsAgent}
          useAgent={useAgent}
          setUseAgent={setUseAgent}
          agentCredential={agentCredential}
          setAgentCredential={setAgentCredential}
          keyPem={keyPem}
          setKeyPem={setKeyPem}
          keyLoaded={keyLoaded}
          busy={busy}
          authorized={authorized}
          onImport={handleImport}
          onDecrypt={handleDecrypt}
        />
      )}

      {decryptError && <Banner kind="error" text={decryptError} onDismiss={() => setDecryptError(null)} />}

      {decrypted && (
        <DecryptedView
          reviewOnly={reviewOnly}
          orderedPayload={orderedPayload}
          joinedText={joinedText}
          decrypted={decrypted}
        />
      )}

      {canReconcile && (
        <Banner
          kind="info"
          text="The review side effect may or may not have reached Hindsight. Reconcile explicitly; nothing is replayed automatically."
        />
      )}

      {canFinalize && (
        <Banner
          kind="info"
          text="Hindsight completed the original action. Finalize the same decision without calling Hindsight again. Retain approval still requires the exact decrypted object."
        />
      )}

      <ActionBar
        visible={canReview || canReconcile || canFinalize}
        canReview={canReview}
        canApprove={canApprove}
        canReject={canReject}
        canReconcile={canReconcile}
        canFinalize={canFinalize}
        reviewOnly={reviewOnly}
        supportsApproval={supportsApproval}
        hasDecrypted={decrypted !== null}
        authorized={authorized}
        busy={busy}
        pendingAction={pendingAction}
        onOpenAction={(action) => setPendingAction(action)}
        onCancel={() => setPendingAction(null)}
        onRunAction={handleRunAction}
      />
    </section>
  );
}

interface ActionBarProps extends ActionButtonsProps {
  readonly visible: boolean;
  readonly pendingAction: PendingAction;
  readonly onCancel: () => void;
}

export function ActionBar(props: ActionBarProps) {
  if (!props.visible) return null;
  const { pendingAction, onCancel, onOpenAction, onRunAction } = props;
  return (
    <div className="sticky bottom-0 -mx-4 -mb-4 border-t border-zinc-800 bg-zinc-900/95 px-4 py-3 backdrop-blur">
      {pendingAction === null ? (
        <ActionButtons
          canReview={props.canReview}
          canApprove={props.canApprove}
          canReject={props.canReject}
          canReconcile={props.canReconcile}
          canFinalize={props.canFinalize}
          reviewOnly={props.reviewOnly}
          supportsApproval={props.supportsApproval}
          hasDecrypted={props.hasDecrypted}
          authorized={props.authorized}
          busy={props.busy}
          onOpenAction={onOpenAction}
          onRunAction={onRunAction}
        />
      ) : (
        <ConfirmBar
          pendingAction={pendingAction}
          reviewOnly={props.reviewOnly}
          busy={props.busy}
          onConfirm={() => onRunAction(pendingAction)}
          onCancel={onCancel}
        />
      )}
    </div>
  );
}

export interface ActionButtonsProps {
  readonly canReview: boolean;
  readonly canApprove: boolean;
  readonly canReject: boolean;
  readonly canReconcile: boolean;
  readonly canFinalize: boolean;
  readonly reviewOnly: boolean;
  readonly supportsApproval: boolean;
  readonly hasDecrypted: boolean;
  readonly authorized: boolean;
  readonly busy: boolean;
  readonly onOpenAction: (action: OpenAction) => void;
  readonly onRunAction: (action: RunnableAction) => void;
}

export function ActionButtons({
  canReview,
  canApprove,
  canReject,
  canReconcile,
  canFinalize,
  reviewOnly,
  supportsApproval,
  hasDecrypted,
  authorized,
  busy,
  onOpenAction,
  onRunAction,
}: ActionButtonsProps) {
  return (
    <div className="flex flex-wrap gap-2">
      {(canReview || canApprove || canReject) && (
        <>
          {((canReview && supportsApproval) || canApprove) && (
            <button
              onClick={() => onOpenAction("approve")}
              disabled={!hasDecrypted || busy || !authorized}
              data-testid="approve-open"
              title={approveTitle(hasDecrypted, authorized)}
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
            >
              {approveLabel(canFinalize, reviewOnly)}
            </button>
          )}
          {(canReview || canReject) && (
            <button
              onClick={() => onOpenAction("reject")}
              disabled={busy || !authorized}
              data-testid="reject-open"
              className="rounded-lg bg-red-600/80 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-40"
            >
              {rejectLabel(canFinalize, reviewOnly)}
            </button>
          )}
          {canReview && (
            <button
              onClick={() => onRunAction("postpone")}
              disabled={busy || !authorized}
              data-testid="postpone"
              className="rounded-lg border border-zinc-600 px-4 py-2 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
            >
              Postpone
            </button>
          )}
        </>
      )}
      {canReconcile && (
        <>
          <button
            onClick={() => onOpenAction("confirmed_applied")}
            disabled={busy || !authorized}
            data-testid="reconcile-applied-open"
            title={reviewTokenTitle(authorized)}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
          >
            Confirm applied
          </button>
          <button
            onClick={() => onOpenAction("confirmed_not_applied")}
            disabled={busy || !authorized}
            data-testid="reconcile-not-applied-open"
            title={reviewTokenTitle(authorized)}
            className="rounded-lg border border-zinc-600 px-4 py-2 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
          >
            Confirm not applied
          </button>
        </>
      )}
    </div>
  );
}

interface ConfirmBarProps {
  readonly pendingAction: OpenAction;
  readonly reviewOnly: boolean;
  readonly busy: boolean;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}

export function ConfirmBar({ pendingAction, reviewOnly, busy, onConfirm, onCancel }: ConfirmBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="confirm-bar">
      <span className="text-sm text-zinc-300">
        {confirmPrompt(pendingAction, reviewOnly)}
      </span>
      <button
        onClick={onConfirm}
        disabled={busy}
        data-testid="confirm-action"
        className={`rounded-lg px-4 py-2 text-sm font-medium text-white ${confirmButtonClass(pendingAction)} disabled:opacity-40`}
      >
        {confirmLabel(busy, pendingAction)}
      </button>
      <button
        onClick={onCancel}
        disabled={busy}
        className="rounded-lg border border-zinc-600 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
      >
        Cancel
      </button>
    </div>
  );
}

interface DecryptedViewProps {
  readonly reviewOnly: boolean;
  readonly orderedPayload: string | null;
  readonly joinedText: string | null;
  readonly decrypted: DecryptedQuarantineObject;
}

export function DecryptedView({ reviewOnly, orderedPayload, joinedText, decrypted }: DecryptedViewProps) {
  return (
    <div className="rounded-lg border border-emerald-500/30 bg-zinc-950 p-3">
      <div className="mb-2 text-xs font-medium text-emerald-300">
        Decrypted locally - digest verified against the stored envelope
      </div>
      {reviewOnly && orderedPayload !== null && (
        <div className="mb-3">
          <h3 className="mb-1 text-xs font-medium text-emerald-300">Original field order under review</h3>
          <pre data-testid="ordered-payload" className="mono max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-zinc-200">
            {orderedPayload}
          </pre>
        </div>
      )}
      {reviewOnly && joinedText !== null && (
        <div className="mb-3">
          <h3 className="mb-1 text-xs font-medium text-zinc-300">Joined text under review</h3>
          <pre data-testid="joined-text" className="mono max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-zinc-200">
            {joinedText}
          </pre>
        </div>
      )}
      <pre
        data-testid="payload"
        className="mono max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-zinc-200"
      >
        {JSON.stringify(decrypted, null, 2)}
      </pre>
    </div>
  );
}

interface DecryptControlsProps {
  readonly detail: QuarantineItemResponse;
  readonly needsAgent: boolean;
  readonly useAgent: boolean;
  readonly setUseAgent: (value: boolean) => void;
  readonly agentCredential: string;
  readonly setAgentCredential: (value: string) => void;
  readonly keyPem: string;
  readonly setKeyPem: (value: string) => void;
  readonly keyLoaded: boolean;
  readonly busy: boolean;
  readonly authorized: boolean;
  readonly onImport: () => void;
  readonly onDecrypt: () => void;
}

function envelopeHint(needsAgent: boolean, keyLoaded: boolean): string {
  if (needsAgent) return " Use the trusted local review agent; no token private key enters the browser.";
  if (keyLoaded) return " Decryption key imported (non-extractable).";
  return " Paste the quarantine decryption key. It never leaves this browser tab.";
}

export function DecryptControls({
  detail, needsAgent, useAgent, setUseAgent, agentCredential, setAgentCredential,
  keyPem, setKeyPem, keyLoaded, busy, authorized, onImport, onDecrypt,
}: DecryptControlsProps) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
      <div className="text-xs text-zinc-400">
        Encrypted envelope loaded ({formatBytes(JSON.stringify(detail.encrypted).length)}).
        {envelopeHint(needsAgent, keyLoaded)}
      </div>
      {detail.encrypted.encryption.provider === undefined && (
        <label className="flex items-center gap-2 text-xs text-zinc-300">
          <input
            type="checkbox"
            checked={useAgent}
            onChange={(e) => setUseAgent(e.target.checked)}
            data-testid="use-agent"
          />
          {"Use a hardware-backed key via local review agent"}
        </label>
      )}
      {needsAgent && (
        <>
          <input
            type="password"
            value={agentCredential}
            onChange={(e) => setAgentCredential(e.target.value)}
            autoComplete="off"
            data-testid="agent-credential"
            placeholder="Local review agent credential"
            className="mono rounded-lg border border-zinc-700 bg-zinc-900 p-2 text-xs outline-none focus:border-sky-500"
          />
          <button
            onClick={onDecrypt}
            disabled={agentCredential.length < 32 || busy || !authorized}
            data-testid="decrypt-agent"
            className="self-start rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40"
          >
            Decrypt with local agent
          </button>
        </>
      )}
      {!needsAgent && !keyLoaded && (
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
            onClick={onImport}
            disabled={!keyPem.trim()}
            data-testid="import-key"
            className="self-start rounded-lg border border-zinc-600 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-40"
          >
            Import key
          </button>
        </>
      )}
      {!needsAgent && keyLoaded && (
        <button
          onClick={onDecrypt}
          data-testid="decrypt"
          className="self-start rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500"
        >
          Decrypt item
        </button>
      )}
    </div>
  );
}

export function ItemMetadata({ item, record, onClose }: {
  readonly item: QuarantineItemSummary;
  readonly record: QuarantineItemSummary;
  readonly onClose: () => void;
}) {
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

  return (
    <>
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
    </>
  );
}
