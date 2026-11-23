interface Props {
  readonly kind: "error" | "ok" | "info";
  readonly text: string;
  readonly onDismiss?: () => void;
}

const STYLE = {
  error: "border-red-500/40 bg-red-500/10 text-red-200",
  ok: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
  info: "border-sky-500/40 bg-sky-500/10 text-sky-200",
} as const;

export function Banner({ kind, text, onDismiss }: Props) {
  const className = `flex items-start justify-between gap-3 rounded-lg border px-3 py-2 text-sm ${STYLE[kind]}`;
  const content = (
    <>
      <span className="break-words">{text}</span>
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="dismiss"
          className="shrink-0 rounded px-1.5 text-current opacity-70 hover:opacity-100"
        >
          x
        </button>
      )}
    </>
  );
  if (kind === "error") {
    return (
      <div role="alert" className={className}>
        {content}
      </div>
    );
  }
  // <output> carries the implicit "status" live-region role.
  return <output className={className}>{content}</output>;
}
