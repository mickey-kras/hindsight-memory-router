import type { QuarantineItemSummary } from "../lib/types";
import { KIND_LABEL, REASON_STYLE, STATUS_STYLE, timeAgo } from "../lib/format";

interface Props {
  items: QuarantineItemSummary[];
  total: number;
  selectedId: string | null;
  onSelect: (item: QuarantineItemSummary) => void;
}

function Badge({ text, style }: { text: string; style: string }) {
  return (
    <span className={`inline-block rounded-md border px-1.5 py-0.5 text-[11px] ${style}`}>
      {text}
    </span>
  );
}

export function QueueView({ items, total, selectedId, onSelect }: Props) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-10 text-center text-sm text-zinc-500">
        Quarantine is empty.
      </div>
    );
  }

  return (
    <div data-testid="queue">
      <div className="mb-2 text-xs text-zinc-500">
        {items.length} shown / {total} reviewable
      </div>

      {/* Desktop table */}
      <div className="hidden overflow-hidden rounded-xl border border-zinc-800 md:block">
        <table className="w-full text-left text-sm">
          <thead className="bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Kind</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Writer</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Age</th>
              <th className="px-3 py-2" title="postponed / requarantined">
                P/R
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800 bg-zinc-900/40">
            {items.map((item) => (
              <tr
                key={item.quarantine_id}
                onClick={() => onSelect(item)}
                data-testid={`row-${item.quarantine_id}`}
                className={`cursor-pointer transition hover:bg-zinc-800/60 ${
                  selectedId === item.quarantine_id ? "bg-zinc-800/80" : ""
                }`}
              >
                <td className="mono px-3 py-2 text-xs text-zinc-300">{item.quarantine_id}</td>
                <td className="px-3 py-2 text-zinc-300">{KIND_LABEL[item.kind]}</td>
                <td className="px-3 py-2">
                  <Badge text={item.reason} style={REASON_STYLE[item.reason]} />
                </td>
                <td className="mono px-3 py-2 text-xs text-zinc-400">{item.writer_id ?? "-"}</td>
                <td className="px-3 py-2">
                  <Badge text={item.status} style={STATUS_STYLE[item.status]} />
                </td>
                <td className="px-3 py-2 text-xs text-zinc-400" title={item.created_at}>
                  {timeAgo(item.created_at)}
                </td>
                <td className="mono px-3 py-2 text-xs text-zinc-500">
                  {item.postpone_count}/{item.requarantine_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mobile cards */}
      <div className="flex flex-col gap-2 md:hidden">
        {items.map((item) => (
          <button
            key={item.quarantine_id}
            onClick={() => onSelect(item)}
            data-testid={`card-${item.quarantine_id}`}
            className={`rounded-xl border p-3 text-left transition active:bg-zinc-800 ${
              selectedId === item.quarantine_id
                ? "border-sky-500/50 bg-zinc-800/70"
                : "border-zinc-800 bg-zinc-900/60"
            }`}
          >
            <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
              <Badge text={item.reason} style={REASON_STYLE[item.reason]} />
              <Badge text={item.status} style={STATUS_STYLE[item.status]} />
              <span className="ml-auto text-[11px] text-zinc-500">{timeAgo(item.created_at)}</span>
            </div>
            <div className="mono text-xs text-zinc-300">{item.quarantine_id}</div>
            <div className="mt-1 text-xs text-zinc-500">
              {KIND_LABEL[item.kind]}
              {item.writer_id ? ` - ${item.writer_id}` : ""}
              {item.postpone_count > 0 ? ` - postponed x${item.postpone_count}` : ""}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
