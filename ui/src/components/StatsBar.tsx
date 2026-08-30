import type { QuarantineStats } from "../lib/types";
import { formatBytes } from "../lib/format";

interface Props {
  stats: QuarantineStats;
}

export function StatsBar({ stats }: Props) {
  const cards: Array<{ label: string; value: string; tone?: string }> = [
    { label: "Pending", value: String(stats.pending_items), tone: "text-sky-300" },
    { label: "Postponed", value: String(stats.postponed_items), tone: "text-zinc-300" },
    { label: "Total", value: String(stats.total_items) },
    { label: "Allowed", value: String(stats.reviewed_allowed_items), tone: "text-emerald-300" },
    { label: "Blocked", value: String(stats.reviewed_blocked_items), tone: "text-red-300" },
    { label: "Encrypted", value: formatBytes(stats.encrypted_bytes) },
    { label: "Events", value: String(stats.event_count) },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7" data-testid="stats">
      {cards.map((card) => (
        <div
          key={card.label}
          className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-3 py-2.5"
        >
          <div className="text-[11px] uppercase tracking-wide text-zinc-500">{card.label}</div>
          <div className={`mono text-lg font-semibold ${card.tone ?? "text-zinc-100"}`}>
            {card.value}
          </div>
        </div>
      ))}
    </div>
  );
}
