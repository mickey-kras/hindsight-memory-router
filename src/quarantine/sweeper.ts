import type { QuarantineRepository } from "./repository.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export interface RetentionSweepConfig {
  // Days of audit history to keep; 0 keeps events forever.
  eventRetentionDays: number;
  now?: () => Date;
}

export interface RetentionSweepResult {
  expired_items: number;
  pruned_events: number;
}

// One retention pass: remove expired pending/postponed items with a cleanup
// audit event each, then prune audit events older than the configured
// retention window and leave a retention_pruned marker when anything was
// pruned.
export async function runQuarantineSweep(
  repository: QuarantineRepository,
  config: RetentionSweepConfig,
): Promise<RetentionSweepResult> {
  const now = config.now?.() ?? new Date();
  const at = now.toISOString();
  const expiredItems = await repository.sweepExpiredItems(at);
  let prunedEvents = 0;
  if (config.eventRetentionDays > 0) {
    const cutoff = new Date(
      now.getTime() - config.eventRetentionDays * DAY_MS,
    ).toISOString();
    prunedEvents = await repository.pruneEventsBefore(cutoff, at);
  }
  return { expired_items: expiredItems, pruned_events: prunedEvents };
}

export interface QuarantineSweeperOptions extends RetentionSweepConfig {
  // Interval between sweeps in seconds; must be positive. Callers decide
  // whether the sweeper runs at all (0 disables it).
  intervalSeconds: number;
}

// Starts the periodic retention sweeper. The timer is unref'd so it never
// keeps the process alive; clear it with clearInterval during shutdown.
export function startQuarantineSweeper(
  repository: QuarantineRepository,
  options: QuarantineSweeperOptions,
): NodeJS.Timeout {
  if (
    !Number.isSafeInteger(options.intervalSeconds) ||
    options.intervalSeconds <= 0
  ) {
    throw new Error("sweeper intervalSeconds must be a positive integer");
  }
  // A sweep that outlasts the interval must not overlap the next tick;
  // overlapping runs would append duplicate cleanup/retention_pruned events.
  let sweeping = false;
  const timer = setInterval(() => {
    if (sweeping) return;
    sweeping = true;
    runQuarantineSweep(repository, options)
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "unknown error";
        process.stderr.write(`quarantine retention sweep failed: ${message}\n`);
      })
      .finally(() => {
        sweeping = false;
      });
  }, options.intervalSeconds * 1000);
  timer.unref();
  return timer;
}
