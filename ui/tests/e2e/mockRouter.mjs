// Mock memory-router admin API for e2e tests. Serves the golden fixtures
// produced by the router's real envelope.py and enforces token scopes like
// the real router: read for GET, review for item actions, cleanup for cleanup.

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "../fixtures");

const TOKENS = {
  read: "e2e-read-token",
  review: "e2e-review-token",
  cleanup: "e2e-cleanup-token",
};
const MAX_POSTPONES = 3;

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) && Array.isArray(b) &&
      a.length === b.length &&
      a.every((entry, i) => deepEqual(entry, b[i]))
    );
  }
  if (typeof a === "object") {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

export function startMockRouter(port = 8899) {
  const index = JSON.parse(readFileSync(path.join(FIXTURES, "index.json"), "utf8"));
  let items;
  let actions;
  let eventCount;

  const reset = () => {
    items = new Map();
    for (const entry of index.items) {
      items.set(entry.record.quarantine_id, {
        record: { ...entry.record },
        encrypted: JSON.parse(readFileSync(path.join(FIXTURES, entry.envelope_file), "utf8")),
        decrypted: JSON.parse(readFileSync(path.join(FIXTURES, entry.decrypted_file), "utf8")),
      });
    }
    actions = [];
    eventCount = 12;
  };
  reset();

  const reviewable = () =>
    [...items.values()].filter((i) => ["pending", "postponed"].includes(i.record.status));

  const stats = () => {
    const all = [...items.values()];
    return {
      total_items: all.length,
      pending_items: all.filter((i) => i.record.status === "pending").length,
      postponed_items: all.filter((i) => i.record.status === "postponed").length,
      reviewed_allowed_items: all.filter((i) => i.record.status === "reviewed_allowed").length,
      reviewed_blocked_items: all.filter((i) => i.record.status === "reviewed_blocked").length,
      encrypted_bytes: all.reduce((sum, i) => sum + (i.record.encrypted_bytes ?? 0), 0),
      event_count: eventCount,
    };
  };

  const send = (res, status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };

  const authorized = (req, scope) => {
    const header = req.headers.authorization ?? "";
    return header === `Bearer ${TOKENS[scope]}`;
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://mock");
    const finish = (status, body) => send(res, status, body);

    if (url.pathname === "/version") return finish(200, { version: "0.9.0-e2e-mock" });
    if (url.pathname === "/health/ready") return finish(200, { status: "ready" });
    if (url.pathname === "/__actions") return finish(200, actions);
    if (url.pathname === "/__tokens") return finish(200, TOKENS);
    if (url.pathname === "/__reset" && req.method === "POST") {
      reset();
      return finish(200, { reset: true });
    }
    if (url.pathname === "/__seed-more" && req.method === "POST") {
      const template = items.values().next().value;
      for (let index = 0; index < 102; index += 1) {
        const quarantineId = `q_seed_${index.toString(16).padStart(16, "0")}`;
        items.set(quarantineId, {
          ...template,
          record: {
            ...template.record,
            quarantine_id: quarantineId,
            created_at: new Date(Date.parse(template.record.created_at) + index).toISOString(),
          },
        });
      }
      return finish(200, { seeded: 102 });
    }

    if (!url.pathname.startsWith("/admin/quarantine")) {
      return finish(404, { error: "not_found", message: "not found" });
    }

    const isCleanup = url.pathname === "/admin/quarantine/cleanup";
    const scope = isCleanup ? "cleanup" : req.method === "GET" ? "read" : "review";
    if (!authorized(req, scope)) {
      return finish(401, { error: "unauthorized", message: "invalid or missing admin token" });
    }

    if (url.pathname === "/admin/quarantine/queue" && req.method === "GET") {
      const limit = Math.min(500, Number(url.searchParams.get("limit") ?? 100));
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const list = reviewable()
        .sort((a, b) => a.record.created_at.localeCompare(b.record.created_at))
        .map((i) => i.record);
      return finish(200, { items: list.slice(offset, offset + limit), total: list.length });
    }

    if (url.pathname === "/admin/quarantine/stats" && req.method === "GET") {
      return finish(200, stats());
    }

    if (isCleanup && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        const scopeValue = parsed.scope ?? "pending";
        const pool = [...items.values()].filter((i) =>
          scopeValue === "all"
            ? true
            : ["pending", "postponed"].includes(i.record.status),
        );
        const matched = pool.filter(
          (i) =>
            (!parsed.reasons || parsed.reasons.includes(i.record.reason)) &&
            (!parsed.older_than || Date.parse(i.record.created_at) < Date.parse(parsed.older_than)),
        );
        const bytes = matched.reduce((sum, i) => sum + (i.record.encrypted_bytes ?? 0), 0);
        if (parsed.dry_run !== false) {
          actions.push({ action: "cleanup_preview", count: matched.length });
          return finish(200, { dry_run: true, count: matched.length, encrypted_bytes: bytes });
        }
        if (parsed.expected_count !== matched.length) {
          return finish(409, {
            error: "cleanup_selection_changed",
            message: "cleanup selection changed since preview",
          });
        }
        for (const item of matched) items.delete(item.record.quarantine_id);
        eventCount += matched.length;
        actions.push({ action: "cleanup_execute", count: matched.length });
        return finish(200, { dry_run: false, count: matched.length, encrypted_bytes: bytes });
      });
      return;
    }

    const match = url.pathname.match(
      /^\/admin\/quarantine\/items\/(q_[0-9A-Za-z]+_[0-9a-f]{16})(\/(approve|reject|postpone))?$/,
    );
    if (!match) return finish(404, { error: "not_found", message: "not found" });
    const item = items.get(match[1]);
    if (!item) {
      return finish(404, { error: "quarantine_not_found", message: "quarantine item not found" });
    }
    const action = match[3];

    if (req.method === "GET" && !action) {
      return finish(200, { record: item.record, encrypted: item.encrypted });
    }

    if (req.method === "POST" && action === "approve") {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        if (!deepEqual(parsed.decrypted, item.decrypted)) {
          return finish(409, {
            error: "quarantine_hash_mismatch",
            message: "decrypted quarantine content differs from the original item",
          });
        }
        if (!["retain_request", "recalled_memory"].includes(item.record.kind)) {
          return finish(409, {
            error: "invalid_review_action",
            message: "this quarantine item cannot be approved into memory",
          });
        }
        item.record.status = "reviewed_allowed";
        eventCount += 1;
        actions.push({ action: "approve", quarantine_id: item.record.quarantine_id, decrypted: parsed.decrypted });
        finish(
          200,
          item.record.kind === "recalled_memory"
            ? {
                reviewed: true,
                allowed: true,
                quarantine_id: item.record.quarantine_id,
                source_bank: item.record.source_bank,
                source_memory_id: item.record.source_memory_id,
              }
            : {
                approved: true,
                quarantine_id: item.record.quarantine_id,
                target_bank: "openclaw-main",
              },
        );
      });
      return;
    }

    if (req.method === "POST" && action === "reject") {
      item.record.status = "reviewed_blocked";
      eventCount += 1;
      actions.push({ action: "reject", quarantine_id: item.record.quarantine_id });
      return finish(
        200,
        item.record.kind === "recalled_memory"
          ? {
              reviewed: true,
              allowed: false,
              quarantine_id: item.record.quarantine_id,
              source_bank: item.record.source_bank,
              source_memory_id: item.record.source_memory_id,
            }
          : { rejected: true, quarantine_id: item.record.quarantine_id },
      );
    }

    if (req.method === "POST" && action === "postpone") {
      if (item.record.postpone_count >= MAX_POSTPONES) {
        return finish(409, {
          error: "postpone_limit_reached",
          message:
            "maximum postpone count reached; approve, reject, or wait for QUARANTINE_ITEM_TTL_DAYS expiry",
        });
      }
      item.record.postpone_count += 1;
      item.record.status = "postponed";
      eventCount += 1;
      actions.push({ action: "postpone", quarantine_id: item.record.quarantine_id });
      return finish(200, {
        postponed: true,
        quarantine_id: item.record.quarantine_id,
        count: item.record.postpone_count,
      });
    }

    return finish(405, { error: "method_not_allowed", message: "method not allowed" });
  });

  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => resolve({ server, actions, tokens: TOKENS }));
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const port = Number(process.argv[2] ?? 8899);
  startMockRouter(port).then(() => console.log(`mock router on 127.0.0.1:${port}`));
}
