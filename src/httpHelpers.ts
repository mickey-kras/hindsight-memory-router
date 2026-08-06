import type { IncomingMessage, ServerResponse } from "node:http";
import { HttpError } from "./httpError.js";

const ORIGIN_FORM_BASE = "http://memory-router.internal";

export function parseRequestUrl(rawUrl: string): URL {
  try {
    if (rawUrl.startsWith("/")) {
      // The synthetic authority is inert: callers only consume pathname and
      // searchParams after WHATWG normalization of an origin-form target.
      return new URL(`${ORIGIN_FORM_BASE}${rawUrl}`);
    }
    if (/^https?:\/\//i.test(rawUrl)) {
      return new URL(rawUrl);
    }
  } catch {
    // Fall through to the stable public error below.
  }
  throw new HttpError(400, "invalid_url", "request URL is malformed");
}

export async function readJson(
  req: IncomingMessage,
  maxBodyBytes: number,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.length;
    if (totalBytes > maxBodyBytes) {
      throw new HttpError(413, "payload_too_large", "payload too large");
    }
    chunks.push(buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new HttpError(400, "invalid_json", "invalid JSON body");
  }
}

export function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new HttpError(
      400,
      "invalid_path_encoding",
      "path segment contains malformed percent-encoding",
    );
  }
}

export function parseMemoryPath(
  pathname: string,
): { writerId: string; action: "retain" | "recall" } | null {
  const retain = pathname.match(/^\/v1\/default\/banks\/([^/]+)\/memories$/);
  if (retain) {
    return { writerId: decodePathSegment(retain[1]), action: "retain" };
  }

  const recall = pathname.match(
    /^\/v1\/default\/banks\/([^/]+)\/memories\/recall$/,
  );
  if (recall) {
    return { writerId: decodePathSegment(recall[1]), action: "recall" };
  }

  return null;
}

export function parseAdminItemPath(pathname: string): {
  quarantineId: string;
  action: "read" | "approve" | "reject" | "postpone";
} | null {
  const match = pathname.match(
    /^\/admin\/quarantine\/items\/([^/]+)(?:\/(approve|reject|postpone))?$/,
  );
  if (!match) return null;
  return {
    quarantineId: decodePathSegment(match[1]),
    action: (match[2] ?? "read") as "read" | "approve" | "reject" | "postpone",
  };
}

export function integerQuery(
  query: URLSearchParams,
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const values = query.getAll(name);
  if (values.length === 0) return fallback;
  if (values.length > 1) {
    throw new HttpError(400, "invalid_query", `${name} is invalid`);
  }
  const value = Number(values[0]);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new HttpError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}
