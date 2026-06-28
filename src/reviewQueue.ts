import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { ReviewRecord } from "./types.js";

export interface ReviewQueue {
  enqueue(record: ReviewRecord): void;
}

export class JsonlReviewQueue implements ReviewQueue {
  constructor(private readonly path: string) {}

  enqueue(record: ReviewRecord): void {
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, JSON.stringify(record) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
  }

  list(): ReviewRecord[] {
    return readReviewQueue(this.path);
  }

  replace(records: ReviewRecord[]): void {
    writeReviewQueue(this.path, records);
  }
}

export function readReviewQueue(path: string): ReviewRecord[] {
  try {
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as ReviewRecord);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

export function writeReviewQueue(path: string, records: ReviewRecord[]): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    records.map((record) => JSON.stringify(record)).join("\n") +
      (records.length > 0 ? "\n" : ""),
    { encoding: "utf8", mode: 0o600 },
  );
}

export class MemoryReviewQueue implements ReviewQueue {
  readonly records: ReviewRecord[] = [];

  enqueue(record: ReviewRecord): void {
    this.records.push(record);
  }
}
