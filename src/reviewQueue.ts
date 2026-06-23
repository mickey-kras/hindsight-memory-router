import { appendFileSync, mkdirSync } from "node:fs";
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
}

export class MemoryReviewQueue implements ReviewQueue {
  readonly records: ReviewRecord[] = [];

  enqueue(record: ReviewRecord): void {
    this.records.push(record);
  }
}
