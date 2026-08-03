export type BankId =
  "core" | "main" | "personal" | "dev" | "creative" | "ops" | "research";

export const BANK_IDS: readonly BankId[] = [
  "core",
  "main",
  "personal",
  "dev",
  "creative",
  "ops",
  "research",
] as const;

export interface WriterRule {
  role: string;
  source: string;
  write_bank: BankId;
  read_banks: BankId[];
}

export interface WriterRegistry {
  writers: Record<string, WriterRule>;
  defaults: {
    unknown_writer_action: "review_queue";
    suspicious_content_action: "review_queue";
  };
}

export interface MemoryItem {
  content: string;
  context?: string | null;
  document_id?: string | null;
  metadata?: Record<string, string> | null;
  tags?: string[] | null;
  timestamp?: string | null;
  update_mode?: "replace" | "append" | null;
  [key: string]: unknown;
}

export interface RetainBody {
  items: MemoryItem[];
  async?: boolean;
  document_tags?: string[];
  [key: string]: unknown;
}

export interface RecallBody {
  query: string;
  max_tokens?: number;
  budget?: "low" | "mid" | "high";
  types?: string[] | null;
  tags?: string[] | null;
  tags_match?: string;
  trace?: boolean;
  [key: string]: unknown;
}

export interface RecallResult {
  id: string;
  text: string;
  type?: string | null;
  metadata?: Record<string, string> | null;
  [key: string]: unknown;
}

export interface RecallResponse {
  results: RecallResult[];
  chunks?: Record<string, unknown> | null;
  entities?: Record<string, unknown> | null;
  source_facts?: Record<string, unknown> | null;
  trace?: Record<string, unknown> | null;
}

export type ReviewReason =
  | "unknown_writer"
  | "suspicious_content"
  | "suspicious_query"
  | "recalled_suspicious_memory"
  | "denied_endpoint";

export type QuarantineKind =
  "retain_request" | "recall_request" | "recalled_memory" | "security_event";

export type QuarantineStatus =
  "pending" | "postponed" | "reviewed_allowed" | "reviewed_blocked";

export interface QuarantineItemSummary {
  quarantine_id: string;
  created_at: string;
  updated_at: string;
  kind: QuarantineKind;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  source_bank?: BankId;
  source_memory_id?: string;
  dedupe_key?: string;
  sha256: string;
  status: QuarantineStatus;
  postpone_count: number;
  requarantine_count: number;
}
