// Types mirror openapi/openapi.json (hindsight-memory-router). Keep in sync.

export type QuarantineKind =
  | "retain_request"
  | "recall_request"
  | "recalled_memory"
  | "security_event";

export type QuarantineStatus = "pending" | "postponed" | "reviewed_allowed" | "reviewed_blocked";

export type ReviewReason =
  | "unknown_writer"
  | "suspicious_content"
  | "suspicious_query"
  | "recalled_suspicious_memory"
  | "denied_endpoint"
  | "auth_failed";

export interface QuarantineItemSummary {
  quarantine_id: string;
  created_at: string;
  updated_at: string;
  kind: QuarantineKind;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  source_bank?: string;
  source_memory_id?: string;
  source_content_sha256?: string;
  dedupe_key?: string;
  sha256: string;
  status: QuarantineStatus;
  postpone_count: number;
  requarantine_count: number;
  encrypted_bytes?: number;
  expires_at?: string;
}

export interface QuarantineQueueResponse {
  items: QuarantineItemSummary[];
  total: number;
}

export interface EncryptionMetadata {
  algorithm: string;
  key_wrap: string;
  aad?: string;
  wrapped_key_b64: string;
  iv_b64: string;
  tag_b64: string;
}

export interface EncryptedQuarantineEnvelope {
  version: number;
  quarantine_id: string;
  created_at: string;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  sha256: string;
  encryption: EncryptionMetadata;
  ciphertext_b64: string;
}

export interface QuarantineItemResponse {
  record: QuarantineItemSummary;
  encrypted: EncryptedQuarantineEnvelope;
}

export interface DecryptedQuarantineObject {
  quarantine_id: string;
  created_at: string;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  payload: unknown;
}

export interface QuarantineStats {
  total_items: number;
  pending_items: number;
  postponed_items: number;
  reviewed_allowed_items: number;
  reviewed_blocked_items: number;
  encrypted_bytes: number;
  event_count: number;
}

export interface CleanupRequest {
  scope?: "pending" | "all";
  reasons?: ReviewReason[];
  older_than?: string;
  dry_run?: boolean;
  expected_count?: number;
}

export interface CleanupResponse {
  dry_run: boolean;
  count: number;
  encrypted_bytes: number;
}

export interface RouterError {
  error: string;
  message?: string;
}

export interface VersionResponse {
  version?: string;
  [key: string]: unknown;
}
