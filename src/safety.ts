import type { MemoryItem, RecallResult, RetainBody } from "./types.js";

export interface SafetyFinding {
  matched: string;
  reason:
    | "prompt_injection"
    | "secret_like"
    | "permission_rewrite"
    | "invisible_unicode"
    | "encoded_payload"
    | "split_instruction";
}

export interface SafetyResult {
  safe: boolean;
  findings: SafetyFinding[];
  transformations: Array<"nfkc" | "invisible">;
}

const MAX_CANONICAL_BYTES = 64 * 1024;
const MAX_BASE64_SPANS = 8;
const MAX_BASE64_DECODED_BYTES = 16 * 1024;
const BASE64_CHAR = /^[A-Za-z0-9+/=]$/;
const CANONICAL_BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const RULES: Array<{
  pattern: RegExp;
  matched: string;
  reason: SafetyFinding["reason"];
}> = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
    matched: "ignore previous instructions",
    reason: "prompt_injection",
  },
  {
    pattern: /system\s+prompt/i,
    matched: "system prompt",
    reason: "prompt_injection",
  },
  {
    pattern: /developer\s+message/i,
    matched: "developer message",
    reason: "prompt_injection",
  },
  {
    pattern: /new\s+instructions/i,
    matched: "new instructions",
    reason: "prompt_injection",
  },
  {
    pattern: /you\s+are\s+now/i,
    matched: "you are now",
    reason: "prompt_injection",
  },
  {
    pattern: /write\s+this\s+to\s+memory/i,
    matched: "write this to memory",
    reason: "prompt_injection",
  },
  {
    pattern: /remember\s+this\s+as\s+truth/i,
    matched: "remember this as truth",
    reason: "prompt_injection",
  },
  {
    pattern: /store\s+this\s+as\s+core\s+memory/i,
    matched: "store this as core memory",
    reason: "prompt_injection",
  },
  {
    pattern: /overwrite\s+permissions/i,
    matched: "overwrite permissions",
    reason: "permission_rewrite",
  },
  {
    pattern: /reveal\s+(the\s+)?(secret|token|key)/i,
    matched: "reveal secret",
    reason: "secret_like",
  },
  { pattern: /\bapi[_ -]?key\b/i, matched: "api key", reason: "secret_like" },
  { pattern: /private\s+key/i, matched: "private key", reason: "secret_like" },
  {
    pattern: /BEGIN\s+OPENSSH\s+PRIVATE\s+KEY/i,
    matched: "private key block",
    reason: "secret_like",
  },
  { pattern: /exfiltrate/i, matched: "exfiltrate", reason: "secret_like" },
];

export function scanContent(content: string): SafetyResult {
  return scanFields([content]);
}

export function scanRetainBody(body: RetainBody): SafetyResult {
  return scanFields((body.items ?? []).flatMap(memoryItemFields));
}

export function scanRecallResult(result: RecallResult): SafetyResult {
  return scanFields([result.text]);
}

export function canonicalizeContent(content: string): {
  content: string;
  transformations: Array<"nfkc" | "invisible">;
} {
  const normalized = content.normalize("NFKC");
  const transformations: Array<"nfkc" | "invisible"> = [];
  if (normalized !== content) transformations.push("nfkc");

  let stripped = "";
  let removedInvisible = false;
  for (const character of normalized) {
    if (isInvisible(character)) removedInvisible = true;
    else stripped += character;
  }
  if (removedInvisible) transformations.push("invisible");
  return { content: stripped, transformations };
}

interface ScanState {
  findings: SafetyFinding[];
  transformations: Set<"nfkc" | "invisible">;
  canonicalFields: string[];
  directMatches: Set<string>;
  decodedBytes: number;
  base64Spans: number;
}

function scanFields(fields: readonly string[]): SafetyResult {
  const state: ScanState = {
    findings: [],
    transformations: new Set(),
    canonicalFields: [],
    directMatches: new Set(),
    decodedBytes: 0,
    base64Spans: 0,
  };

  for (const field of fields) scanField(field, state);
  scanSplitRules(state);

  return {
    safe: state.findings.length === 0,
    findings: state.findings,
    transformations: [...state.transformations],
  };
}

function scanSplitRules(state: ScanState): void {
  let window = "";
  for (const field of state.canonicalFields) {
    window = boundedAppend(window, field);
    for (const finding of scanRules(window)) {
      if (!state.directMatches.has(finding.matched)) {
        addFinding(state.findings, {
          matched: finding.matched,
          reason: "split_instruction",
        });
      }
    }
  }
}

function scanField(field: string, state: ScanState): void {
  const canonical = canonicalizeContent(field);
  state.canonicalFields.push(canonical.content);
  canonical.transformations.forEach((value) =>
    state.transformations.add(value),
  );
  if (canonical.transformations.includes("invisible")) {
    addFinding(state.findings, {
      matched: "invisible_unicode",
      reason: "invisible_unicode",
    });
  }

  for (const finding of scanRules(canonical.content)) {
    addFinding(state.findings, finding);
    state.directMatches.add(finding.matched);
  }

  for (const candidate of base64Candidates(canonical.content)) {
    scanBase64Candidate(candidate, state);
    if (state.base64Spans > MAX_BASE64_SPANS) break;
  }
}

function scanBase64Candidate(candidate: string, state: ScanState): void {
  state.base64Spans += 1;
  if (state.base64Spans > MAX_BASE64_SPANS) {
    addFinding(state.findings, {
      matched: "span_limit",
      reason: "encoded_payload",
    });
    return;
  }
  if (!isCanonicalBase64(candidate)) {
    addFinding(state.findings, {
      matched: "invalid_base64",
      reason: "encoded_payload",
    });
    return;
  }

  const decodedLength = decodedBase64Length(candidate);
  if (
    decodedLength > MAX_BASE64_DECODED_BYTES ||
    state.decodedBytes + decodedLength > MAX_BASE64_DECODED_BYTES
  ) {
    addFinding(state.findings, {
      matched: "decoded_size_limit",
      reason: "encoded_payload",
    });
    return;
  }

  const decoded = Buffer.from(candidate, "base64");
  if (decoded.toString("base64") !== candidate) return;
  state.decodedBytes += decoded.length;

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
  } catch {
    addFinding(state.findings, {
      matched: "invalid_utf8",
      reason: "encoded_payload",
    });
    return;
  }

  const decodedCanonical = canonicalizeContent(text);
  decodedCanonical.transformations.forEach((value) =>
    state.transformations.add(value),
  );
  const decodedFindings = scanRules(decodedCanonical.content);
  if (decodedFindings.length === 0) return;
  addFinding(state.findings, {
    matched: "unsafe_base64",
    reason: "encoded_payload",
  });
  decodedFindings.forEach((finding) => addFinding(state.findings, finding));
}

function memoryItemFields(item: MemoryItem): string[] {
  return [
    item.content,
    item.context ?? "",
    item.document_id ?? "",
    ...(item.tags ?? []),
    ...Object.values(item.metadata ?? {}),
  ].filter((value): value is string => typeof value === "string");
}

function scanRules(content: string): SafetyFinding[] {
  return RULES.filter((rule) => rule.pattern.test(content)).map(
    ({ matched, reason }) => ({ matched, reason }),
  );
}

function base64Candidates(content: string): string[] {
  const candidates: string[] = [];
  let current = "";
  const flush = () => {
    if (current.length >= 16 && looksLikeBase64(current)) {
      candidates.push(current);
    }
    current = "";
  };

  for (const character of content) {
    if (BASE64_CHAR.test(character)) current += character;
    else flush();
  }
  flush();
  return candidates;
}

function looksLikeBase64(candidate: string): boolean {
  const mixedCase = /[a-z]/.test(candidate) && /[A-Z]/.test(candidate);
  return /[=+/]/.test(candidate) || (mixedCase && /\d/.test(candidate));
}

function isCanonicalBase64(candidate: string): boolean {
  return candidate.length % 4 === 0 && CANONICAL_BASE64.test(candidate);
}

function decodedBase64Length(candidate: string): number {
  const padding = candidate.endsWith("==")
    ? 2
    : candidate.endsWith("=")
      ? 1
      : 0;
  return (candidate.length / 4) * 3 - padding;
}

function boundedAppend(window: string, field: string): string {
  const characters = [...(window ? `${window} ${field}` : field)];
  let bytes = characters.reduce(
    (total, character) => total + Buffer.byteLength(character, "utf8"),
    0,
  );
  let start = 0;
  while (bytes > MAX_CANONICAL_BYTES && start < characters.length) {
    bytes -= Buffer.byteLength(characters[start] ?? "", "utf8");
    start += 1;
  }
  return characters.slice(start).join("");
}

function isInvisible(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return (
    codePoint === 0x200b ||
    codePoint === 0x200c ||
    codePoint === 0x200d ||
    codePoint === 0x2060 ||
    (codePoint !== undefined && codePoint >= 0xfe00 && codePoint <= 0xfe0f) ||
    (codePoint !== undefined && codePoint >= 0xe0000 && codePoint <= 0xe007f)
  );
}

function addFinding(findings: SafetyFinding[], finding: SafetyFinding): void {
  if (
    !findings.some(
      (candidate) =>
        candidate.reason === finding.reason &&
        candidate.matched === finding.matched,
    )
  ) {
    findings.push(finding);
  }
}
