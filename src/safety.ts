import { createHash } from "node:crypto";

export interface SafetyFinding {
  matched: string;
  reason: "prompt_injection" | "secret_like" | "permission_rewrite";
}

export interface SafetyResult {
  safe: boolean;
  findings: SafetyFinding[];
}

const RULES: Array<{ pattern: RegExp; matched: string; reason: SafetyFinding["reason"] }> = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, matched: "ignore previous instructions", reason: "prompt_injection" },
  { pattern: /system\s+prompt/i, matched: "system prompt", reason: "prompt_injection" },
  { pattern: /developer\s+message/i, matched: "developer message", reason: "prompt_injection" },
  { pattern: /new\s+instructions/i, matched: "new instructions", reason: "prompt_injection" },
  { pattern: /you\s+are\s+now/i, matched: "you are now", reason: "prompt_injection" },
  { pattern: /write\s+this\s+to\s+memory/i, matched: "write this to memory", reason: "prompt_injection" },
  { pattern: /remember\s+this\s+as\s+truth/i, matched: "remember this as truth", reason: "prompt_injection" },
  { pattern: /store\s+this\s+as\s+core\s+memory/i, matched: "store this as core memory", reason: "prompt_injection" },
  { pattern: /overwrite\s+permissions/i, matched: "overwrite permissions", reason: "permission_rewrite" },
  { pattern: /reveal\s+(the\s+)?(secret|token|key)/i, matched: "reveal secret", reason: "secret_like" },
  { pattern: /\bapi[_ -]?key\b/i, matched: "api key", reason: "secret_like" },
  { pattern: /private\s+key/i, matched: "private key", reason: "secret_like" },
  { pattern: /BEGIN\s+OPENSSH\s+PRIVATE\s+KEY/i, matched: "private key block", reason: "secret_like" },
  { pattern: /exfiltrate/i, matched: "exfiltrate", reason: "secret_like" },
];

export function scanContent(content: string): SafetyResult {
  const findings = RULES.filter((rule) => rule.pattern.test(content)).map(({ matched, reason }) => ({ matched, reason }));
  return { safe: findings.length === 0, findings };
}

export function safePreview(content: string, maxChars = 300): string {
  return content.replace(/\s+/g, " ").trim().slice(0, maxChars);
}

export function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}
