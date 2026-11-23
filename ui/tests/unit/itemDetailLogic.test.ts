import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
  QuarantineKind,
} from "../../src/lib/types";

vi.mock("../../src/lib/api", () => ({
  approveItem: vi.fn(),
  rejectItem: vi.fn(),
  postponeItem: vi.fn(),
  reconcileItem: vi.fn(),
}));
vi.mock("../../src/lib/reviewAgent", () => ({ decryptWithReviewAgent: vi.fn() }));
vi.mock("../../src/lib/quarantineCrypto", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/lib/quarantineCrypto")>()),
  decryptEnvelope: vi.fn(),
}));

const api = await import("../../src/lib/api");
const { decryptWithReviewAgent } = await import("../../src/lib/reviewAgent");
const { DecryptError, decryptEnvelope } = await import("../../src/lib/quarantineCrypto");
const logic = await import("../../src/components/itemDetailLogic");

const TOKENS = { read: "r", review: "rv", cleanup: "c" };

function summary(
  kind: QuarantineKind,
  overrides: Partial<QuarantineItemSummary> = {},
): QuarantineItemSummary {
  return {
    quarantine_id: "q_1",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    kind,
    reason: "suspicious_content",
    sha256: "summary-hash",
    status: "pending",
    postpone_count: 0,
    requarantine_count: 0,
    ...overrides,
  };
}

function decryptedWith(payload: unknown): DecryptedQuarantineObject {
  return {
    quarantine_id: "q_1",
    created_at: "2026-01-01T00:00:00Z",
    reason: "suspicious_content",
    payload,
  };
}

function detailWith(provider?: string): QuarantineItemResponse {
  return {
    record: summary("retain_request", { sha256: "record-hash", updated_at: "2026-01-03T00:00:00Z" }),
    encrypted: { encryption: provider === undefined ? {} : { provider } },
  } as unknown as QuarantineItemResponse;
}

beforeEach(() => vi.clearAllMocks());

describe("executeAction", () => {
  const plaintext = decryptedWith({});

  it("refuses approval before decryption", async () => {
    const onAction = vi.fn();
    await expect(
      logic.executeAction("approve", {
        tokens: TOKENS, item: summary("retain_request"), detail: null, decrypted: null, onAction,
      }),
    ).rejects.toThrow("decrypt the item before approving");
    expect(api.approveItem).not.toHaveBeenCalled();
    expect(onAction).not.toHaveBeenCalled();
  });

  it.each([
    ["retain_request", {}, "approved q_1"],
    ["blocked_content", { exception_active: true }, "approved exact exception q_1; applies to matching later calls"],
    ["blocked_content", {}, "classified q_1 as false positive; content remains blocked"],
  ] as const)("approves %s with the decrypted object", async (kind, result, message) => {
    vi.mocked(api.approveItem).mockResolvedValue(result);
    const onAction = vi.fn();
    await logic.executeAction("approve", {
      tokens: TOKENS, item: summary(kind), detail: null, decrypted: plaintext, onAction,
    });
    expect(api.approveItem).toHaveBeenCalledWith(TOKENS, "q_1", plaintext);
    expect(onAction).toHaveBeenCalledWith(message);
  });

  it.each([
    ["retain_request", "rejected q_1"],
    ["blocked_content", "classified q_1 as true positive; content remains blocked"],
  ] as const)("rejects %s", async (kind, message) => {
    const onAction = vi.fn();
    await logic.executeAction("reject", {
      tokens: TOKENS, item: summary(kind), detail: null, decrypted: null, onAction,
    });
    expect(api.rejectItem).toHaveBeenCalledWith(TOKENS, "q_1");
    expect(onAction).toHaveBeenCalledWith(message);
  });

  it("postpones", async () => {
    const onAction = vi.fn();
    await logic.executeAction("postpone", {
      tokens: "host", item: summary("retain_request"), detail: null, decrypted: null, onAction,
    });
    expect(api.postponeItem).toHaveBeenCalledWith("host", "q_1");
    expect(onAction).toHaveBeenCalledWith("postponed q_1");
  });

  it.each([
    ["retain_request", { decision: "approve" }],
    ["recalled_memory", { decision: "reject" }],
    ["blocked_content", {}],
  ] as const)("reconciles %s against the freshest record", async (kind, decision) => {
    const onAction = vi.fn();
    await logic.executeAction("confirmed_applied", {
      tokens: TOKENS, item: summary(kind), detail: detailWith(), decrypted: null, onAction,
    });
    expect(api.reconcileItem).toHaveBeenCalledWith(TOKENS, "q_1", {
      action: "confirmed_applied",
      ...decision,
      expected_sha256: "record-hash",
      expected_updated_at: "2026-01-03T00:00:00Z",
    });
    expect(onAction).toHaveBeenCalledWith("reconciled q_1 (confirmed_applied)");
  });

  it("reconciles against the summary when no detail has loaded", async () => {
    await logic.executeAction("confirmed_not_applied", {
      tokens: TOKENS, item: summary("retain_request"), detail: null, decrypted: null, onAction: vi.fn(),
    });
    expect(api.reconcileItem).toHaveBeenCalledWith(TOKENS, "q_1", expect.objectContaining({
      expected_sha256: "summary-hash",
      expected_updated_at: "2026-01-02T00:00:00Z",
    }));
  });
});

describe("decryptItem", () => {
  const key = {} as CryptoKey;
  const plaintext = decryptedWith({});

  it("uses the review agent for provider-backed envelopes", async () => {
    vi.mocked(decryptWithReviewAgent).mockResolvedValue(plaintext);
    const detail = detailWith("pkcs11");
    await expect(logic.decryptItem(detail, {
      useAgent: false, agentCredential: "cred", tokens: "host", localKey: null,
    })).resolves.toBe(plaintext);
    expect(decryptWithReviewAgent).toHaveBeenCalledWith(detail.encrypted, "cred");
    expect(decryptEnvelope).not.toHaveBeenCalled();
  });

  it("uses the review agent when the reviewer opts in", async () => {
    vi.mocked(decryptWithReviewAgent).mockResolvedValue(plaintext);
    await logic.decryptItem(detailWith(), {
      useAgent: true, agentCredential: "cred", tokens: TOKENS, localKey: key,
    });
    expect(decryptWithReviewAgent).toHaveBeenCalled();
    expect(decryptEnvelope).not.toHaveBeenCalled();
  });

  it("requires a review token before calling the agent", async () => {
    await expect(logic.decryptItem(detailWith("pkcs11"), {
      useAgent: false, agentCredential: "cred", tokens: { ...TOKENS, review: "" }, localKey: null,
    })).rejects.toBeInstanceOf(DecryptError);
    expect(decryptWithReviewAgent).not.toHaveBeenCalled();
  });

  it("decrypts locally with an imported key", async () => {
    vi.mocked(decryptEnvelope).mockResolvedValue(plaintext);
    const detail = detailWith();
    await expect(logic.decryptItem(detail, {
      useAgent: false, agentCredential: "", tokens: TOKENS, localKey: key,
    })).resolves.toBe(plaintext);
    expect(decryptEnvelope).toHaveBeenCalledWith(detail.encrypted, key);
  });

  it("returns null without a local key", async () => {
    await expect(logic.decryptItem(detailWith(), {
      useAgent: false, agentCredential: "", tokens: TOKENS, localKey: null,
    })).resolves.toBeNull();
    expect(decryptEnvelope).not.toHaveBeenCalled();
  });
});

describe("payload extraction", () => {
  it.each([
    [null, null, null],
    [decryptedWith("text"), null, null],
    [decryptedWith(null), null, null],
    [decryptedWith({}), null, null],
    [decryptedWith({ joined_text: 1, ordered_payload_json: 2 }), null, null],
    [decryptedWith({ joined_text: "a b", ordered_payload_json: "{}" }), "a b", "{}"],
  ])("extracts review fields from %j", (decrypted, joined, ordered) => {
    expect(logic.extractJoinedText(decrypted)).toBe(joined);
    expect(logic.extractOrderedPayload(decrypted)).toBe(ordered);
  });
});

describe("labels and prompts", () => {
  it.each([
    [true, false, "Finalize approval", "Finalize rejection"],
    [false, true, "Mark false positive", "Mark true positive"],
    [false, false, "Approve", "Reject"],
  ])("labels finalize=%s reviewOnly=%s", (canFinalize, reviewOnly, approve, reject) => {
    expect(logic.approveLabel(canFinalize, reviewOnly)).toBe(approve);
    expect(logic.rejectLabel(canFinalize, reviewOnly)).toBe(reject);
  });

  it("explains why approval is disabled", () => {
    expect(logic.approveTitle(false, true)).toBe("decrypt first");
    expect(logic.approveTitle(true, false)).toBe("review token required");
    expect(logic.approveTitle(true, true)).toBe("");
    expect(logic.reviewTokenTitle(false)).toBe("review token required");
    expect(logic.reviewTokenTitle(true)).toBe("");
  });

  it.each([
    ["approve", true, "Mark this exact finding as false positive?"],
    ["approve", false, "Approve into memory?"],
    ["reject", true, "Mark this finding as true positive?"],
    ["reject", false, "Reject this item?"],
    ["confirmed_applied", false, "Confirm the side effect reached Hindsight?"],
    ["confirmed_not_applied", false, "Confirm the side effect never reached Hindsight?"],
  ] as const)("prompts for %s (reviewOnly=%s)", (action, reviewOnly, prompt) => {
    expect(logic.confirmPrompt(action, reviewOnly)).toContain(prompt);
  });

  it.each([
    ["approve", "Confirm approve", "bg-emerald-600"],
    ["reject", "Confirm reject", "bg-red-600"],
    ["confirmed_applied", "Confirm reconcile", "bg-emerald-600"],
    ["confirmed_not_applied", "Confirm reconcile", "bg-zinc-600"],
  ] as const)("styles the %s confirmation", (action, label, style) => {
    expect(logic.confirmLabel(false, action)).toBe(label);
    expect(logic.confirmLabel(true, action)).toBe("working...");
    expect(logic.confirmButtonClass(action)).toContain(style);
  });
});
