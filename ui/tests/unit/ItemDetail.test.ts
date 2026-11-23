import { createElement, type FunctionComponent } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  ActionBar,
  ActionButtons,
  ConfirmBar,
  DecryptControls,
  DecryptedView,
  ItemDetail,
  ItemMetadata,
} from "../../src/components/ItemDetail";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
  QuarantineKind,
} from "../../src/lib/types";

describe("completed checkpoint controls", () => {
  function render(kind: QuarantineKind, overrides: Partial<QuarantineItemSummary> = {}) {
    const item: QuarantineItemSummary = {
      quarantine_id: "q_retain_0123456789abcdef",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      kind,
      reason: "suspicious_content",
      sha256: "hash",
      status: "review_side_effect_completed",
      postpone_count: 0,
      requarantine_count: 0,
      expires_at: "2000-01-01T00:00:00Z",
      ...overrides,
    };
    return renderToStaticMarkup(createElement(ItemDetail, {
      item, tokens: "host", onAction: () => {}, onClose: () => {}, onUnauthorized: () => {},
    }));
  }

  it("requires decryption to finalize retain approval and offers no other action", () => {
    const html = render("retain_request");
    expect(html).toContain("Finalize approval");
    expect(html).toMatch(/disabled=""[^>]*data-testid="approve-open"/);
    expect(html).not.toContain('data-testid="reject-open"');
    expect(html).not.toContain('data-testid="postpone"');
    expect(html).not.toContain('data-testid="reconcile-');
  });

  it("offers only finalization of recalled-memory rejection", () => {
    const html = render("recalled_memory");
    expect(html).toContain("Finalize rejection");
    expect(html).not.toContain('data-testid="approve-open"');
    expect(html).not.toContain('data-testid="postpone"');
    expect(html).not.toContain('data-testid="reconcile-');
  });

  it("explains exact later-call approval without offering a memory action", () => {
    const html = render("blocked_content", { status: "pending" });
    expect(html).toContain("Mark false positive");
    expect(html).toContain("Mark true positive");
    expect(html).toContain("this exact content on later calls");
    expect(html).toMatch(/disabled=""[^>]*data-testid="approve-open"/);
    expect(html).not.toContain("Approve into memory");
  });

  it("shows audit context without decryption or an approval action", () => {
    const html = render("security_event", {
      status: "pending", reason: "denied_endpoint", audit_summary: "POST /v1/default/banks/{bank}/unknown",
    });
    expect(html).toContain('data-testid="audit-summary"');
    expect(html).toContain("POST /v1/default/banks/{bank}/unknown");
    expect(html).not.toContain('data-testid="approve-open"');
  });
});

describe("ItemDetail subcomponents", () => {
  const noop = () => {};
  const html = <P extends object>(type: FunctionComponent<P>, props: P): string =>
    renderToStaticMarkup(createElement(type, props));
  const buttons = {
    canReview: false, canApprove: false, canReject: false, canReconcile: false, canFinalize: false,
    reviewOnly: false, supportsApproval: true, hasDecrypted: true, authorized: true, busy: false,
    onOpenAction: noop, onRunAction: noop,
  };

  it("hides the action bar when no action applies", () => {
    expect(html(ActionBar, { ...buttons, visible: false, pendingAction: null, onCancel: noop })).toBe("");
  });

  it("shows the confirmation instead of buttons while an action is pending", () => {
    const out = html(ActionBar, { ...buttons, visible: true, canReview: true, pendingAction: "reject", onCancel: noop });
    expect(out).toContain('data-testid="confirm-bar"');
    expect(out).toContain("Reject this item?");
    expect(out).not.toContain('data-testid="postpone"');
  });

  it("offers review actions for pending items", () => {
    const out = html(ActionButtons, { ...buttons, canReview: true });
    for (const id of ["approve-open", "reject-open", "postpone"]) expect(out).toContain(`data-testid="${id}"`);
    expect(out).not.toContain("reconcile-");
  });

  it("omits approval for kinds without an approval path", () => {
    const out = html(ActionButtons, { ...buttons, canReview: true, supportsApproval: false });
    expect(out).not.toContain('data-testid="approve-open"');
    expect(out).toContain('data-testid="reject-open"');
  });

  it("disables review actions without a review token", () => {
    const out = html(ActionButtons, { ...buttons, canReview: true, authorized: false });
    expect(out).toContain('title="review token required"');
    expect(out).toMatch(/disabled=""[^>]*data-testid="postpone"/);
  });

  it("offers only reconciliation for started side effects", () => {
    const out = html(ActionButtons, { ...buttons, canReconcile: true, authorized: false });
    expect(out).toMatch(/disabled=""[^>]*data-testid="reconcile-applied-open"/);
    expect(out).toContain('data-testid="reconcile-not-applied-open"');
    expect(out).not.toContain('data-testid="postpone"');
  });

  it("disables confirmation while busy", () => {
    const out = html(ConfirmBar, { pendingAction: "approve", reviewOnly: false, busy: true, onConfirm: noop, onCancel: noop });
    expect(out).toContain("working...");
    expect(out).toMatch(/disabled=""[^>]*data-testid="confirm-action"/);
  });

  it("shows review fields only for review-only items", () => {
    const decrypted = { quarantine_id: "q_1", payload: { joined_text: "joined" } } as unknown as DecryptedQuarantineObject;
    const review = html(DecryptedView, { reviewOnly: true, orderedPayload: "{\"a\":1}", joinedText: "joined", decrypted });
    expect(review).toContain('data-testid="ordered-payload"');
    expect(review).toContain('data-testid="joined-text"');
    const plain = html(DecryptedView, { reviewOnly: false, orderedPayload: "{}", joinedText: "joined", decrypted });
    expect(plain).not.toContain('data-testid="ordered-payload"');
    expect(plain).not.toContain('data-testid="joined-text"');
    expect(plain).toContain("q_1");
  });

  const controls = {
    useAgent: false, setUseAgent: noop, agentCredential: "", setAgentCredential: noop,
    keyPem: "", setKeyPem: noop, keyLoaded: false, busy: false, authorized: true,
    onImport: noop, onDecrypt: noop,
  };
  const localDetail = { encrypted: { encryption: {} } } as unknown as QuarantineItemResponse;

  it("asks for a key before local decryption", () => {
    const out = html(DecryptControls, { ...controls, detail: localDetail, needsAgent: false });
    expect(out).toContain('data-testid="key-input"');
    expect(out).toMatch(/disabled=""[^>]*data-testid="import-key"/);
    expect(out).toContain('data-testid="use-agent"');
    expect(out).toContain("Paste the quarantine decryption key");
  });

  it("decrypts locally once the key is imported", () => {
    const out = html(DecryptControls, { ...controls, detail: localDetail, needsAgent: false, keyLoaded: true });
    expect(out).toContain('data-testid="decrypt"');
    expect(out).not.toContain('data-testid="key-input"');
    expect(out).toContain("Decryption key imported");
  });

  it("uses only the review agent for provider-backed envelopes", () => {
    const out = html(DecryptControls, {
      ...controls, detail: { encrypted: { encryption: { provider: "pkcs11" } } } as unknown as QuarantineItemResponse,
      needsAgent: true,
      agentCredential: "x".repeat(32),
    });
    expect(out).toContain('data-testid="agent-credential"');
    expect(out).not.toMatch(/disabled=""[^>]*data-testid="decrypt-agent"/);
    expect(out).not.toContain('data-testid="use-agent"');
    expect(out).not.toContain('data-testid="key-input"');
  });

  it("requires a full-length agent credential", () => {
    const out = html(DecryptControls, { ...controls, detail: localDetail, needsAgent: true, useAgent: true, agentCredential: "short" });
    expect(out).toMatch(/disabled=""[^>]*data-testid="decrypt-agent"/);
  });

  it("lists optional metadata only when present", () => {
    const item: QuarantineItemSummary = {
      quarantine_id: "q_meta", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
      kind: "recalled_memory", reason: "suspicious_content", sha256: "h", status: "pending",
      postpone_count: 1, requarantine_count: 2,
    };
    const bare = html(ItemMetadata, { item, record: item, onClose: noop });
    expect(bare).not.toContain("Writer");
    expect(bare).not.toContain("Encrypted size");
    const full: QuarantineItemSummary = {
      ...item, writer_id: "w1", source: "openclaw", source_bank: "b1", source_memory_id: "m1",
      encrypted_bytes: 2048, expires_at: "2026-02-01T00:00:00Z",
    };
    const out = html(ItemMetadata, { item: full, record: full, onClose: noop });
    for (const label of ["Writer", "Source", "Source bank", "Source memory", "Encrypted size", "Expires"]) {
      expect(out).toContain(`>${label}<`);
    }
  });
});
