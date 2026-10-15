import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ItemDetail } from "../../src/components/ItemDetail";
import type { QuarantineItemSummary, QuarantineKind } from "../../src/lib/types";

describe("completed checkpoint controls", () => {
  function render(kind: QuarantineKind) {
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
});
