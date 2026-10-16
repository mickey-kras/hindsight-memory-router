import { startTransition, useLayoutEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ItemDetail } from "../../src/components/ItemDetail";
import { fetchItem } from "../../src/lib/api";
import type { QuarantineItemSummary } from "../../src/lib/types";

const RETAIN_ID = "q_retain_0123456789abcdef";
const RECALL_ID = "q_recall_aaaabbbbccccdddd";
const tokens = { read: "e2e-read-token", review: "e2e-review-token", cleanup: "e2e-cleanup-token" };
const initial = await fetchItem(tokens, RETAIN_ID);
const next = await fetchItem(tokens, RECALL_ID);
const noop = () => {};

declare global {
  interface Window {
    selectBoundaryItem: () => void;
    boundarySnapshot?: { item: string; payload: string | null };
  }
}

function SelectionBoundary() {
  const [item, setItem] = useState<QuarantineItemSummary>(initial.record);
  useLayoutEffect(() => {
    window.selectBoundaryItem = () => startTransition(() => setItem(next.record));
    if (item !== initial.record) {
      // Observe the committed selection before passive Effects, without a paint delay.
      queueMicrotask(() => {
        window.boundarySnapshot = {
          item: item.quarantine_id,
          payload: document.querySelector('[data-testid="payload"]')?.textContent ?? null,
        };
      });
    }
  }, [item]);
  return <ItemDetail item={item} tokens={tokens} onAction={noop} onClose={noop} onUnauthorized={noop} />;
}

createRoot(document.getElementById("root")!).render(<SelectionBoundary />);
