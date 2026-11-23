// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
  QuarantineKind,
  QuarantineStatus,
} from "../../src/lib/types";

vi.mock("../../src/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/lib/api")>()),
  fetchItem: vi.fn(),
  approveItem: vi.fn(),
  rejectItem: vi.fn(),
  postponeItem: vi.fn(),
  reconcileItem: vi.fn(),
}));
vi.mock("../../src/lib/reviewAgent", () => ({ decryptWithReviewAgent: vi.fn() }));
vi.mock("../../src/lib/quarantineCrypto", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/lib/quarantineCrypto")>()),
  importDecryptionKeyPem: vi.fn(),
  decryptEnvelope: vi.fn(),
}));

const api = await import("../../src/lib/api");
const { decryptWithReviewAgent } = await import("../../src/lib/reviewAgent");
const crypto = await import("../../src/lib/quarantineCrypto");
const { ItemDetail } = await import("../../src/components/ItemDetail");

const KEY = {} as CryptoKey;
const PLAINTEXT = {
  quarantine_id: "q_1",
  created_at: "2026-01-01T00:00:00Z",
  reason: "suspicious_content",
  payload: { text: "secret" },
} as DecryptedQuarantineObject;

function summary(kind: QuarantineKind, status: QuarantineStatus = "pending"): QuarantineItemSummary {
  return {
    quarantine_id: "q_1",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    kind,
    reason: "suspicious_content",
    sha256: "hash",
    status,
    postpone_count: 0,
    requarantine_count: 0,
  };
}

function detail(record: QuarantineItemSummary, provider?: string): QuarantineItemResponse {
  return {
    record,
    encrypted: { encryption: provider === undefined ? {} : { provider } },
  } as unknown as QuarantineItemResponse;
}

function mount(item: QuarantineItemSummary, tokens: "host" | { read: string; review: string; cleanup: string } = "host") {
  const props = { item, tokens, onAction: vi.fn(), onClose: vi.fn(), onUnauthorized: vi.fn() };
  const view = render(createElement(ItemDetail, props));
  return { ...props, view };
}

async function decryptLocally(): Promise<void> {
  fireEvent.change(await screen.findByTestId("key-input"), { target: { value: "PEM" } });
  fireEvent.click(screen.getByTestId("import-key"));
  fireEvent.click(await screen.findByTestId("decrypt"));
  await screen.findByTestId("payload");
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(crypto.importDecryptionKeyPem).mockResolvedValue(KEY);
  vi.mocked(crypto.decryptEnvelope).mockResolvedValue(PLAINTEXT);
});
afterEach(cleanup);

describe("ItemDetail loading", () => {
  it("signs out a host session on 401", async () => {
    vi.mocked(api.fetchItem).mockRejectedValue(new api.ApiError(401, "unauthorized", "expired"));
    const { onUnauthorized } = mount(summary("retain_request"));
    expect(await screen.findByText("unauthorized: expired")).toBeTruthy();
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("reports non-API load failures generically", async () => {
    vi.mocked(api.fetchItem).mockRejectedValue(new Error("network"));
    const { onUnauthorized } = mount(summary("retain_request"), { read: "r", review: "rv", cleanup: "c" });
    expect(await screen.findByText("load failed")).toBeTruthy();
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("ignores a response for a deselected item", async () => {
    let resolve: (value: QuarantineItemResponse) => void = () => {};
    vi.mocked(api.fetchItem).mockReturnValueOnce(new Promise((r) => { resolve = r; }));
    vi.mocked(api.fetchItem).mockReturnValueOnce(new Promise(() => {}));
    const { view, onAction, onClose, onUnauthorized } = mount(summary("retain_request"));
    view.rerender(createElement(ItemDetail, {
      item: { ...summary("retain_request"), quarantine_id: "q_2" },
      tokens: "host", onAction, onClose, onUnauthorized,
    }));
    resolve(detail(summary("retain_request")));
    await Promise.resolve();
    expect(screen.queryByTestId("key-input")).toBeNull();
  });

  it("closes", () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    const { onClose } = mount(summary("retain_request"));
    fireEvent.click(screen.getByLabelText("close detail"));
    expect(onClose).toHaveBeenCalledOnce();
  });
});

describe("ItemDetail decryption", () => {
  it("imports a local key, drops the PEM, and decrypts", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    mount(summary("retain_request"));
    await decryptLocally();
    expect(crypto.importDecryptionKeyPem).toHaveBeenCalledWith("PEM");
    expect(crypto.decryptEnvelope).toHaveBeenCalledWith(expect.anything(), KEY);
    expect(screen.getByTestId("payload").textContent).toContain("secret");
  });

  it.each([
    [new crypto.DecryptError("bad key"), "bad key"],
    [new Error("boom"), "key import failed"],
  ])("reports key import failure %#", async (error, message) => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(crypto.importDecryptionKeyPem).mockRejectedValue(error);
    mount(summary("retain_request"));
    fireEvent.change(await screen.findByTestId("key-input"), { target: { value: "PEM" } });
    fireEvent.click(screen.getByTestId("import-key"));
    expect(await screen.findByText(message)).toBeTruthy();
  });

  it("reports decryption failure", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(crypto.decryptEnvelope).mockRejectedValue(new Error("tampered"));
    mount(summary("retain_request"));
    fireEvent.change(await screen.findByTestId("key-input"), { target: { value: "PEM" } });
    fireEvent.click(screen.getByTestId("import-key"));
    fireEvent.click(await screen.findByTestId("decrypt"));
    expect(await screen.findByText("decryption failed")).toBeTruthy();
  });

  it("decrypts through the opted-in review agent", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(decryptWithReviewAgent).mockResolvedValue(PLAINTEXT);
    mount(summary("retain_request"));
    fireEvent.click(await screen.findByTestId("use-agent"));
    fireEvent.change(screen.getByTestId("agent-credential"), { target: { value: "x".repeat(32) } });
    fireEvent.click(screen.getByTestId("decrypt-agent"));
    await screen.findByTestId("payload");
    expect(decryptWithReviewAgent).toHaveBeenCalledWith(expect.anything(), "x".repeat(32));
  });
});

describe("ItemDetail actions", () => {
  it("approves after decryption and confirmation", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(api.approveItem).mockResolvedValue({});
    const { onAction } = mount(summary("retain_request"));
    await decryptLocally();
    fireEvent.click(screen.getByTestId("approve-open"));
    fireEvent.click(screen.getByTestId("confirm-action"));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith("approved q_1"));
    expect(api.approveItem).toHaveBeenCalledWith("host", "q_1", PLAINTEXT);
  });

  it("cancels a pending confirmation", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    mount(summary("retain_request"));
    fireEvent.click(await screen.findByTestId("reject-open"));
    fireEvent.click(screen.getByText("Cancel"));
    expect(screen.queryByTestId("confirm-bar")).toBeNull();
    expect(api.rejectItem).not.toHaveBeenCalled();
  });

  it("postpones without confirmation", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(api.postponeItem).mockResolvedValue({});
    const { onAction } = mount(summary("retain_request"));
    fireEvent.click(await screen.findByTestId("postpone"));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith("postponed q_1"));
  });

  it.each([
    ["reconcile-applied-open", "confirmed_applied"],
    ["reconcile-not-applied-open", "confirmed_not_applied"],
  ] as const)("reconciles via %s", async (button, action) => {
    const record = summary("retain_request", "review_side_effect_started");
    vi.mocked(api.fetchItem).mockResolvedValue(detail(record));
    vi.mocked(api.reconcileItem).mockResolvedValue({
      reconciled: true, action, quarantine_id: "q_1", status: "approved",
    });
    const { onAction } = mount(record);
    fireEvent.click(await screen.findByTestId(button));
    fireEvent.click(screen.getByTestId("confirm-action"));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith(`reconciled q_1 (${action})`));
  });

  it("surfaces an API failure, resets the confirmation, and signs out on 401", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(api.rejectItem).mockRejectedValue(new api.ApiError(401, "unauthorized", "expired"));
    const { onUnauthorized, onAction } = mount(summary("retain_request"));
    fireEvent.click(await screen.findByTestId("reject-open"));
    fireEvent.click(screen.getByTestId("confirm-action"));
    expect(await screen.findByText("unauthorized: expired")).toBeTruthy();
    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(onAction).not.toHaveBeenCalled();
    expect(screen.queryByTestId("confirm-bar")).toBeNull();
  });

  it("reports non-API action failures generically", async () => {
    vi.mocked(api.fetchItem).mockResolvedValue(detail(summary("retain_request")));
    vi.mocked(api.postponeItem).mockRejectedValue(new Error("network"));
    mount(summary("retain_request"));
    fireEvent.click(await screen.findByTestId("postpone"));
    expect(await screen.findByText("action failed")).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/dismiss/i));
    expect(screen.queryByText("action failed")).toBeNull();
  });
});
