import { DecryptError, validateEnvelope, verifyReviewedObject } from "./quarantineCrypto";
import type { DecryptedQuarantineObject, EncryptedQuarantineEnvelope } from "./types";

// Fixed loopback target: the console cannot send an envelope to a user-supplied URL.
export const REVIEW_AGENT_URL = "http://127.0.0.1:8765/decrypt";

export async function decryptWithReviewAgent(
  envelope: EncryptedQuarantineEnvelope,
  credential: string,
): Promise<DecryptedQuarantineObject> {
  validateEnvelope(envelope);
  if (credential.length < 32) throw new DecryptError("local review agent credential is required");
  let response: Response;
  try {
    response = await fetch(REVIEW_AGENT_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ envelope }),
      cache: "no-store",
      credentials: "omit",
    });
  } catch {
    throw new DecryptError("local review agent is unavailable");
  }
  if (!response.ok) throw new DecryptError("local review agent rejected decryption");
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new DecryptError("invalid local review agent response");
  }
  if (typeof value !== "object" || value === null || !("decrypted" in value)) {
    throw new DecryptError("invalid local review agent response");
  }
  return verifyReviewedObject(envelope, value.decrypted);
}
