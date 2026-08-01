import { generateKeyPairSync } from "node:crypto";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
  type QuarantineStoreLimits,
} from "../src/quarantine/quarantineStore.js";

export function quarantineKeys(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

export function memoryQuarantine(
  limits: Partial<QuarantineStoreLimits> = {},
) {
  const keys = quarantineKeys();
  const repository = new MemoryQuarantineRepository();
  const store = new EncryptedDatabaseQuarantineStore(
    keys.publicKey,
    repository,
    { ...DEFAULT_QUARANTINE_LIMITS, ...limits },
  );
  return { keys, repository, store };
}
