import { readFile, writeFile } from "node:fs/promises";

const openApiPath = "openapi/openapi.json";
const document = JSON.parse(await readFile(openApiPath, "utf8"));

const admin = document.components?.securitySchemes?.AdminToken;
if (!admin) throw new Error("OpenAPI AdminToken scheme is missing");
admin.description =
  "Bearer credential authorized for the requested admin capability: read or review for admin reads, review for approve/reject/postpone, cleanup for cleanup, or the legacy migration superuser.";

const tag = document.tags?.find(
  (entry) => entry.name === "Quarantine administration",
);
if (!tag) throw new Error("OpenAPI quarantine administration tag is missing");
tag.description =
  "Capability-scoped manual review operations. Use read, review, or cleanup credentials according to the endpoint; the legacy admin credential is migration-only.";

await writeFile(openApiPath, `${JSON.stringify(document, null, 2)}\n`);
