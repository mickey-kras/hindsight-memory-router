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

const readmePath = "README.md";
const readme = await readFile(readmePath, "utf8");
const oldMigration = `1. Generate independent read, review, and cleanup tokens.
2. Configure the scoped tokens while temporarily retaining the legacy admin token.
3. Update each admin client to use only the token matching its responsibilities.
4. Unset \`MEMORY_ROUTER_ADMIN_TOKEN\` and restart the router.
5. Rotate any individual scoped token without changing the others.
6. Review quarantine events if compromise is suspected.`;
const newMigration = `1. Generate independent read, review, and cleanup tokens.
2. Configure the scoped tokens while temporarily retaining the legacy admin token, then restart the router.
3. Update each admin client to use only the token matching its responsibilities.
4. Verify every scoped client works and confirm the startup warning still reports the legacy migration superuser as active.
5. Unset \`MEMORY_ROUTER_ADMIN_TOKEN\` and restart the router again.
6. Rotate any individual scoped token without changing the others.
7. Review quarantine events if compromise is suspected.`;
if (!readme.includes(oldMigration) && !readme.includes(newMigration)) {
  throw new Error("README admin token migration block is missing");
}
await writeFile(readmePath, readme.replace(oldMigration, newMigration));
