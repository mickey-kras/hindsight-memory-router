import { readFileSync, writeFileSync } from "node:fs";

function updateText(path, update) {
  const current = readFileSync(path, "utf8");
  const next = update(current);
  if (next !== current) writeFileSync(path, next);
}

function replaceOnce(content, before, after, path) {
  if (content.includes(after)) return content;
  if (!content.includes(before)) {
    throw new Error(`expected readiness patch target not found in ${path}`);
  }
  return content.replace(before, after);
}

updateText("src/quarantine/repository.ts", (content) => {
  let next = replaceOnce(
    content,
    "  initialize(): Promise<void>;\n  close(): Promise<void>;",
    "  initialize(): Promise<void>;\n  ping(): Promise<void>;\n  close(): Promise<void>;",
    "src/quarantine/repository.ts",
  );
  next = next.replace(
    /\nexport async function pingQuarantineRepository\([\s\S]*?\n}\n\nexport function toSummary/,
    "\nexport function toSummary",
  );
  return next;
});

updateText("src/quarantine/memoryRepository.ts", (content) =>
  replaceOnce(
    content,
    "  async initialize(): Promise<void> {}\n  async close(): Promise<void> {}",
    "  async initialize(): Promise<void> {}\n  async ping(): Promise<void> {}\n  async close(): Promise<void> {}",
    "src/quarantine/memoryRepository.ts",
  ),
);

updateText("src/quarantine/sqlRepository.ts", (content) =>
  replaceOnce(
    content,
    "  async initialize(): Promise<void> {\n    await initializeSchema(this.database);\n  }\n\n  async close(): Promise<void> {",
    '  async initialize(): Promise<void> {\n    await initializeSchema(this.database);\n  }\n\n  async ping(): Promise<void> {\n    await this.database.get("SELECT 1 AS ready");\n  }\n\n  async close(): Promise<void> {',
    "src/quarantine/sqlRepository.ts",
  ),
);

updateText("src/server.ts", (content) => {
  let next = content.replace(
    'import {\n  pingQuarantineRepository,\n  type QuarantineRepository,\n} from "./quarantine/repository.js";',
    'import type { QuarantineRepository } from "./quarantine/repository.js";',
  );
  next = next.replace(
    "await pingQuarantineRepository(quarantineRepository);",
    "await quarantineRepository.ping();",
  );
  return next;
});

updateText("tests/apiSurface.test.ts", (content) =>
  content.replaceAll(
    'vi.spyOn(repository, "previewCleanup")',
    'vi.spyOn(repository, "ping")',
  ),
);

updateText("tests/openapiContract.test.ts", (content) =>
  replaceOnce(
    content,
    '    expect(actual.get("GET /ready")?.responses).toHaveProperty("503");',
    '    expect(actual.get("GET /ready")?.responses).toHaveProperty("4XX");\n    expect(actual.get("GET /ready")?.responses).toHaveProperty("503");',
    "tests/openapiContract.test.ts",
  ),
);

const openApiPath = "openapi/openapi.json";
const document = JSON.parse(readFileSync(openApiPath, "utf8"));

document.paths["/ready"] = {
  get: {
    operationId: "getReadiness",
    summary: "Check router readiness",
    description:
      "Checks that the quarantine database is reachable without changing state.",
    tags: ["Service"],
    security: [],
    responses: {
      200: {
        description: "Router and quarantine storage are ready.",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/ReadinessResponse" },
          },
        },
      },
      "4XX": {
        description:
          "The HTTP server rejected a malformed client request before invoking the readiness handler.",
      },
      503: {
        description: "Quarantine storage is unavailable.",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/ReadinessResponse" },
          },
        },
      },
    },
  },
};

document.components.schemas.ReadinessResponse = {
  type: "object",
  additionalProperties: false,
  required: ["status", "service"],
  properties: {
    status: { type: "string", enum: ["ready", "not_ready"] },
    service: { type: "string", const: "memory-router" },
  },
};

writeFileSync(openApiPath, `${JSON.stringify(document, null, 2)}\n`);
