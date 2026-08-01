import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

type SecurityRequirement = Record<string, unknown[]>;

type Operation = {
  operationId?: string;
  description?: string;
  security?: SecurityRequirement[];
  requestBody?: {
    content?: {
      "application/json"?: {
        schema?: { $ref?: string };
      };
    };
  };
};

type OpenApiDocument = {
  openapi: string;
  info: { version: string };
  paths: Record<string, Record<string, Operation>>;
  components: {
    securitySchemes: Record<string, unknown>;
  };
};

const document = JSON.parse(
  readFileSync("openapi/openapi.json", "utf8"),
) as OpenApiDocument;

const expectedOperations = new Map<string, string>([
  ["GET /health", "getHealth"],
  ["GET /version", "getVersion"],
  ["POST /v1/default/banks/{writer_id}/memories", "retainMemory"],
  ["POST /v1/default/banks/{writer_id}/memories/recall", "recallMemory"],
  ["GET /admin/quarantine/queue", "listQuarantineQueue"],
  ["GET /admin/quarantine/stats", "getQuarantineStats"],
  ["POST /admin/quarantine/cleanup", "cleanupQuarantine"],
  ["GET /admin/quarantine/items/{quarantine_id}", "getQuarantineItem"],
  [
    "POST /admin/quarantine/items/{quarantine_id}/approve",
    "approveQuarantineItem",
  ],
  [
    "POST /admin/quarantine/items/{quarantine_id}/reject",
    "rejectQuarantineItem",
  ],
  [
    "POST /admin/quarantine/items/{quarantine_id}/postpone",
    "postponeQuarantineItem",
  ],
]);

function operations(): Map<string, Operation> {
  const result = new Map<string, Operation>();
  for (const [path, pathItem] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (["get", "post", "put", "patch", "delete"].includes(method)) {
        result.set(`${method.toUpperCase()} ${path}`, operation);
      }
    }
  }
  return result;
}

function securityScheme(operation: Operation): string | null {
  const requirement = operation.security?.[0];
  return requirement ? (Object.keys(requirement)[0] ?? null) : null;
}

async function withServer<T>(run: (baseUrl: string) => Promise<T>): Promise<T> {
  const quarantine = memoryQuarantine();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    routerToken: "router-token",
    adminToken: "admin-token",
    hindsight: new FakeHindsightGateway(),
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

describe("OpenAPI contract", () => {
  it("documents exactly the implemented public operations", () => {
    const actual = operations();
    expect([...actual.keys()].sort()).toEqual(
      [...expectedOperations.keys()].sort(),
    );
    for (const [key, operationId] of expectedOperations) {
      expect(actual.get(key)?.operationId).toBe(operationId);
    }
    expect(document.paths).not.toHaveProperty(
      "/admin/quarantine/items/{quarantine_id}/promote",
    );
  });

  it("documents the router and admin authentication boundaries", () => {
    expect(Object.keys(document.components.securitySchemes).sort()).toEqual([
      "AdminToken",
      "RouterToken",
    ]);

    const actual = operations();
    expect(actual.get("GET /health")?.security).toEqual([]);
    expect(securityScheme(actual.get("GET /version") ?? {})).toBe(
      "RouterToken",
    );
    expect(
      securityScheme(
        actual.get("POST /v1/default/banks/{writer_id}/memories") ?? {},
      ),
    ).toBe("RouterToken");
    expect(
      securityScheme(
        actual.get("POST /v1/default/banks/{writer_id}/memories/recall") ?? {},
      ),
    ).toBe("RouterToken");

    for (const [key, operation] of actual) {
      if (key.includes(" /admin/")) {
        expect(securityScheme(operation), key).toBe("AdminToken");
      }
    }
  });

  it("documents exact unchanged-object approval", () => {
    const approve = operations().get(
      "POST /admin/quarantine/items/{quarantine_id}/approve",
    );
    expect(
      approve?.requestBody?.content?.["application/json"]?.schema?.$ref,
    ).toBe("#/components/schemas/ApproveRequest");
    expect(approve?.description).toContain("complete object unchanged");
    expect(approve?.description).toContain("SHA-256");
  });

  it("keeps the documented version aligned with the running router", async () => {
    expect(document.openapi).toBe("3.1.0");
    await withServer(async (baseUrl) => {
      const response = await fetch(`${baseUrl}/version`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { api_version: string };
      expect(document.info.version).toBe(body.api_version);
    });
  });
});
