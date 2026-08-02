import { readFileSync, writeFileSync } from "node:fs";

const path = "openapi/openapi.json";
const document = JSON.parse(readFileSync(path, "utf8"));

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

writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`);
