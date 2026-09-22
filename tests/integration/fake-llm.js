import { Buffer } from "node:buffer";
import { createServer } from "node:http";
import process from "node:process";
import { URL } from "node:url";

const PORT = Number(process.env.PORT ?? "11434");
const EMBEDDING_DIM = 384;

function send(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function embedding() {
  return Array.from({ length: EMBEDDING_DIM }, (_, index) =>
    index === 0 ? 1 : 0,
  );
}

function textFromMessages(messages) {
  if (!Array.isArray(messages)) return "CI smoke memory fact.";
  const last = [...messages].reverse().find((item) => item?.content);
  return typeof last?.content === "string"
    ? last.content
    : "CI smoke memory fact.";
}

function inputList(input) {
  return Array.isArray(input) ? input : [input ?? ""];
}

// Hindsight 0.10.x drives structured work through schema-constrained calls:
// retain/consolidation use response_format (ollama native "format"), and
// reflect runs an agentic tool loop over the OpenAI-compatible endpoint. The
// fake must answer both protocols or every structured call retries and fails.
function resolveRef(schema, root) {
  let current = schema;
  const seen = new Set();
  while (current && typeof current === "object" && typeof current.$ref === "string" && !seen.has(current.$ref)) {
    seen.add(current.$ref);
    const ref = current.$ref;
    if (!ref.startsWith("#/")) return {};
    current = ref
      .slice(2)
      .split("/")
      .reduce((node, key) => (node && typeof node === "object" ? node[key] : undefined), root);
  }
  return current && typeof current === "object" ? current : {};
}

function minimalInstance(schema, root, depth = 0) {
  if (!schema || typeof schema !== "object" || depth > 8) return {};
  const resolved = resolveRef(schema, root ?? schema);
  if (resolved.const !== undefined) return resolved.const;
  if (Array.isArray(resolved.enum) && resolved.enum.length > 0) return resolved.enum[0];
  for (const combiner of ["anyOf", "oneOf"]) {
    if (Array.isArray(resolved[combiner]) && resolved[combiner].length > 0) {
      return minimalInstance(resolved[combiner][0], root ?? schema, depth + 1);
    }
  }
  const type = Array.isArray(resolved.type)
    ? (resolved.type.find((entry) => entry !== "null") ?? "null")
    : resolved.type;
  if (type === "string" || (!type && !resolved.properties && resolved.enum === undefined && resolved.const === undefined && typeof resolved.minLength === "number")) {
    const min = typeof resolved.minLength === "number" ? resolved.minLength : 1;
    let value = "ci";
    while (value.length < min) value += "i";
    return value;
  }
  if (type === "integer" || type === "number") {
    if (typeof resolved.minimum === "number") return resolved.minimum;
    if (typeof resolved.exclusiveMinimum === "number") return resolved.exclusiveMinimum + 1;
    return 1;
  }
  if (type === "boolean") return false;
  if (type === "null") return null;
  if (type === "array" || resolved.items) {
    const min = typeof resolved.minItems === "number" ? resolved.minItems : 0;
    const item = minimalInstance(resolved.items ?? {}, root ?? schema, depth + 1);
    return Array.from({ length: Math.min(min, 2) }, () => item);
  }
  // Object: emit every required key; when nothing is required, emit all
  // declared properties so loose schemas still validate end to end.
  const properties = resolved.properties && typeof resolved.properties === "object" ? resolved.properties : {};
  const required = Array.isArray(resolved.required) ? resolved.required : Object.keys(properties);
  const output = {};
  for (const key of required) {
    if (Object.hasOwn(properties, key)) {
      output[key] = minimalInstance(properties[key], root ?? schema, depth + 1);
    }
  }
  return output;
}

function schemaContent(schema, messages) {
  const output = minimalInstance(schema ?? { type: "object" });
  const marker = textFromMessages(messages).match(/\bCI_SMOKE_[A-Za-z0-9_]+\b/)?.[0];
  const factSchema = resolveRef(schema?.properties?.facts?.items, schema);
  if (marker && factSchema.properties?.what && factSchema.properties?.fact_type) {
    output.facts = [{
      what: `The integration smoke retained marker ${marker}.`,
      when: "N/A",
      where: "N/A",
      who: "N/A",
      why: "N/A",
      fact_type: "world",
    }];
  }
  return JSON.stringify(output);
}

// Free-form answers are a fixed benign fact, never a prompt echo. Hindsight's
// own prompts carry meta-instructions (for example the phrase "system prompt"
// in the reflect final-synthesis instructions) that the router response
// scanner must keep blocking; a parroting fake would trip that gate and block
// every reflect response in CI. Real models do not recite their prompts.
const CI_FACT = "CI extracted fact: the release test project uses Python and TypeScript.";

function toolArguments(definition, messages) {
  const parameters = definition?.parameters && typeof definition.parameters === "object" ? definition.parameters : {};
  const args = minimalInstance(parameters);
  const text = textFromMessages(messages).slice(0, 200);
  const properties = parameters.properties ?? {};
  for (const key of Object.keys(properties)) {
    const lowered = key.toLowerCase();
    if (lowered === "answer" || lowered === "text" || lowered === "response") {
      args[key] = `CI reflect answer: ${text}`;
    } else if (lowered === "query" || lowered === "search_query" || lowered.endsWith("query")) {
      args[key] = text;
    }
  }
  return args;
}

function chatCompletionWithToolCall(body) {
  const tools = Array.isArray(body.tools) ? body.tools : [];
  const declared = tools.filter((tool) => tool?.type === "function" && typeof tool?.function?.name === "string");
  // A single declared tool means the caller narrowed the list to force it.
  // With the full list open, close the loop immediately via the done tool so
  // the reflect agent never depends on model judgement.
  const chosen =
    declared.length === 1
      ? declared[0]
      : (declared.find((tool) => tool.function.name === "done") ?? declared[0]);
  if (!chosen) return null;
  return {
    id: "ci-chat",
    object: "chat.completion",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_ci_1",
              type: "function",
              function: {
                name: chosen.function.name,
                arguments: JSON.stringify(toolArguments(chosen.function, body.messages)),
              },
            },
          ],
        },
        finish_reason: "tool_calls",
      },
    ],
  };
}

createServer(async (req, res) => {
  try {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`);

    if (method === "GET" && ["/health", "/api/tags"].includes(url.pathname)) {
      return send(res, 200, { models: [{ name: "ci-fake" }] });
    }

    if (method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = await readJson(req);
      if (Array.isArray(body.tools) && body.tools.length > 0) {
        const completion = chatCompletionWithToolCall(body);
        if (completion) return send(res, 200, completion);
      }
      const responseFormat = body.response_format;
      if (responseFormat && typeof responseFormat === "object") {
        const schema =
          responseFormat.type === "json_schema" ? responseFormat.json_schema?.schema : null;
        return send(res, 200, {
          id: "ci-chat",
          object: "chat.completion",
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: schemaContent(schema, body.messages) },
              finish_reason: "stop",
            },
          ],
        });
      }
      return send(res, 200, {
        id: "ci-chat",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: CI_FACT,
            },
            finish_reason: "stop",
          },
        ],
      });
    }

    if (method === "POST" && url.pathname === "/v1/embeddings") {
      const body = await readJson(req);
      return send(res, 200, {
        object: "list",
        data: inputList(body.input).map((_, index) => ({
          object: "embedding",
          index,
          embedding: embedding(),
        })),
        model: body.model ?? "ci-fake",
      });
    }

    if (method === "POST" && url.pathname === "/api/embeddings") {
      return send(res, 200, { embedding: embedding() });
    }

    if (method === "POST" && url.pathname === "/api/embed") {
      const body = await readJson(req);
      return send(res, 200, {
        model: body.model ?? "ci-fake",
        embeddings: inputList(body.input).map(() => embedding()),
      });
    }

    if (method === "POST" && url.pathname === "/api/chat") {
      const body = await readJson(req);
      const content = body.format ? schemaContent(body.format, body.messages) : CI_FACT;
      return send(res, 200, {
        model: body.model ?? "ci-fake",
        done: true,
        message: {
          role: "assistant",
          content,
        },
      });
    }

    if (method === "POST" && url.pathname === "/api/generate") {
      const body = await readJson(req);
      return send(res, 200, {
        model: body.model ?? "ci-fake",
        done: true,
        response: CI_FACT,
      });
    }

    return send(res, 404, { error: "not found" });
  } catch {
    return send(res, 500, { error: "internal error" });
  }
}).listen(PORT, () => {
  process.stdout.write(`fake-llm listening on ${PORT}\n`);
});
