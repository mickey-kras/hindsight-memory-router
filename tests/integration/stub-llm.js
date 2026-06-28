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

createServer(async (req, res) => {
  try {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`);

    if (method === "GET" && ["/health", "/api/tags"].includes(url.pathname)) {
      return send(res, 200, { models: [{ name: "ci-stub" }] });
    }

    if (method === "POST" && url.pathname === "/v1/chat/completions") {
      const body = await readJson(req);
      const text = textFromMessages(body.messages);
      return send(res, 200, {
        id: "ci-chat",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: `CI extracted fact: ${text}`,
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
        model: body.model ?? "ci-stub",
      });
    }

    if (method === "POST" && url.pathname === "/api/embeddings") {
      return send(res, 200, { embedding: embedding() });
    }

    if (method === "POST" && url.pathname === "/api/embed") {
      const body = await readJson(req);
      return send(res, 200, {
        model: body.model ?? "ci-stub",
        embeddings: inputList(body.input).map(() => embedding()),
      });
    }

    if (method === "POST" && url.pathname === "/api/chat") {
      const body = await readJson(req);
      return send(res, 200, {
        model: body.model ?? "ci-stub",
        done: true,
        message: {
          role: "assistant",
          content: `CI extracted fact: ${textFromMessages(body.messages)}`,
        },
      });
    }

    if (method === "POST" && url.pathname === "/api/generate") {
      const body = await readJson(req);
      return send(res, 200, {
        model: body.model ?? "ci-stub",
        done: true,
        response: `CI extracted fact: ${body.prompt ?? "memory"}`,
      });
    }

    return send(res, 404, { error: "not found" });
  } catch {
    return send(res, 500, { error: "internal error" });
  }
}).listen(PORT, () => {
  process.stdout.write(`stub-llm listening on ${PORT}\n`);
});
