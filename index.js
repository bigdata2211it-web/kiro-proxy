const http = require("http");
const https = require("https");
const crypto = require("crypto");
const path = require("path");
const os = require("os");
const Database = require("better-sqlite3");
const systemInstructions = require("./system-instructions");

const PORT = parseInt(process.env.KIRO_PROXY_PORT || "11436");
const HOST = "q.us-east-1.amazonaws.com";

// ─────────────────────────────────────────────────────────────
// Retry / fallback config
// ─────────────────────────────────────────────────────────────
const RETRY_MAX = parseInt(process.env.KIRO_RETRY_MAX || "5");
const RETRY_BASE_MS = parseInt(process.env.KIRO_RETRY_BASE_MS || "800");
const RETRY_CAP_MS = parseInt(process.env.KIRO_RETRY_CAP_MS || "8000");
// Если модель throttled N раз подряд — переключаемся на следующую в цепочке
const FALLBACK_AFTER = parseInt(process.env.KIRO_FALLBACK_AFTER || "2");

function parseFallbackChain(raw) {
  if (!raw) return null;
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}
const USER_FALLBACK = parseFallbackChain(process.env.KIRO_FALLBACK_MODELS);

// Default fallback chains — проверенные. Если модель throttled — следующая.
const DEFAULT_FALLBACK = {
  "claude-opus-4.7":   ["claude-opus-4.7", "claude-opus-4.6", "claude-sonnet-4.6", "auto"],
  "claude-opus-4.6":   ["claude-opus-4.6", "claude-opus-4.5", "claude-sonnet-4.6", "auto"],
  "claude-opus-4.5":   ["claude-opus-4.5", "claude-sonnet-4.5", "claude-sonnet-4.6", "auto"],
  "claude-sonnet-4.6": ["claude-sonnet-4.6", "claude-sonnet-4.5", "claude-sonnet-4", "auto"],
  "claude-sonnet-4.5": ["claude-sonnet-4.5", "claude-sonnet-4", "claude-sonnet-4.6", "auto"],
  "claude-sonnet-4":   ["claude-sonnet-4", "claude-sonnet-4.5", "auto"],
  "claude-haiku-4.5":  ["claude-haiku-4.5", "claude-haiku-4", "claude-sonnet-4.6", "auto"],
  "claude-haiku-4":    ["claude-haiku-4", "claude-haiku-4.5", "auto"],
  "auto":              ["auto", "claude-sonnet-4.6", "claude-haiku-4.5"]
};

function fallbackFor(model) {
  if (USER_FALLBACK && USER_FALLBACK.length) return USER_FALLBACK;
  return DEFAULT_FALLBACK[model] || [model];
}

// Sleep helper
const sleep = ms => new Promise(r => setTimeout(r, ms));
function backoff(attempt) {
  const exp = Math.min(RETRY_CAP_MS, RETRY_BASE_MS * Math.pow(2, attempt));
  return Math.floor(exp / 2 + Math.random() * (exp / 2));
}

// Распознаём транзиентные/capacity ошибки, на которых имеет смысл ретрай/фоллбэк
function classifyError(statusCode, body) {
  if (statusCode === 429) return { retryable: true, capacity: true, reason: "429" };
  if (statusCode >= 500 && statusCode <= 599) return { retryable: true, capacity: false, reason: `${statusCode}` };
  if (statusCode === 400) {
    try {
      const j = JSON.parse(body);
      const t = (j.__type || j.type || "").toLowerCase();
      const r = (j.reason || "").toLowerCase();
      const m = (j.message || "").toLowerCase();
      if (t.includes("throttling") || t.includes("throttle")) return { retryable: true, capacity: true, reason: "throttling" };
      if (r.includes("insufficient_model_capacity") || m.includes("insufficient_model_capacity")) return { retryable: true, capacity: true, reason: "capacity" };
      if (m.includes("high traffic") || m.includes("try again")) return { retryable: true, capacity: true, reason: "traffic" };
    } catch {}
  }
  return { retryable: false, capacity: false, reason: "hard" };
}

// ─────────────────────────────────────────────────────────────
// Kiro DB / token
// ─────────────────────────────────────────────────────────────
const DB_PATH = process.env.KIRO_DB_PATH || (() => {
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  if (process.platform === "win32") {
    return path.join(process.env.APPDATA || path.join(home, "AppData", "Roaming"), "kiro-cli", "data.sqlite3");
  }
  if (process.platform === "darwin") {
    const xdg = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
    return path.join(xdg, "kiro-cli", "data.sqlite3");
  }
  const xdg = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
  return path.join(xdg, "kiro-cli", "data.sqlite3");
})();

function kiroOsName() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "darwin") return "macos";
  return "linux";
}

const DUMP_DIR = process.env.KIRO_DUMP_DIR || os.tmpdir();

function getToken() {
  const db = new Database(DB_PATH, { readonly: true });
  const row = db.prepare("SELECT value FROM auth_kv WHERE key='kirocli:social:token'").get();
  db.close();
  if (!row) throw new Error("No token in Kiro DB. Run: kiro-cli login");
  return JSON.parse(row.value);
}

// ─────────────────────────────────────────────────────────────
// AWS Event Stream parser
// ─────────────────────────────────────────────────────────────
class EventStreamParser {
  constructor() { this.buf = Buffer.alloc(0); }

  feed(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    const events = [];
    while (this.buf.length >= 12) {
      const totalLen = this.buf.readUInt32BE(0);
      if (this.buf.length < totalLen) break;

      const headersLen = this.buf.readUInt32BE(4);
      const headerEnd = 12 + headersLen;
      const payloadEnd = totalLen - 4;

      let hp = 12;
      const headers = {};
      while (hp < headerEnd) {
        const nl = this.buf[hp++];
        const name = this.buf.slice(hp, hp + nl).toString(); hp += nl;
        const vt = this.buf[hp++];
        if (vt === 7) {
          const vl = this.buf.readUInt16BE(hp); hp += 2;
          headers[name] = this.buf.slice(hp, hp + vl).toString(); hp += vl;
        } else break;
      }
      events.push({ type: headers[":event-type"], payload: this.buf.slice(headerEnd, payloadEnd).toString() });
      this.buf = this.buf.slice(totalLen);
    }
    return events;
  }
}

const VALID_MODELS = new Set([
  "auto","claude-opus-4.7","claude-opus-4.6","claude-sonnet-4.6","claude-opus-4.5",
  "claude-sonnet-4.5","claude-sonnet-4","claude-haiku-4.5","claude-haiku-4",
  "deepseek-3.2","minimax-m2.5","minimax-m2.1","qwen3-coder-next","glm-5"
]);

function normalizeModel(m) {
  if (!m) return "auto";
  if (VALID_MODELS.has(m)) return m;
  if (/opus.*4\.?7/i.test(m)) return "claude-opus-4.7";
  if (/opus.*4\.?6/i.test(m)) return "claude-opus-4.6";
  if (/opus.*4\.?5/i.test(m)) return "claude-opus-4.5";
  if (/opus/i.test(m)) return "claude-opus-4.7";
  if (/sonnet.*4\.?6/i.test(m)) return "claude-sonnet-4.6";
  if (/sonnet.*4\.?5/i.test(m)) return "claude-sonnet-4.5";
  if (/sonnet/i.test(m)) return "claude-sonnet-4.6";
  if (/haiku/i.test(m)) return "claude-haiku-4.5";
  if (/deepseek/i.test(m)) return "deepseek-3.2";
  if (/qwen/i.test(m)) return "qwen3-coder-next";
  if (/glm/i.test(m)) return "glm-5";
  if (/minimax/i.test(m)) return "minimax-m2.5";
  return "auto";
}

function openaiToolsToKiro(tools) {
  if (!tools || !tools.length) return undefined;
  return tools.map(t => {
    const fn = t.function || t;
    return { toolSpecification: { name: fn.name, description: fn.description || "", inputSchema: { json: fn.parameters || { type: "object", properties: {} } } } };
  });
}

function flattenContent(c) {
  if (typeof c === "string") return c;
  if (!Array.isArray(c)) return "";
  return c.map(x => typeof x === "string" ? x : (x.type === "text" ? x.text : "")).join("\n");
}

function tryParseJson(s) { try { return JSON.parse(s); } catch { return { result: s }; } }

function normalizeToolUseId(id) {
  if (!id) return `tooluse_${crypto.randomBytes(10).toString("hex")}`;
  if (id.startsWith("tooluse_")) return id;
  const stripped = id.replace(/^(toolu_|call_|tool_)/, "");
  return `tooluse_${stripped}`;
}

function lastAssistantToolIds(history) {
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i];
    if (h.assistantResponseMessage?.toolUses?.length) {
      return new Set(h.assistantResponseMessage.toolUses.map(t => t.toolUseId));
    }
    if (h.assistantResponseMessage) break;
  }
  return new Set();
}

function filterOrphanToolResults(results, validIds) {
  return results.filter(r => validIds.has(r.toolUseId));
}

function openaiToKiro(body, overrideModel, instructionsHeader) {
  const { messages, tools: openaiTools } = body;
  const model = overrideModel || normalizeModel(body.model);
  const history = [];
  let systemPrompt = "";
  let pendingToolResults = [];
  let pendingUserMessage = null;
  let pendingAssistantMessage = null;

  for (const msg of messages) {
    if (msg.role === "system") systemPrompt += flattenContent(msg.content) + "\n";
  }
  // Apply extra system instructions (loaded from files if configured).
  systemPrompt = systemInstructions.apply(systemPrompt.trim(), instructionsHeader);
  const nonSystem = messages.filter(m => m.role !== "system");

  for (const msg of nonSystem) {
    if (msg.role === "user") {
      if (pendingAssistantMessage) {
        history.push({ assistantResponseMessage: pendingAssistantMessage });
        pendingAssistantMessage = null;
      }
      if (pendingToolResults.length) {
        const validIds = lastAssistantToolIds(history);
        const kept = filterOrphanToolResults(pendingToolResults, validIds);
        if (kept.length) {
          history.push({ userInputMessage: { content: "", userInputMessageContext: { toolResults: kept }, origin: "KIRO_CLI", modelId: model } });
        }
        pendingToolResults = [];
      }
      if (pendingUserMessage) { history.push({ userInputMessage: pendingUserMessage }); pendingUserMessage = null; }
      pendingUserMessage = { content: flattenContent(msg.content), userInputMessageContext: {}, origin: "KIRO_CLI", modelId: model };
    } else if (msg.role === "assistant") {
      if (pendingAssistantMessage) {
        history.push({ assistantResponseMessage: pendingAssistantMessage });
        pendingAssistantMessage = null;
      }
      if (pendingToolResults.length) {
        const validIds = lastAssistantToolIds(history);
        const kept = filterOrphanToolResults(pendingToolResults, validIds);
        if (kept.length) {
          history.push({ userInputMessage: { content: pendingUserMessage ? pendingUserMessage.content : "", userInputMessageContext: { toolResults: kept }, origin: "KIRO_CLI", modelId: model } });
        } else if (pendingUserMessage && pendingUserMessage.content) {
          history.push({ userInputMessage: { ...pendingUserMessage } });
        }
        pendingToolResults = [];
        pendingUserMessage = null;
      } else if (pendingUserMessage) {
        history.push({ userInputMessage: pendingUserMessage }); pendingUserMessage = null;
      }
      const assistantMsg = { messageId: crypto.randomUUID(), content: flattenContent(msg.content) };
      if (msg.tool_calls?.length) {
        assistantMsg.toolUses = msg.tool_calls.map(tc => ({
          toolUseId: normalizeToolUseId(tc.id),
          name: tc.function?.name || tc.name,
          input: typeof tc.function?.arguments === "string" ? (tc.function.arguments ? tryParseJson(tc.function.arguments) : {}) : (tc.function?.arguments || tc.input || {})
        }));
      }
      if (!assistantMsg.content && !assistantMsg.toolUses) {
        assistantMsg.content = ".";
      }
      pendingAssistantMessage = assistantMsg;
    } else if (msg.role === "tool") {
      pendingToolResults.push({ toolUseId: normalizeToolUseId(msg.tool_call_id), content: [{ json: typeof msg.content === "string" ? tryParseJson(msg.content) : msg.content }], status: "success" });
    }
  }
  if (pendingAssistantMessage) { history.push({ assistantResponseMessage: pendingAssistantMessage }); pendingAssistantMessage = null; }

  const userContext = { envState: { operatingSystem: kiroOsName(), currentWorkingDirectory: process.cwd() } };
  if (openaiTools) userContext.tools = openaiToolsToKiro(openaiTools);

  let currentMessage;
  if (pendingToolResults.length) {
    const validIds = lastAssistantToolIds(history);
    const kept = filterOrphanToolResults(pendingToolResults, validIds);
    if (kept.length) {
      userContext.toolResults = kept;
      const content = pendingUserMessage?.content || "continue";
      currentMessage = { userInputMessage: { content, userInputMessageContext: userContext, origin: "KIRO_CLI", modelId: model } };
    } else {
      const content = pendingUserMessage?.content || "continue";
      currentMessage = { userInputMessage: { content, userInputMessageContext: userContext, origin: "KIRO_CLI", modelId: model } };
    }
  } else if (pendingUserMessage) {
    let content = pendingUserMessage.content;
    if (systemPrompt) content = systemPrompt + content;
    if (!content) content = ".";
    currentMessage = { userInputMessage: { content, userInputMessageContext: userContext, origin: "KIRO_CLI", modelId: model } };
  } else {
    currentMessage = { userInputMessage: { content: systemPrompt || ".", userInputMessageContext: userContext, origin: "KIRO_CLI", modelId: model } };
  }

  return { conversationState: { conversationId: crypto.randomUUID(), history, currentMessage, chatTriggerType: "MANUAL", agentTaskType: "vibe" } };
}

// ─────────────────────────────────────────────────────────────
// Одна попытка HTTPS-запроса к Kiro. Резолвится объектом:
//   { ok: true, proxyRes }  — 200, стримим дальше
//   { ok: false, statusCode, body, cls } — ошибка, решаем: ретрай/фоллбэк/отдать наверх
//   { ok: false, transport: err } — сетевая ошибка
// ─────────────────────────────────────────────────────────────
function kiroAttempt(body, tokenData) {
  return new Promise((resolve) => {
    const opts = {
      hostname: HOST, port: 443, path: "/", method: "POST",
      headers: {
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
        "authorization": `Bearer ${tokenData.access_token}`,
        "content-length": Buffer.byteLength(body)
      }
    };
    const req = https.request(opts, (proxyRes) => {
      if (proxyRes.statusCode === 200) {
        resolve({ ok: true, proxyRes });
        return;
      }
      let errBody = "";
      proxyRes.on("data", d => errBody += d);
      proxyRes.on("end", () => {
        const cls = classifyError(proxyRes.statusCode, errBody);
        resolve({ ok: false, statusCode: proxyRes.statusCode, body: errBody, cls });
      });
    });
    req.on("error", (err) => resolve({ ok: false, transport: err }));
    req.write(body);
    req.end();
  });
}

// Пытается отправить запрос с retry+fallback, пока не получит 200 или не исчерпает все попытки.
// onSuccess(proxyRes, usedModel) — вызвать со стримом ответа.
// onFail({statusCode, body, usedModel}) — финальная ошибка, отдать клиенту.
async function sendWithRetry(parsed, tokenData, instructionsHeader, onSuccess, onFail) {
  const requestedModel = normalizeModel(parsed.model);
  const chain = fallbackFor(requestedModel);
  let usedModel = requestedModel;
  let lastErr = null;

  for (let modelIdx = 0; modelIdx < chain.length; modelIdx++) {
    const tryModel = chain[modelIdx];
    usedModel = tryModel;
    let capacityStrikes = 0;

    for (let attempt = 0; attempt < RETRY_MAX; attempt++) {
      const kiroReq = openaiToKiro(parsed, tryModel, instructionsHeader);
      kiroReq.profileArn = tokenData.profile_arn;
      const bodyStr = JSON.stringify(kiroReq);

      const res = await kiroAttempt(bodyStr, tokenData);
      if (res.ok) {
        return onSuccess(res.proxyRes, usedModel);
      }
      lastErr = res;

      if (res.transport) {
        console.error(`[KIRO] transport err: ${res.transport.message} (model=${tryModel} attempt=${attempt})`);
        await sleep(backoff(attempt));
        continue;
      }

      const { statusCode, body, cls } = res;
      console.error(`[KIRO] ${statusCode} (${cls.reason}) model=${tryModel} attempt=${attempt}: ${body.slice(0,180)}`);

      if (statusCode === 400) {
        try {
          const fs = require("fs");
          const dumpPath = path.join(DUMP_DIR, `kiro-proxy-400-${Date.now()}.json`);
          fs.writeFileSync(dumpPath, JSON.stringify({ incoming: parsed, outgoing: kiroReq, err: body, model: tryModel }, null, 2));
        } catch {}
      }

      if (!cls.retryable) {
        return onFail({ statusCode, body, usedModel });
      }
      if (cls.capacity) capacityStrikes++;

      // Если модель упёрлась в capacity FALLBACK_AFTER раз — не мучаем, идём на следующую
      if (cls.capacity && capacityStrikes >= FALLBACK_AFTER && modelIdx < chain.length - 1) {
        console.warn(`[KIRO] capacity exhausted on ${tryModel}, falling back to ${chain[modelIdx+1]}`);
        break;
      }
      await sleep(backoff(attempt));
    }
  }

  // Все попытки и все fallback-модели исчерпаны
  if (lastErr && lastErr.transport) {
    return onFail({ statusCode: 502, body: JSON.stringify({ error: { message: lastErr.transport.message, type: "upstream_unavailable" } }), usedModel });
  }
  if (lastErr) {
    return onFail({ statusCode: lastErr.statusCode, body: lastErr.body, usedModel });
  }
  return onFail({ statusCode: 503, body: JSON.stringify({ error: { message: "All fallback models exhausted", type: "capacity_exhausted" } }), usedModel });
}

// ─────────────────────────────────────────────────────────────
// HTTP сервер
// ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") { res.writeHead(200); res.end(); return; }

  if (req.url === "/v1/models") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ object: "list", data: [...VALID_MODELS].map(id => ({ id, object: "model", owned_by: "kiro", created: Math.floor(Date.now()/1000) })) }));
    return;
  }
  if (req.url === "/health") { res.writeHead(200); res.end("ok"); return; }

  if (req.url === "/debug/instructions") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(systemInstructions.status(), null, 2));
    return;
  }
  if (req.url === "/debug/instructions/reload" && req.method === "POST") {
    systemInstructions.reload();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(systemInstructions.status(), null, 2));
    return;
  }

  if (req.url === "/v1/chat/completions" && req.method === "POST") {
    console.log("[REQ]", new Date().toISOString(), req.headers["user-agent"] || "?");
    let raw = "";
    req.on("data", c => raw += c);
    req.on("end", async () => {
      let parsed;
      try { parsed = JSON.parse(raw); } catch { res.writeHead(400); res.end('{"error":"bad json"}'); return; }
      console.log("[DEBUG] model:", parsed.model, "msgs:", parsed.messages?.length, "tools:", parsed.tools?.length || 0, "stream:", parsed.stream);

      let tokenData;
      try { tokenData = getToken(); } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: { message: e.message } })); return; }

      const id = `chatcmpl-kiro-${Date.now()}`;
      const streaming = parsed.stream;
      const instructionsHeader = req.headers["x-proxy-instructions"];

      await sendWithRetry(parsed, tokenData, instructionsHeader,
        (proxyRes, usedModel) => {
          if (streaming) {
            res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" });
            const parser = new EventStreamParser();
            const toolCallsById = new Map();
            let toolCallIndex = 0;

            proxyRes.on("data", (chunk) => {
              const events = parser.feed(chunk);
              for (const e of events) {
                if (e.type === "assistantResponseEvent") {
                  try {
                    const d = JSON.parse(e.payload);
                    if (d.content) {
                      res.write(`data: ${JSON.stringify({
                        id, object: "chat.completion.chunk", model: usedModel, created: Math.floor(Date.now()/1000),
                        choices: [{ index: 0, delta: { content: d.content }, finish_reason: null }]
                      })}\n\n`);
                    }
                  } catch {}
                } else if (e.type === "toolUseEvent") {
                  try {
                    const d = JSON.parse(e.payload);
                    if (!toolCallsById.has(d.toolUseId)) {
                      toolCallsById.set(d.toolUseId, { index: toolCallIndex++, sent_name: false });
                      const tc = toolCallsById.get(d.toolUseId);
                      res.write(`data: ${JSON.stringify({
                        id, object: "chat.completion.chunk", model: usedModel, created: Math.floor(Date.now()/1000),
                        choices: [{ index: 0, delta: { tool_calls: [{ index: tc.index, id: d.toolUseId, type: "function", function: { name: d.name, arguments: "" } }] }, finish_reason: null }]
                      })}\n\n`);
                      tc.sent_name = true;
                    }
                    if (d.input !== undefined && d.input !== "") {
                      const tc = toolCallsById.get(d.toolUseId);
                      res.write(`data: ${JSON.stringify({
                        id, object: "chat.completion.chunk", model: usedModel, created: Math.floor(Date.now()/1000),
                        choices: [{ index: 0, delta: { tool_calls: [{ index: tc.index, function: { arguments: d.input } }] }, finish_reason: null }]
                      })}\n\n`);
                    }
                  } catch {}
                }
              }
            });

            proxyRes.on("end", () => {
              const finishReason = toolCallsById.size > 0 ? "tool_calls" : "stop";
              res.write(`data: ${JSON.stringify({
                id, object: "chat.completion.chunk", model: usedModel, created: Math.floor(Date.now()/1000),
                choices: [{ index: 0, delta: {}, finish_reason: finishReason }]
              })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            });
            proxyRes.on("error", (e) => { console.error("[KIRO] stream err:", e.message); try { res.end(); } catch {} });
          } else {
            const chunks = [];
            proxyRes.on("data", d => chunks.push(d));
            proxyRes.on("end", () => {
              const parser = new EventStreamParser();
              const events = parser.feed(Buffer.concat(chunks));
              const contentParts = [];
              const toolCallsById = new Map();
              for (const e of events) {
                if (e.type === "assistantResponseEvent") {
                  try { const d = JSON.parse(e.payload); if (d.content) contentParts.push(d.content); } catch {}
                } else if (e.type === "toolUseEvent") {
                  try {
                    const d = JSON.parse(e.payload);
                    if (!toolCallsById.has(d.toolUseId)) toolCallsById.set(d.toolUseId, { id: d.toolUseId, name: d.name, parts: [] });
                    if (d.input !== undefined) toolCallsById.get(d.toolUseId).parts.push(d.input);
                  } catch {}
                }
              }
              const toolCalls = [...toolCallsById.values()].map(tc => ({ id: tc.id, type: "function", function: { name: tc.name, arguments: tc.parts.join("") || "{}" } }));
              const content = contentParts.join("");
              const message = { role: "assistant", content: content || null };
              if (toolCalls.length) message.tool_calls = toolCalls;
              const finishReason = toolCalls.length ? "tool_calls" : "stop";
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify({
                id, object: "chat.completion", model: usedModel, created: Math.floor(Date.now()/1000),
                choices: [{ index: 0, message, finish_reason: finishReason }],
                usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
              }));
            });
          }
        },
        ({ statusCode, body, usedModel }) => {
          console.error(`[KIRO] final fail model=${usedModel} status=${statusCode}`);
          res.writeHead(statusCode || 502, { "Content-Type": "application/json" });
          let parsedBody;
          try { parsedBody = JSON.parse(body); } catch { parsedBody = { raw: body }; }
          res.end(JSON.stringify({ error: { message: parsedBody.message || parsedBody.raw || "upstream error", code: statusCode, model: usedModel, upstream: parsedBody } }));
        }
      );
    });
    return;
  }
  res.writeHead(404); res.end('{"error":"not found"}');
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[kiro-proxy] v4 http://127.0.0.1:${PORT} (retry=${RETRY_MAX}, fallback_after=${FALLBACK_AFTER})`);
});
