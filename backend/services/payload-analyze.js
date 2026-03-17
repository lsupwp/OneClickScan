const { GoogleGenAI } = require('@google/genai');

function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not set');
  }
  return new GoogleGenAI({ apiKey });
}

function buildSystemPrompt() {
  return `
You are a Senior Penetration Tester.

Given a list of HTTP endpoints with method, query params, and body params (from HTML forms and URLs),
decide which tool is best for testing each endpoint:
- sqlmap: likely DB-backed parameters (id, user_id, search, q, s, filter, order, sort, page, category, post, comment, product, report)
- XSStrike: likely reflected/stored XSS vectors (search fields, comment fields, message/content/body, name/email inputs that might be rendered)
- curl: basic API probing or file exposure checks (GET endpoints, json/xmlrpc/wp-json, static loaders, admin scripts)

For each item, output a JSON array ONLY (no markdown, no prose) with this schema:
[
  {
    "action": "https://host/path",
    "method": "GET|POST|PUT|DELETE|PATCH",
    "tool": "sqlmap|xsstrike|curl",
    "risk": "Info|Low|Medium|High|Critical",
    "cmd": "one single CLI command ready to run",
    "what": "what this payload tests",
    "why": "why you chose this tool for this endpoint",
    "notes": "optional short safety/usage note"
  }
]

Rules:
- Prefer a single command per item.
- If method is POST, include data params for the tool.
- Always include the full URL.
- Keep commands safe and non-destructive. No brute force, no credential stuffing.

Tool flag constraints (CRITICAL: do NOT invent flags):
- xsstrike allowed flags:
  -u, --data, -e, --fuzzer, --timeout, --proxy, --crawl, --json, --path,
  --seeds, -f, -l, --headers, -t, -d, --skip, --skip-dom, --blind,
  --console-log-level, --file-log-level, --log-file
- sqlmap allowed flags (common subset):
  -u/--url, --data, --cookie, --random-agent, --proxy, --tor, --check-tor,
  -p, --dbms, --level, --risk, --technique,
  -a/--all, -b/--banner, --current-user, --current-db, --passwords,
  --dbs, --tables, --columns, --schema, --dump, --dump-all,
  -D, -T, -C, --os-shell, --os-pwn, --batch, --flush-session, -v
- If you are unsure a flag exists, omit it. Prefer minimal valid commands that will run.
`.trim();
}

function safeJsonParse(text) {
  const trimmed = (text || '').trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf('[');
    const end = trimmed.lastIndexOf(']');
    if (start >= 0 && end > start) {
      return JSON.parse(trimmed.slice(start, end + 1));
    }
    throw new Error('Gemini output is not valid JSON');
  }
}

function clampRisk(risk) {
  const allowed = new Set(['Info', 'Low', 'Medium', 'High', 'Critical']);
  return allowed.has(risk) ? risk : 'Info';
}

function clampTool(tool) {
  const allowed = new Set(['sqlmap', 'xsstrike', 'curl']);
  return allowed.has(tool) ? tool : 'curl';
}

function normalizeInput(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .filter((e) => e && typeof e.action === 'string' && typeof e.method === 'string')
    .map((e) => ({
      found_in: Array.isArray(e.found_in) ? e.found_in.slice(0, 5) : [],
      action: e.action,
      method: String(e.method).toUpperCase(),
      query_string: e.query_string && typeof e.query_string === 'object' ? e.query_string : {},
      payload: e.payload && typeof e.payload === 'object' ? e.payload : {},
      form_id: typeof e.form_id === 'string' ? e.form_id : null,
      form_name: typeof e.form_name === 'string' ? e.form_name : null,
    }));
}

async function analyzePayloadReconWithGemini(payloadReconEntries) {
  const ai = getGeminiClient();
  const model = process.env.GEMINI_MODEL || 'models/gemini-2.5-flash';
  const input = normalizeInput(payloadReconEntries).slice(0, 200);

  const response = await ai.models.generateContent({
    model,
    // NOTE: @google/genai here only accepts role: user|model; embed system prompt into user content.
    contents: `${buildSystemPrompt()}\n\nPayload Recon entries:\n${JSON.stringify(input, null, 2)}`,
  });

  const data = safeJsonParse(response.text);
  if (!Array.isArray(data)) throw new Error('Gemini output JSON is not an array');

  return data
    .filter((x) => x && typeof x.action === 'string' && typeof x.method === 'string')
    .map((x) => ({
      action: x.action,
      method: String(x.method).toUpperCase(),
      tool: clampTool(String(x.tool || '').toLowerCase()),
      risk: clampRisk(String(x.risk || 'Info')),
      cmd: typeof x.cmd === 'string' ? x.cmd : '',
      what: typeof x.what === 'string' ? x.what : '',
      why: typeof x.why === 'string' ? x.why : '',
      notes: typeof x.notes === 'string' ? x.notes : undefined,
    }));
}

module.exports = {
  analyzePayloadReconWithGemini,
};

