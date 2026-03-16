const { GoogleGenAI } = require('@google/genai');

function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not set');
  }
  return new GoogleGenAI({ apiKey });
}

function buildPrompt(urls) {
  return `
You are a security triage assistant for web paths discovered by a crawler.

Score each URL from 1 to 5 using this scale:
5 Critical: immediate compromise likely (secrets, shells, passwd, exposed configs)
4 High: admin/debug/status endpoints or sensitive panels
3 Medium: leaks useful info (.git, swagger, phpinfo, editor folders)
2 Low: backups/temp/logs/test folders with low impact
1 Info: typical public assets/pages (images, css/js, favicon, about)

Return ONLY valid JSON (no markdown) in this exact shape:
[
  { "url": "https://example.com/path", "score": 1, "level": "Info|Low|Medium|High|Critical", "reason": "short thai or english reason" }
]

URLs:
${urls.map((u) => `- ${u}`).join('\n')}
`.trim();
}

function safeJsonParse(text) {
  const trimmed = (text || '').trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // try to extract first JSON array
    const start = trimmed.indexOf('[');
    const end = trimmed.lastIndexOf(']');
    if (start >= 0 && end > start) {
      const slice = trimmed.slice(start, end + 1);
      return JSON.parse(slice);
    }
    throw new Error('Gemini output is not valid JSON');
  }
}

async function scoreUrlsWithGemini(urls) {
  const ai = getGeminiClient();
  const prompt = buildPrompt(urls);

  const response = await ai.models.generateContent({
    model: process.env.GEMINI_MODEL || 'gemini-3-flash-preview',
    contents: prompt,
  });

  const text = response.text;
  const data = safeJsonParse(text);

  if (!Array.isArray(data)) {
    throw new Error('Gemini output JSON is not an array');
  }

  // minimal validation / normalization
  const normalized = data
    .filter((x) => x && typeof x.url === 'string')
    .map((x) => ({
      url: x.url,
      score: Number(x.score),
      level: typeof x.level === 'string' ? x.level : undefined,
      reason: typeof x.reason === 'string' ? x.reason : undefined,
    }))
    .filter((x) => Number.isFinite(x.score) && x.score >= 1 && x.score <= 5);

  return normalized;
}

module.exports = {
  scoreUrlsWithGemini,
};

