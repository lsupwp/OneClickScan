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

const MAX_RETRIES = 4;
const INITIAL_DELAY_MS = 2000;

function isRateLimitError(err) {
  if (!err) return false;
  const status = err.status ?? err.statusCode ?? err.code;
  if (status === 429) return true;
  const msg = (err.message || err.toString() || '').toLowerCase();
  return /429|resource.exhausted|rate.limit|quota|too many requests/i.test(msg);
}

/** Daily quota (e.g. FreeTier 20/day) — retry won't help */
function isDailyQuotaExceeded(err) {
  const msg = (err?.message || err?.toString() || '') + (err?.body || '');
  return /FreeTier|PerDay|quota exceeded|exceeded your current quota/i.test(msg);
}

/** Parse retry delay from Gemini error (seconds) */
function getRetryDelaySeconds(err) {
  const raw = (err?.message || '') + (err?.body || '');
  const match = raw.match(/retry in (\d+(?:\.\d+)?)s/i) || raw.match(/"retryDelay":"(\d+)s"/);
  if (match) return Math.ceil(Number(match[1]));
  const retryInfo = raw.match(/"retryDelay":(\d+)/);
  if (retryInfo) return Math.ceil(Number(retryInfo[1]) / 1e9); // nanos to seconds
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Run one Gemini scoring job at a time to avoid 429 when Katana + FFuf finish together */
const scoringQueue = [];
let scoringQueueRunning = false;

async function processScoringQueue() {
  if (scoringQueueRunning || scoringQueue.length === 0) return;
  scoringQueueRunning = true;
  while (scoringQueue.length > 0) {
    const task = scoringQueue.shift();
    try {
      await task();
    } catch (err) {
      console.error('Gemini queue task error:', err);
    }
  }
  scoringQueueRunning = false;
}

function enqueueScoring(fn) {
  return new Promise((resolve, reject) => {
    scoringQueue.push(async () => {
      try {
        const result = await fn();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
    processScoringQueue();
  });
}

async function scoreUrlsWithGeminiInternal(urls) {
  const ai = getGeminiClient();
  const prompt = buildPrompt(urls);
  const model = process.env.GEMINI_MODEL || 'gemini-3-flash-preview';

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await ai.models.generateContent({
        model,
        contents: prompt,
      });

      const text = response.text;
      const data = safeJsonParse(text);

      if (!Array.isArray(data)) {
        throw new Error('Gemini output JSON is not an array');
      }

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
    } catch (err) {
      if (isRateLimitError(err) && isDailyQuotaExceeded(err)) {
        throw new Error(
          'Gemini โควต้าฟรีหมดแล้ว (จำกัด 20 ครั้ง/วัน) — รอถึงวันถัดไปหรืออัปเกรดแผนที่ Google AI Studio'
        );
      }
      if (attempt < MAX_RETRIES && isRateLimitError(err)) {
        const delaySec = getRetryDelaySeconds(err);
        const delayMs = delaySec != null ? delaySec * 1000 : INITIAL_DELAY_MS * Math.pow(2, attempt);
        console.log('[gemini] 429, retry after', delayMs / 1000, 's, attempt', attempt + 1);
        await sleep(delayMs);
        continue;
      }
      if (isRateLimitError(err)) {
        const msg = err?.message || err?.toString() || 'Unknown error';
        throw new Error(`Gemini rate limit (429). ${msg}`);
      }
      throw err;
    }
  }
}

async function scoreUrlsWithGemini(urls) {
  return enqueueScoring(() => scoreUrlsWithGeminiInternal(urls));
}

module.exports = {
  scoreUrlsWithGemini,
};

