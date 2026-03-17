const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const {
  getOrCreateTarget,
  getKatanaScanRound,
  insertKatanaScan,
} = require('../db');
const { broadcastToJob } = require('../websocket');
const { scoreUrlsWithGemini } = require('./gemini');

const RESULT_DIR = path.join(__dirname, '..', 'result');
const KALI_CONTAINER =
  process.env.KALI_CONTAINER_NAME || 'kali'; // ตั้งชื่อ container ตามที่ใช้จริง

if (!fs.existsSync(RESULT_DIR)) {
  fs.mkdirSync(RESULT_DIR, { recursive: true });
}

function sanitizeTargetName(targetName) {
  return targetName.replace(/[^a-zA-Z0-9_.-]+/g, '_');
}

function getKatanaFlagsDefinition() {
  return {
    name: 'katana',
    description: 'Web crawling and reconnaissance tool',
    defaultFlags: ['-silent', '-j', '-jc'],
    flags: [
      {
        name: '-u',
        label: 'Target URL',
        type: 'string',
        required: true,
        description: 'Target URL to scan',
      },
      {
        name: '-depth',
        label: 'Depth',
        type: 'number',
        required: false,
        default: 3,
        description: 'maximum depth to crawl',
      },
      {
        name: '-jc',
        label: 'JS crawl',
        type: 'boolean',
        required: false,
        default: true,
        description: 'enable endpoint parsing / crawling in javascript file',
      },
      {
        name: '-jsl',
        label: 'JSluice',
        type: 'boolean',
        required: false,
        default: false,
        description: 'enable jsluice parsing in javascript file (memory intensive)',
      },
      {
        name: '-td',
        label: 'Tech detect',
        type: 'boolean',
        required: false,
        default: false,
        description: 'enable technology detection',
      },
      {
        name: '-H',
        label: 'Headers',
        type: 'string',
        multiple: true,
        required: false,
        description: 'custom header/cookie in header:value format',
      },
      {
        name: '-timeout',
        label: 'Timeout (sec)',
        type: 'number',
        required: false,
        description: 'time to wait for request in seconds',
      },
      {
        name: '-c',
        label: 'Concurrency',
        type: 'number',
        required: false,
        description: 'number of concurrent fetchers',
      },
      {
        name: '-s',
        label: 'Strategy',
        type: 'string',
        required: false,
        description: 'Visit strategy (depth-first, breadth-first)',
      },
      {
        name: '-iqp',
        label: 'Ignore query params',
        type: 'boolean',
        required: false,
        description: 'Ignore crawling same path with different query-param values',
      },
      {
        name: '-dr',
        label: 'Disable redirects',
        type: 'boolean',
        required: false,
        description: 'disable following redirects',
      },
    ],
  };
}

function getKatanaFlags() {
  return getKatanaFlagsDefinition();
}

async function startKatanaScan({ targetUrl, userFlags, jobId }) {
  const target = getOrCreateTarget(targetUrl);
  const round = getKatanaScanRound(target.target_id);

  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const fileName = `katana-${round}.json`;
  const hostResultPath = path.join(targetDir, fileName);

  const flagsDef = getKatanaFlagsDefinition();
  const baseFlags = flagsDef.defaultFlags || [];
  const extraFlags = Array.isArray(userFlags) ? userFlags : [];
  const flagsJson = JSON.stringify({
    baseFlags,
    extraFlags,
  });

  const args = [
    'exec',
    KALI_CONTAINER,
    'katana',
    '-u',
    targetUrl,
    ...baseFlags,
    ...extraFlags,
  ];

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: 'Starting katana scan...',
  });

  const docker = spawn('docker', args);
  let stdoutBuf = '';

  docker.on('error', (err) => {
    console.error('Failed to start docker:', err);
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message:
        err && err.code === 'EACCES'
          ? 'Docker permission denied (need docker group or sudo)'
          : `Failed to start docker: ${err.message || String(err)}`,
    });
  });

  docker.stdout.on('data', (data) => {
    const text = data.toString();
    stdoutBuf += text;
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: text,
    });
  });

  docker.stderr.on('data', (data) => {
    const text = data.toString();
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: text,
      stream: 'stderr',
    });
  });

  docker.on('close', (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `Katana scan exited with code ${code}`,
      });
      return;
    }

    try {
      broadcastToJob(jobId, {
        type: 'status',
        jobId,
        status: 'processing',
        message: 'Filtering katana results (status_code==200)...',
      });

      const { urls, statusByUrl } = extractUrlsFromKatanaJsonLines(stdoutBuf);

      broadcastToJob(jobId, {
        type: 'status',
        jobId,
        status: 'scoring',
        message: `Sending ${urls.length} URLs to Gemini for scoring...`,
      });

      // NOTE: to avoid huge prompts, cap batch size for now
      const capped = urls.slice(0, Number(process.env.GEMINI_URL_CAP || 200));

      scoreUrlsWithGemini(capped)
        .then((scored) => {
          const hostDir = path.dirname(hostResultPath);
          if (!fs.existsSync(hostDir)) {
            fs.mkdirSync(hostDir, { recursive: true });
          }

          const scoredWithStatus = scored.map((s) => ({
            ...s,
            status: statusByUrl[s.url] ?? null,
          }));
          const scoredUrlsSet = new Set(scored.map((s) => s.url));
          const non200Entries = Object.entries(statusByUrl)
            .filter(([url]) => !scoredUrlsSet.has(url))
            .map(([url, status]) => ({
              url,
              status,
              score: null,
              level: null,
              reason: null,
            }));
          const merged = [...scoredWithStatus, ...non200Entries];
          fs.writeFileSync(hostResultPath, JSON.stringify(merged, null, 2), 'utf8');

          const scanAt = new Date().toISOString();
          insertKatanaScan(
            target.target_id,
            path.relative(path.join(__dirname, '..'), hostResultPath),
            flagsJson,
            scanAt
          );

          broadcastToJob(jobId, {
            type: 'done',
            jobId,
            status: 'completed',
            totalUrls: urls.length,
            scoredUrls: scored.length,
            resultFile: path.relative(
              path.join(__dirname, '..'),
              hostResultPath
            ),
            scanAt,
          });
        })
        .catch((err) => {
          console.error('Gemini scoring failed:', err);
          const msg = err?.message || '';
          const is429 = /429|rate limit|resource.exhausted/i.test(msg);
          broadcastToJob(jobId, {
            type: 'error',
            jobId,
            message: is429
              ? 'Gemini rate limit (429) — ลองรอสักครู่แล้วรันใหม่'
              : msg || 'Gemini scoring failed',
          });
        });
    } catch (err) {
      console.error('Error handling katana result:', err);
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: 'Error handling katana result',
      });
    }
  });
}

/**
 * Parse Katana JSON-lines output.
 * Returns { urls: string[] } (only status 200, for Gemini) and
 * { statusByUrl: Record<string, number> } (all URLs with status for saving).
 */
function extractUrlsFromKatanaJsonLines(output) {
  const urls = [];
  const seen = new Set();
  const statusByUrl = {};
  const lines = (output || '').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      const status = obj?.response?.status_code;
      const url = obj?.request?.endpoint;
      if (typeof url === 'string' && url) {
        if (status != null && typeof status === 'number') {
          statusByUrl[url] = status;
        }
        if (status === 200 && !seen.has(url)) {
          seen.add(url);
          urls.push(url);
        }
      }
    } catch {
      // ignore non-json lines
    }
  }
  return { urls, statusByUrl };
}

module.exports = {
  getKatanaFlags,
  startKatanaScan,
};

