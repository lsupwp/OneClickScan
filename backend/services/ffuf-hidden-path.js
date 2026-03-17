const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const {
  getOrCreateTarget,
  getFfufScanRound,
  insertFfufScan,
} = require('../db');
const { broadcastToJob } = require('../websocket');
const { scoreUrlsWithGemini } = require('./gemini');

const RESULT_DIR = path.join(__dirname, '..', 'result');
const WORDLIST_UPLOAD_DIR = path.join(__dirname, '..', 'temp', 'wordlists');
const KALI_CONTAINER = process.env.KALI_CONTAINER_NAME || 'kali-engine';
const FFUF_DEFAULT_WORDLIST =
  process.env.FFUF_DEFAULT_WORDLIST ||
  '/usr/share/seclists/Discovery/Web-Content/common.txt';
const KALI_WORDLIST_MOUNT = process.env.KALI_WORDLIST_MOUNT || '/mnt/wordlists';

if (!fs.existsSync(RESULT_DIR)) {
  fs.mkdirSync(RESULT_DIR, { recursive: true });
}
if (!fs.existsSync(WORDLIST_UPLOAD_DIR)) {
  fs.mkdirSync(WORDLIST_UPLOAD_DIR, { recursive: true });
}

function sanitizeTargetName(targetName) {
  return targetName.replace(/[^a-zA-Z0-9_.-]+/g, '_');
}

function sanitizeJobId(jobId) {
  return String(jobId).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getWordlistPathInContainer(wordlistOption) {
  if (wordlistOption === 'default' || !wordlistOption) {
    return FFUF_DEFAULT_WORDLIST;
  }
  const fileId = typeof wordlistOption === 'string' ? wordlistOption : wordlistOption?.fileId;
  if (!fileId) return FFUF_DEFAULT_WORDLIST;
  return `${KALI_WORDLIST_MOUNT}/${fileId}.txt`;
}

function getWordlistPathOnHost(fileId) {
  return path.join(WORDLIST_UPLOAD_DIR, `${fileId}.txt`);
}

function parseFfufJsonOutput(raw) {
  const entries = [];
  try {
    const data = JSON.parse(raw);
    const results = data?.results;
    if (!Array.isArray(results)) return entries;
    const seen = new Set();
    for (const r of results) {
      const url = r?.url;
      if (typeof url !== 'string' || seen.has(url)) continue;
      seen.add(url);
      const status = typeof r?.status === 'number' ? r.status : null;
      entries.push({ url, status });
    }
  } catch (_) {}
  return entries;
}

async function startFfufScan({ targetUrl, wordlist, jobId, extraFlags }) {
  const target = getOrCreateTarget(targetUrl);
  const round = getFfufScanRound(target.target_id);

  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const outFileName = `ffuf-hidden-path-${round}.json`;
  const hostResultPath = path.join(targetDir, outFileName);

  const baseUrl = targetUrl.replace(/\/?$/, '/');
  const ffufUrl = `${baseUrl}FUZZ`;

  const wordlistInContainer = getWordlistPathInContainer(wordlist);
  const wordlistSource = wordlist === 'default' || !wordlist ? 'default' : 'upload';

  const outFileInContainer = `/tmp/ffuf-${sanitizeJobId(jobId)}.json`;

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: 'Starting ffuf hidden path scan...',
  });

  const safeExtra = Array.isArray(extraFlags) ? extraFlags : [];

  const args = [
    'exec',
    KALI_CONTAINER,
    'ffuf',
    '-u',
    ffufUrl,
    '-w',
    wordlistInContainer,
    '-s',
    ...safeExtra,
    '-o',
    outFileInContainer,
  ];

  const docker = spawn('docker', args);
  let stderrBuf = '';

  docker.on('error', (err) => {
    console.error('Failed to start docker (ffuf):', err);
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message:
        err?.code === 'EACCES'
          ? 'Docker permission denied'
          : `Failed to start docker: ${err.message || String(err)}`,
    });
  });

  docker.stderr.on('data', (data) => {
    const text = data.toString();
    stderrBuf += text;
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: text,
      stream: 'stderr',
    });
  });

  docker.stdout.on('data', (data) => {
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: data.toString(),
    });
  });

  docker.on('close', (code) => {
    console.log('[ffuf] docker process closed, code=', code, 'jobId=', jobId);
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `ffuf exited with code ${code}`,
      });
      tryDeleteUploadedWordlist(wordlist);
      return;
    }

    const catArgs = ['exec', KALI_CONTAINER, 'cat', outFileInContainer];
    const cat = spawn('docker', catArgs);
    let rawJson = '';
    let catDone = false;

    const CAT_TIMEOUT_MS = 15000;
    const catTimeout = setTimeout(() => {
      if (catDone) return;
      catDone = true;
      console.error('[ffuf] cat timeout after', CAT_TIMEOUT_MS, 'ms, jobId=', jobId);
      cat.kill('SIGKILL');
      tryDeleteUploadedWordlist(wordlist);
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: 'อ่านผลจาก container เกินเวลา — ลองรันใหม่',
      });
    }, CAT_TIMEOUT_MS);

    cat.on('error', (err) => {
      console.error('[ffuf] cat spawn error:', err, 'jobId=', jobId);
      if (!catDone) {
        catDone = true;
        clearTimeout(catTimeout);
        tryDeleteUploadedWordlist(wordlist);
        broadcastToJob(jobId, {
          type: 'error',
          jobId,
          message: 'ไม่สามารถอ่านผลจาก container: ' + (err?.message || String(err)),
        });
      }
    });

    cat.stdout.on('data', (data) => {
      rawJson += data.toString();
    });

    cat.on('close', (catCode) => {
      if (catDone) return;
      catDone = true;
      clearTimeout(catTimeout);
      console.log('[ffuf] cat closed, code=', catCode, 'jobId=', jobId, 'output length=', rawJson.length);
      tryDeleteUploadedWordlist(wordlist);

      if (catCode !== 0 || !rawJson) {
        broadcastToJob(jobId, {
          type: 'error',
          jobId,
          message: 'Could not read ffuf output from container',
        });
        return;
      }

      broadcastToJob(jobId, {
        type: 'status',
        jobId,
        status: 'processing',
        message: 'Parsing ffuf results...',
      });

      const entries = parseFfufJsonOutput(rawJson);
      const urlList = entries.map((e) => e.url);
      const statusByUrl = Object.fromEntries(entries.map((e) => [e.url, e.status]));

      console.log('[ffuf] parsed', entries.length, 'URLs, sending to Gemini, jobId=', jobId);
      broadcastToJob(jobId, {
        type: 'status',
        jobId,
        status: 'scoring',
        message: `Sending ${entries.length} URLs to Gemini for scoring...`,
      });

      const capped = urlList.slice(0, Number(process.env.GEMINI_URL_CAP || 200));

      scoreUrlsWithGemini(capped)
        .then((scored) => {
          const merged = scored.map((s) => ({
            ...s,
            status: statusByUrl[s.url] ?? null,
          }));

          const hostDir = path.dirname(hostResultPath);
          if (!fs.existsSync(hostDir)) {
            fs.mkdirSync(hostDir, { recursive: true });
          }
          fs.writeFileSync(
            hostResultPath,
            JSON.stringify(merged, null, 2),
            'utf8'
          );

          const scanAt = new Date().toISOString();
          const relResult = path.relative(path.join(__dirname, '..'), hostResultPath);
          insertFfufScan(target.target_id, relResult, wordlistSource, scanAt);

          console.log('[ffuf] done, jobId=', jobId);
          broadcastToJob(jobId, {
            type: 'done',
            jobId,
            status: 'completed',
            totalUrls: entries.length,
            scoredUrls: merged.length,
            resultFile: relResult,
            scanAt,
          });
        })
        .catch((err) => {
          console.error('Gemini scoring failed (ffuf):', err);
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
    });
  });
}

function tryDeleteUploadedWordlist(wordlist) {
  if (!wordlist || wordlist === 'default') return;
  const fileId = typeof wordlist === 'string' ? wordlist : wordlist?.fileId;
  if (!fileId) return;
  const hostPath = getWordlistPathOnHost(fileId);
  try {
    if (fs.existsSync(hostPath)) {
      fs.unlinkSync(hostPath);
    }
  } catch (err) {
    console.error('Failed to delete uploaded wordlist:', err);
  }
}

module.exports = {
  startFfufScan,
  getWordlistPathOnHost,
  WORDLIST_UPLOAD_DIR,
};
