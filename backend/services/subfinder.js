const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { getDomain } = require('tldts');

const { getOrCreateTarget, getSubfinderScanRound, insertSubfinderScan } = require('../db');
const { broadcastToJob } = require('../websocket');

const RESULT_DIR = path.join(__dirname, '..', 'result');
const KALI_CONTAINER = process.env.KALI_CONTAINER_NAME || 'kali-engine';

if (!fs.existsSync(RESULT_DIR)) {
  fs.mkdirSync(RESULT_DIR, { recursive: true });
}

function sanitizeTargetName(targetName) {
  return targetName.replace(/[^a-zA-Z0-9_.-]+/g, '_');
}

function sanitizeJobId(jobId) {
  return String(jobId).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function extractScheme(targetUrl) {
  try {
    const u = new URL(targetUrl);
    if (u.protocol === 'https:') return 'https';
    return 'http';
  } catch {
    return 'http';
  }
}

function registrableDomainFromUrl(targetUrl) {
  try {
    const u = new URL(targetUrl);
    const host = u.hostname;
    return getDomain(host) || host;
  } catch {
    return String(targetUrl || '').trim();
  }
}

function parseJsonLines(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (!trimmed.startsWith('{')) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      // ignore
    }
  }
  return out;
}

function runDockerExecCapture({ args, stdinText, timeoutMs, onProgress, jobId }) {
  return new Promise((resolve, reject) => {
    const proc = spawn('docker', ['exec', '-i', KALI_CONTAINER, ...args]);
    let out = '';
    let done = false;

    const t = setTimeout(() => {
      if (done) return;
      done = true;
      try {
        proc.kill('SIGKILL');
      } catch {}
      reject(new Error('timeout'));
    }, timeoutMs);

    proc.on('error', (err) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      reject(err);
    });

    proc.stderr.on('data', (data) => {
      const msg = data.toString();
      if (onProgress) onProgress(msg, 'stderr');
      if (jobId) {
        broadcastToJob(jobId, { type: 'progress', jobId, message: msg, stream: 'stderr' });
      }
    });
    proc.stdout.on('data', (data) => {
      out += data.toString();
    });

    proc.on('close', (code) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      if (code !== 0) return reject(new Error(`exit ${code}`));
      resolve(out);
    });

    if (stdinText) {
      proc.stdin.write(stdinText);
    }
    proc.stdin.end();
  });
}

async function startSubfinderScan({ targetUrl, jobId, httpxTimeoutSec = 5 }) {
  const target = getOrCreateTarget(targetUrl);
  const round = getSubfinderScanRound(target.target_id);

  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const scheme = extractScheme(targetUrl);
  const domain = registrableDomainFromUrl(targetUrl);
  const outFileInContainer = `/tmp/subfinder-${sanitizeJobId(jobId)}.json`;

  broadcastToJob(jobId, { type: 'status', jobId, status: 'starting', message: `Starting subfinder for ${domain}...` });

  const sf = spawn('docker', [
    'exec',
    KALI_CONTAINER,
    'subfinder',
    '-d',
    domain,
    '-json',
    '-o',
    outFileInContainer,
  ]);

  sf.stderr.on('data', (data) => {
    broadcastToJob(jobId, { type: 'progress', jobId, message: data.toString(), stream: 'stderr' });
  });
  sf.stdout.on('data', (data) => {
    const msg = data.toString();
    if (msg.trim()) broadcastToJob(jobId, { type: 'progress', jobId, message: msg });
  });
  sf.on('error', (err) => {
    broadcastToJob(jobId, { type: 'error', jobId, message: `Failed to start subfinder: ${err?.message || String(err)}` });
  });

  sf.on('close', async (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, { type: 'error', jobId, message: `subfinder exited with code ${code}` });
      return;
    }

    broadcastToJob(jobId, { type: 'status', jobId, status: 'processing', message: 'Reading subfinder results...' });

    let sfRaw = '';
    try {
      sfRaw = await runDockerExecCapture({
        args: ['cat', outFileInContainer],
        timeoutMs: 20000,
        jobId,
      });
    } catch (err) {
      broadcastToJob(jobId, { type: 'error', jobId, message: 'Could not read subfinder output from container' });
      return;
    }

    const subEntries = parseJsonLines(sfRaw)
      .map((x) => ({
        host: x?.host ?? null,
        input: x?.input ?? domain,
        source: x?.source ?? null,
      }))
      .filter((x) => typeof x.host === 'string' && x.host.length > 0);

    broadcastToJob(jobId, { type: 'status', jobId, status: 'processing', message: `Checking alive hosts with httpx... (${subEntries.length})` });

    const urls = subEntries.map((e) => `${scheme}://${e.host}`).join('\n') + '\n';
    const t = Number(httpxTimeoutSec);
    const httpxTimeout = Number.isFinite(t) && t > 0 ? t : 5;

    let httpxRaw = '';
    try {
      httpxRaw = await runDockerExecCapture({
        args: ['httpx', '-json', '-silent', '-status-code', '-timeout', String(httpxTimeout)],
        stdinText: urls,
        timeoutMs: Math.max(15000, Math.min(180000, httpxTimeout * 1000 * 4)),
        jobId,
      });
    } catch (err) {
      broadcastToJob(jobId, { type: 'error', jobId, message: 'httpx timeout/failed — ลองเพิ่ม timeout หรือรันใหม่' });
      return;
    }

    const httpxEntries = parseJsonLines(httpxRaw)
      .map((x) => ({
        url: x?.url ?? null,
        host: x?.host ?? null,
        status_code: x?.status_code ?? x?.statusCode ?? null,
      }))
      .filter((x) => typeof x.url === 'string' && x.url.length > 0);

    const alive200 = new Set(
      httpxEntries
        .filter((x) => Number(x.status_code) === 200)
        .map((x) => {
          try {
            return new URL(x.url).hostname;
          } catch {
            return null;
          }
        })
        .filter(Boolean)
    );

    const results = subEntries
      .filter((e) => alive200.has(e.host))
      .map((e) => ({
        ...e,
        url: `${scheme}://${e.host}`,
        status_code: 200,
      }));

    const hostResultPath = path.join(targetDir, `subfinder-${round}.json`);
    fs.writeFileSync(hostResultPath, JSON.stringify({ domain, scheme, httpxTimeout, results }, null, 2), 'utf8');
    const rel = path.relative(path.join(__dirname, '..'), hostResultPath);
    const scanAt = new Date().toISOString();
    insertSubfinderScan(target.target_id, rel, scanAt);

    broadcastToJob(jobId, { type: 'done', jobId, status: 'completed', resultFile: rel, scanAt });
  });
}

module.exports = {
  startSubfinderScan,
};

