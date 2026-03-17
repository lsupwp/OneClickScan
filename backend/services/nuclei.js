const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const { getOrCreateTarget, getNucleiScanRound, insertNucleiScan } = require('../db');
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

function extractCve(info) {
  const cve = info?.classification?.['cve-id'];
  if (!cve) return null;
  if (Array.isArray(cve)) return cve[0] || null;
  if (typeof cve === 'string') return cve;
  return null;
}

function simplifyNucleiLine(obj) {
  const info = obj?.info || {};
  return {
    name: info?.name ?? null,
    severity: info?.severity ?? null,
    matchedAt: obj?.['matched-at'] ?? obj?.url ?? null,
    templateId: obj?.['template-id'] ?? null,
    description: info?.description ?? null,
    cve: extractCve(info),
  };
}

function parseJsonLines(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      out.push(simplifyNucleiLine(obj));
    } catch {
      // ignore non-json lines
    }
  }
  return out;
}

async function startNucleiScan({ targetUrl, jobId }) {
  const target = getOrCreateTarget(targetUrl);
  const round = getNucleiScanRound(target.target_id);

  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const outFileInContainer = `/tmp/nuclei-${sanitizeJobId(jobId)}.jsonl`;

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: 'Starting nuclei scan...',
  });

  const args = [
    'exec',
    KALI_CONTAINER,
    'nuclei',
    '-u',
    targetUrl,
    '-jsonl',
    '-silent',
    '-o',
    outFileInContainer,
  ];

  const docker = spawn('docker', args);
  docker.stderr.on('data', (data) => {
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: data.toString(),
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

  docker.on('error', (err) => {
    console.error('Failed to start docker (nuclei):', err);
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message: `Failed to start nuclei: ${err?.message || String(err)}`,
    });
  });

  docker.on('close', (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `nuclei exited with code ${code}`,
      });
      return;
    }

    broadcastToJob(jobId, {
      type: 'status',
      jobId,
      status: 'processing',
      message: 'Reading nuclei results...',
    });

    const cat = spawn('docker', ['exec', KALI_CONTAINER, 'cat', outFileInContainer]);
    let raw = '';
    let catDone = false;
    const CAT_TIMEOUT_MS = 20000;
    const catTimeout = setTimeout(() => {
      if (catDone) return;
      catDone = true;
      try {
        cat.kill('SIGKILL');
      } catch {}
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: 'อ่านผล nuclei เกินเวลา — ลองรันใหม่',
      });
    }, CAT_TIMEOUT_MS);

    cat.on('error', (err) => {
      if (catDone) return;
      catDone = true;
      clearTimeout(catTimeout);
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `อ่านผล nuclei ไม่สำเร็จ: ${err?.message || String(err)}`,
      });
    });
    cat.stdout.on('data', (data) => {
      raw += data.toString();
    });
    cat.on('close', (catCode) => {
      if (catDone) return;
      catDone = true;
      clearTimeout(catTimeout);
      if (catCode !== 0) {
        broadcastToJob(jobId, {
          type: 'error',
          jobId,
          message: 'Could not read nuclei output from container',
        });
        return;
      }

      try {
        const simplified = parseJsonLines(raw);
        const hostResultPath = path.join(targetDir, `nuclei-${round}.json`);
        fs.writeFileSync(hostResultPath, JSON.stringify(simplified, null, 2), 'utf8');
        const rel = path.relative(path.join(__dirname, '..'), hostResultPath);
        const scanAt = new Date().toISOString();
        insertNucleiScan(target.target_id, rel, scanAt);

        broadcastToJob(jobId, {
          type: 'done',
          jobId,
          status: 'completed',
          totalFindings: simplified.length,
          resultFile: rel,
          scanAt,
        });
      } catch (err) {
        console.error('Failed to persist nuclei result:', err);
        broadcastToJob(jobId, {
          type: 'error',
          jobId,
          message: 'Error handling nuclei result',
        });
      }
    });
  });
}

module.exports = {
  startNucleiScan,
};

