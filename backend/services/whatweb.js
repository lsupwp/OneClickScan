const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const { getOrCreateTarget, getWhatwebScanRound, insertWhatwebScan } = require('../db');
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

async function startWhatwebScan({ targetUrl, jobId, aggression = 1, plugins }) {
  const target = getOrCreateTarget(targetUrl);
  const round = getWhatwebScanRound(target.target_id);

  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const outFileInContainer = `/tmp/whatweb-${sanitizeJobId(jobId)}.json`;
  const selectedPlugins = Array.isArray(plugins) && plugins.length ? plugins : null;
  const a = Number(aggression);
  const aSafe = a === 3 || a === 4 ? a : 1;

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: 'Starting whatweb fingerprint...',
  });

  const args = [
    'exec',
    KALI_CONTAINER,
    'whatweb',
    targetUrl,
    '-a',
    String(aSafe),
    `--log-json=${outFileInContainer}`,
    '-q',
  ];
  if (selectedPlugins) {
    args.push('-p', selectedPlugins.join(','));
  }

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
    console.error('Failed to start docker (whatweb):', err);
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message: `Failed to start whatweb: ${err?.message || String(err)}`,
    });
  });

  docker.on('close', (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `whatweb exited with code ${code}`,
      });
      return;
    }

    broadcastToJob(jobId, {
      type: 'status',
      jobId,
      status: 'processing',
      message: 'Reading whatweb results...',
    });

    const cat = spawn('docker', ['exec', KALI_CONTAINER, 'cat', outFileInContainer]);
    let raw = '';
    let catDone = false;
    const CAT_TIMEOUT_MS = 15000;
    const catTimeout = setTimeout(() => {
      if (catDone) return;
      catDone = true;
      try { cat.kill('SIGKILL'); } catch {}
      broadcastToJob(jobId, { type: 'error', jobId, message: 'อ่านผล whatweb เกินเวลา — ลองรันใหม่' });
    }, CAT_TIMEOUT_MS);

    cat.on('error', (err) => {
      if (catDone) return;
      catDone = true;
      clearTimeout(catTimeout);
      broadcastToJob(jobId, { type: 'error', jobId, message: `อ่านผล whatweb ไม่สำเร็จ: ${err?.message || String(err)}` });
    });

    cat.stdout.on('data', (data) => {
      raw += data.toString();
    });
    cat.on('close', (catCode) => {
      if (catDone) return;
      catDone = true;
      clearTimeout(catTimeout);
      if (catCode !== 0 || !raw) {
        broadcastToJob(jobId, { type: 'error', jobId, message: 'Could not read whatweb output from container' });
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        const hostResultPath = path.join(targetDir, `whatweb-${round}.json`);
        fs.writeFileSync(hostResultPath, JSON.stringify(parsed, null, 2), 'utf8');
        const rel = path.relative(path.join(__dirname, '..'), hostResultPath);
        const scanAt = new Date().toISOString();
        insertWhatwebScan(target.target_id, rel, scanAt);
        broadcastToJob(jobId, {
          type: 'done',
          jobId,
          status: 'completed',
          resultFile: rel,
          scanAt,
        });
      } catch (err) {
        console.error('Failed to persist whatweb result:', err);
        broadcastToJob(jobId, { type: 'error', jobId, message: 'Error handling whatweb result' });
      }
    });
  });
}

module.exports = {
  startWhatwebScan,
};

