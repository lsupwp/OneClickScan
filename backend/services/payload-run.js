const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const { getPayloadReconById, insertPayloadToolRun, updatePayloadToolRun } = require('../db');
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

function validateCommand(cmd) {
  const s = String(cmd || '').trim();
  if (!s) return { ok: false, reason: 'cmd is required' };

  // Must start with an allowed tool
  const first = s.split(/\s+/)[0]?.toLowerCase();
  if (!['sqlmap', 'xsstrike', 'curl'].includes(first)) {
    return { ok: false, reason: 'only sqlmap/xsstrike/curl are allowed' };
  }

  // Disallow obvious shell chaining / redirection
  const banned = ['&&', '||', ';', '|', '>', '<', '`', '$('];
  for (const b of banned) {
    if (s.includes(b)) return { ok: false, reason: `forbidden token: ${b}` };
  }

  return { ok: true, cmd: s, tool: first };
}

async function startPayloadToolRun({ payloadReconId, jobId, cmd }) {
  const pr = getPayloadReconById(payloadReconId);
  if (!pr) throw new Error('payload_recon not found');

  const v = validateCommand(cmd);
  if (!v.ok) throw new Error(v.reason);

  const safeTarget = sanitizeTargetName(pr.target_name);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const startedAt = new Date().toISOString();
  const outName = `payload-run-${payloadReconId}-${sanitizeJobId(jobId)}.txt`;
  const hostResultPath = path.join(targetDir, outName);
  const rel = path.relative(path.join(__dirname, '..'), hostResultPath);

  const runId = insertPayloadToolRun(payloadReconId, v.tool, v.cmd, rel, 'running', null, startedAt, null);

  broadcastToJob(jobId, { type: 'status', jobId, status: 'starting', message: `Running ${v.tool}...`, runId, outputFile: rel });

  const ws = fs.createWriteStream(hostResultPath, { flags: 'a' });
  ws.write(`# oneclickscan payload run\n`);
  ws.write(`# started_at: ${startedAt}\n`);
  ws.write(`# tool: ${v.tool}\n`);
  ws.write(`# cmd: ${v.cmd}\n\n`);

  // Use bash -lc for quoting support, but with validation above
  const docker = spawn('docker', ['exec', KALI_CONTAINER, 'bash', '-lc', v.cmd], {
    env: process.env,
  });

  const push = (chunk, stream) => {
    const text = chunk.toString();
    ws.write(text);
    broadcastToJob(jobId, { type: 'progress', jobId, message: text, stream, runId });
  };

  docker.stdout.on('data', (d) => push(d, 'stdout'));
  docker.stderr.on('data', (d) => push(d, 'stderr'));

  docker.on('error', (err) => {
    const finishedAt = new Date().toISOString();
    try {
      ws.write(`\n\n# error: ${err?.message || String(err)}\n`);
      ws.end();
    } catch {}
    updatePayloadToolRun(runId, 'error', 1, finishedAt);
    broadcastToJob(jobId, { type: 'error', jobId, message: `run failed: ${err?.message || String(err)}`, runId, outputFile: rel });
  });

  docker.on('close', (code) => {
    const finishedAt = new Date().toISOString();
    try {
      ws.write(`\n\n# finished_at: ${finishedAt}\n# exit_code: ${code}\n`);
      ws.end();
    } catch {}

    if (code === 0) {
      updatePayloadToolRun(runId, 'done', 0, finishedAt);
      broadcastToJob(jobId, { type: 'done', jobId, status: 'completed', runId, outputFile: rel, scanAt: finishedAt });
    } else {
      updatePayloadToolRun(runId, 'error', code ?? 1, finishedAt);
      broadcastToJob(jobId, { type: 'error', jobId, message: `command exited with code ${code}`, runId, outputFile: rel });
    }
  });

  return { runId, outputFile: rel, tool: v.tool };
}

module.exports = {
  startPayloadToolRun,
};

