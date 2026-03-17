const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const { broadcastToJob } = require('../websocket');

const RESULT_DIR = path.join(__dirname, '..', 'result');

if (!fs.existsSync(RESULT_DIR)) {
  fs.mkdirSync(RESULT_DIR, { recursive: true });
}

function sanitizeJobId(jobId) {
  return String(jobId).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getLanScannerCommand() {
  if (process.env.LAN_SCANNER_BIN && process.env.LAN_SCANNER_BIN.trim()) {
    return process.env.LAN_SCANNER_BIN.trim();
  }
  const bin = process.platform === 'win32' ? 'lan-scan.exe' : 'lan-scan';
  return path.join(__dirname, '..', '..', 'lan-scanner', '.venv', 'bin', bin);
}

function startLanScan({ cidr, mode = 'fast', ports = 'top100', jobId }) {
  const safeJobId = sanitizeJobId(jobId);
  const outFile = path.join(RESULT_DIR, 'lan', `lan-scan-${safeJobId}.json`);
  const outDir = path.dirname(outFile);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const cmd = getLanScannerCommand();
  const args = [cidr, '--ports', String(ports || 'top100'), '--mode', mode === 'accurate' ? 'accurate' : 'fast', '--json-out', outFile];

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: `Starting LAN scan on ${cidr}...`,
  });

  const child = spawn(cmd, args, {
    env: process.env,
  });

  child.stdout.on('data', (data) => {
    const text = data.toString();
    if (!text.trim()) return;
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: text,
    });
  });

  child.stderr.on('data', (data) => {
    const text = data.toString();
    if (!text.trim()) return;
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: text,
      stream: 'stderr',
    });
  });

  child.on('error', (err) => {
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message: `Failed to start lan-scan: ${err?.message || String(err)}`,
    });
  });

  child.on('close', (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `lan-scan exited with code ${code}`,
      });
      return;
    }

    // At this point JSON should be written; just confirm file exists.
    const rel = path.relative(path.join(__dirname, '..'), outFile);
    broadcastToJob(jobId, {
      type: 'done',
      jobId,
      status: 'completed',
      resultFile: rel,
    });
  });
}

module.exports = {
  startLanScan,
};

