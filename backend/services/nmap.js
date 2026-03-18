const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { XMLParser } = require('fast-xml-parser');

const { getOrCreateTarget, getNmapScanRound, insertNmapScan } = require('../db');
const { broadcastToJob } = require('../websocket');

const RESULT_DIR = path.join(__dirname, '..', 'result');
const KALI_CONTAINER = process.env.KALI_CONTAINER_NAME || 'kali-engine';

if (!fs.existsSync(RESULT_DIR)) {
  fs.mkdirSync(RESULT_DIR, { recursive: true });
}

function sanitizeTargetName(targetName) {
  return targetName.replace(/[^a-zA-Z0-9_.-]+/g, '_');
}

/** Extract host (hostname or IP) from URL for nmap target */
function extractHostFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  try {
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
      trimmed = 'http://' + trimmed;
    }
    const u = new URL(trimmed);
    return u.hostname || null;
  } catch {
    return null;
  }
}

/** Split user extra options into array; allow only safe nmap-like args */
function parseExtraOptions(extraOptions) {
  if (!extraOptions || typeof extraOptions !== 'string') return [];
  const tokens = extraOptions.trim().split(/\s+/).filter(Boolean);
  const safe = [];
  for (const t of tokens) {
    if (/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(t) || /^-[a-zA-Z0-9]+$/.test(t) || /^--[a-zA-Z0-9-]+$/.test(t)) {
      safe.push(t);
    } else if (/^-?\d+$/.test(t) || /^[\d-,]+$/.test(t)) {
      safe.push(t);
    }
  }
  return safe;
}

function parseNmapXmlToJson(xmlString) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
  });
  const out = { hosts: [], summary: { totalHosts: 0, openPorts: 0 } };
  let doc;
  try {
    doc = parser.parse(xmlString);
  } catch (e) {
    return out;
  }
  const run = doc?.nmaprun;
  if (!run) return out;

  const hosts = Array.isArray(run.host) ? run.host : run.host ? [run.host] : [];
  for (const host of hosts) {
    const addr = host.address;
    const addrList = Array.isArray(addr) ? addr : addr ? [addr] : [];
    let ip = null;
    let hostname = null;
    for (const a of addrList) {
      const at = a['@_addrtype'];
      const ad = a['@_addr'];
      if (at === 'ipv4' || at === 'ipv6') ip = ad;
      if (at === 'user') hostname = ad;
    }
    if (!ip && addrList[0]) ip = addrList[0]['@_addr'];

    const ports = host.ports?.port;
    const portList = Array.isArray(ports) ? ports : ports ? [ports] : [];
    const openPorts = [];
    for (const p of portList) {
      const state = p.state?.['@_state'] || p.state;
      if (state !== 'open' && state !== 'open|filtered') continue;
      const portId = p['@_portid'] ?? p.portid;
      const protocol = p['@_protocol'] ?? p.protocol ?? 'tcp';
      const svc = p.service;
      const name = svc?.['@_name'] ?? svc?.name ?? null;
      const product = svc?.['@_product'] ?? svc?.product ?? null;
      const version = svc?.['@_version'] ?? svc?.version ?? null;
      openPorts.push({
        port: portId,
        protocol,
        state: state || 'open',
        service: name,
        product: product || null,
        version: version || null,
      });
    }

    const osBlock = host.os;
    let osName = null;
    if (osBlock?.osmatch) {
      const match = Array.isArray(osBlock.osmatch) ? osBlock.osmatch[0] : osBlock.osmatch;
      osName = match?.['@_name'] ?? match?.name ?? null;
    }

    out.hosts.push({
      ip,
      hostname: hostname || null,
      os: osName,
      ports: openPorts,
    });
    out.summary.openPorts += openPorts.length;
  }
  out.summary.totalHosts = out.hosts.length;
  return out;
}

async function startNmapScan({ targetUrl, jobId, extraOptions: extraOptionsRaw }) {
  const host = extractHostFromUrl(targetUrl);
  if (!host) {
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message: 'ไม่สามารถดึง host จาก URL ได้',
    });
    return;
  }

  const target = getOrCreateTarget(targetUrl);
  const round = getNmapScanRound(target.target_id);
  const safeTarget = sanitizeTargetName(targetUrl);
  const targetDir = path.join(RESULT_DIR, safeTarget);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

  const extraArgs = parseExtraOptions(extraOptionsRaw);
  const baseArgs = ['-sV', '-O', '--osscan-guess'];
  const nmapArgs = [...baseArgs, ...extraArgs, host, '-oX', '-'];

  broadcastToJob(jobId, {
    type: 'status',
    jobId,
    status: 'starting',
    message: `Starting nmap (${host})...`,
  });

  const args = ['exec', KALI_CONTAINER, 'nmap', ...nmapArgs];

  const docker = spawn('docker', args);
  let xmlOut = '';

  docker.stdout.on('data', (data) => {
    const chunk = data.toString();
    xmlOut += chunk;
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: chunk,
    });
  });

  docker.stderr.on('data', (data) => {
    broadcastToJob(jobId, {
      type: 'progress',
      jobId,
      message: data.toString(),
      stream: 'stderr',
    });
  });

  docker.on('error', (err) => {
    console.error('Failed to start docker (nmap):', err);
    broadcastToJob(jobId, {
      type: 'error',
      jobId,
      message: `Failed to start nmap: ${err?.message || String(err)}`,
    });
  });

  docker.on('close', (code) => {
    if (code !== 0) {
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: `nmap exited with code ${code}`,
      });
      return;
    }

    broadcastToJob(jobId, {
      type: 'status',
      jobId,
      status: 'processing',
      message: 'Saving result...',
    });

    try {
      const json = parseNmapXmlToJson(xmlOut);
      const resultPath = path.join(targetDir, `nmap-${round}.json`);
      fs.writeFileSync(resultPath, JSON.stringify(json, null, 2), 'utf8');
      const rel = path.relative(path.join(__dirname, '..'), resultPath);
      const scanAt = new Date().toISOString();
      insertNmapScan(target.target_id, rel, scanAt, extraOptionsRaw?.trim() || null);

      broadcastToJob(jobId, {
        type: 'done',
        jobId,
        status: 'completed',
        resultFile: rel,
        scanAt,
      });
    } catch (err) {
      console.error('Failed to save nmap result:', err);
      broadcastToJob(jobId, {
        type: 'error',
        jobId,
        message: err?.message || 'Error saving nmap result',
      });
    }
  });
}

module.exports = {
  startNmapScan,
};
