const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const { startKatanaScan, getKatanaFlags } = require('../services/katana');
const {
  startFfufScan,
  WORDLIST_UPLOAD_DIR,
} = require('../services/ffuf-hidden-path');
const { runPayloadRecon } = require('../services/payload-recon');
const { analyzePayloadReconWithGemini } = require('../services/payload-analyze');
const { startNucleiScan } = require('../services/nuclei');
const { startWhatwebScan } = require('../services/whatweb');
const { startSubfinderScan } = require('../services/subfinder');
const { startLanScan } = require('../services/lan-scanner');
const { startNmapScan } = require('../services/nmap');
const { startPayloadToolRun } = require('../services/payload-run');
const {
  listTargets,
  listKatanaByTarget,
  listFfufByTarget,
  listNucleiByTarget,
  listWhatwebByTarget,
  listSubfinderByTarget,
  listNmapByTarget,
  getOrCreateTarget,
  getPayloadReconScanRound,
  insertPayloadRecon,
  listPayloadReconByTarget,
  getPayloadReconById,
  insertPayloadReconAi,
  listPayloadReconAiByRecon,
  listPayloadToolRunsByRecon,
} = require('../db');

const router = express.Router();

const wordlistStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, WORDLIST_UPLOAD_DIR),
  filename: (req, file, cb) => {
    const id = require('crypto').randomUUID();
    cb(null, `${id}.txt`);
  },
});
const uploadWordlist = multer({
  storage: wordlistStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (ext !== '.txt') {
      return cb(new Error('Only .txt wordlist files are allowed'), false);
    }
    cb(null, true);
  },
});

router.get('/status', (req, res) => {
  res.status(200).json({ message: 'Server is running' });
});

router.get('/tools/katana/flags', (req, res) => {
  res.status(200).json(getKatanaFlags());
});

router.post('/scan/katana', async (req, res) => {
  const { target_url: targetUrl, flags } = req.body || {};

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }

  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

  try {
    await startKatanaScan({
      targetUrl,
      userFlags: Array.isArray(flags) ? flags : undefined,
      jobId,
    });

    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start katana scan:', err);
    res.status(500).json({ error: 'Failed to start katana scan' });
  }
});

router.get('/targets', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  const limit = Number(req.query.limit || 50);
  const offset = Number(req.query.offset || 0);
  res.status(200).json(
    listTargets({
      q,
      limit: Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 200) : 50,
      offset: Number.isFinite(offset) ? Math.max(offset, 0) : 0,
    })
  );
});

router.get('/targets/:targetId/katana', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listKatanaByTarget(targetId));
});

router.get('/targets/:targetId/ffuf', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listFfufByTarget(targetId));
});

router.get('/targets/:targetId/nuclei', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listNucleiByTarget(targetId));
});

router.get('/targets/:targetId/whatweb', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listWhatwebByTarget(targetId));
});

router.get('/targets/:targetId/subfinder', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listSubfinderByTarget(targetId));
});

router.get('/targets/:targetId/payload-recon', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listPayloadReconByTarget(targetId));
});

router.get('/targets/:targetId/nmap', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listNmapByTarget(targetId));
});

router.post('/scan/nuclei', async (req, res) => {
  const { target_url: targetUrl } = req.body || {};
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }
  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  try {
    await startNucleiScan({ targetUrl, jobId });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start nuclei scan:', err);
    res.status(500).json({ error: 'Failed to start nuclei scan' });
  }
});

router.post('/scan/whatweb', async (req, res) => {
  const { target_url: targetUrl, aggression, plugins } = req.body || {};
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }
  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  try {
    await startWhatwebScan({ targetUrl, jobId, aggression, plugins });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start whatweb scan:', err);
    res.status(500).json({ error: 'Failed to start whatweb scan' });
  }
});

router.post('/scan/subfinder', async (req, res) => {
  const { target_url: targetUrl, httpx_timeout_sec: httpxTimeoutSec } = req.body || {};
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }
  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  try {
    await startSubfinderScan({ targetUrl, jobId, httpxTimeoutSec });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start subfinder scan:', err);
    res.status(500).json({ error: 'Failed to start subfinder scan' });
  }
});

router.post('/scan/nmap', async (req, res) => {
  const { target_url: targetUrl, extra_options: extraOptions } = req.body || {};
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }
  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  try {
    await startNmapScan({
      targetUrl: targetUrl.trim(),
      jobId,
      extraOptions: typeof extraOptions === 'string' ? extraOptions : '',
    });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start nmap scan:', err);
    res.status(500).json({ error: 'Failed to start nmap scan' });
  }
});

router.post('/scan/lan', async (req, res) => {
  const { cidr, mode, ports } = req.body || {};

  if (!cidr || typeof cidr !== 'string') {
    return res.status(400).json({ error: 'cidr is required' });
  }

  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

  try {
    await startLanScan({
      cidr: cidr.trim(),
      mode: mode === 'accurate' ? 'accurate' : 'fast',
      ports: typeof ports === 'string' && ports.trim() ? ports.trim() : 'top100',
      jobId,
    });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start lan scan:', err);
    res.status(500).json({ error: 'Failed to start lan scan' });
  }
});

router.post('/upload/wordlist', (req, res, next) => {
  uploadWordlist.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    next();
  });
}, (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded; use field name "file" and .txt only' });
  }
  const fileId = path.basename(req.file.filename, '.txt');
  res.status(200).json({ fileId });
});

router.post('/scan/ffuf', async (req, res) => {
  const { target_url: targetUrl, wordlist, flags } = req.body || {};

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'target_url is required' });
  }

  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

  try {
    await startFfufScan({
      targetUrl,
      wordlist: wordlist === 'default' ? 'default' : wordlist,
      extraFlags: Array.isArray(flags) ? flags : undefined,
      jobId,
    });
    res.status(202).json({ jobId });
  } catch (err) {
    console.error('Failed to start ffuf scan:', err);
    res.status(500).json({ error: 'Failed to start ffuf scan' });
  }
});

router.post('/payload/recon', async (req, res) => {
  const { urls, headers, target_url: targetUrl } = req.body || {};

  if (!Array.isArray(urls) || urls.length === 0) {
    return res
      .status(400)
      .json({ error: 'urls must be a non-empty array of strings' });
  }

  const paths = urls.filter((u) => typeof u === 'string' && u.trim());
  if (!paths.length) {
    return res
      .status(400)
      .json({ error: 'urls must contain at least one non-empty string' });
  }

  const extraHeaders =
    headers && typeof headers === 'object' ? headers : undefined;

  try {
    const result = await runPayloadRecon(paths, {
      timeout: 7000,
      extraHeaders,
    });

    // Optional: persist result for reuse in UI
    if (targetUrl && typeof targetUrl === 'string') {
      try {
        const target = getOrCreateTarget(targetUrl);
        const round = getPayloadReconScanRound(target.target_id);
        const safeTarget = targetUrl.replace(/[^a-zA-Z0-9_.-]+/g, '_');
        const baseDir = path.join(__dirname, '..', 'result', safeTarget);
        if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
        const outFile = path.join(baseDir, `payload-recon-${round}.json`);
        fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
        const rel = path.relative(path.join(__dirname, '..'), outFile);
        const scanAt = new Date().toISOString();
        const payloadReconId = insertPayloadRecon(target.target_id, rel, scanAt);
        res.setHeader('X-Payload-Recon-Id', String(payloadReconId));
        res.setHeader('X-Payload-Recon-Result-File', rel);

        // Auto-analyze after payload recon if not already analyzed successfully.
        // If the latest AI result is an error, allow retry.
        setImmediate(async () => {
          try {
            const existing = listPayloadReconAiByRecon(payloadReconId);
            if (existing && existing.length && !existing[0].error) return;
            const model = process.env.GEMINI_MODEL || null;
            const aiOut = await analyzePayloadReconWithGemini(result);
            const aiFile = path.join(baseDir, `payload-recon-ai-${payloadReconId}-${Date.now()}.json`);
            fs.writeFileSync(aiFile, JSON.stringify(aiOut, null, 2), 'utf8');
            const aiRel = path.relative(path.join(__dirname, '..'), aiFile);
            insertPayloadReconAi(payloadReconId, aiRel, model, null, new Date().toISOString());
          } catch (e) {
            try {
              const aiFile = path.join(baseDir, `payload-recon-ai-${payloadReconId}-${Date.now()}.json`);
              fs.writeFileSync(aiFile, JSON.stringify({ error: String(e?.message || e) }, null, 2), 'utf8');
              const aiRel = path.relative(path.join(__dirname, '..'), aiFile);
              insertPayloadReconAi(payloadReconId, aiRel, process.env.GEMINI_MODEL || null, String(e?.message || e), new Date().toISOString());
            } catch (err2) {
              console.error('Failed to persist payload recon AI error:', err2);
            }
          }
        });
      } catch (e) {
        console.error('Failed to persist payload recon result:', e);
      }
    }

    res.status(200).json(result);
  } catch (err) {
    console.error('payload/recon failed:', err);
    res.status(500).json({ error: 'payload recon failed' });
  }
});

router.post('/payload/analyze', async (req, res) => {
  try {
    const { entries, payload_recon_id: payloadReconId } = req.body || {};
    const prId = Number(payloadReconId);

    if (Number.isFinite(prId) && prId > 0) {
      const existing = listPayloadReconAiByRecon(prId);
      if (existing && existing.length) {
        const latest = existing[0];
        // If latest is success, never re-run.
        // If latest is error, allow retry only when entries are provided.
        if (!latest.error) {
        try {
          const baseDir = path.join(__dirname, '..', 'result');
          const abs = path.resolve(path.join(__dirname, '..', latest.result_file));
          if (!abs.startsWith(baseDir + path.sep) || !fs.existsSync(abs)) {
            return res.status(404).json({ error: 'analysis file not found' });
          }
          const text = fs.readFileSync(abs, 'utf8');
          const parsed = JSON.parse(text);
          if (Array.isArray(parsed)) return res.status(200).json(parsed);
          return res.status(500).json({ error: parsed?.error || latest.error || 'analysis failed' });
        } catch (e) {
          return res.status(500).json({ error: e?.message || 'failed to read analysis file' });
        }
        }
      }
    }

    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'entries must be a non-empty array' });
    }

    const out = await analyzePayloadReconWithGemini(entries);

    if (Number.isFinite(prId) && prId > 0) {
      try {
        // persist analysis next to the payload recon result (same target folder)
        const pr = getPayloadReconById(prId);
        const baseResultDir = path.join(__dirname, '..', 'result');
        const prAbs = pr?.result_file
          ? path.resolve(path.join(__dirname, '..', pr.result_file))
          : null;
        const targetDir =
          prAbs && prAbs.startsWith(baseResultDir + path.sep)
            ? path.dirname(prAbs)
            : baseResultDir;

        const aiFile = path.join(targetDir, `payload-recon-ai-${prId}-${Date.now()}.json`);
        fs.writeFileSync(aiFile, JSON.stringify(out, null, 2), 'utf8');
        const aiRel = path.relative(path.join(__dirname, '..'), aiFile);
        insertPayloadReconAi(prId, aiRel, process.env.GEMINI_MODEL || null, null, new Date().toISOString());
      } catch (e) {
        console.error('Failed to persist payload analyze:', e);
      }
    }

    return res.status(200).json(out);
  } catch (err) {
    console.error('payload/analyze failed:', err);
    res.status(500).json({ error: err?.message || 'payload analyze failed' });
  }
});

router.get('/payload/runs', (req, res) => {
  const prId = Number(req.query.payload_recon_id);
  if (!Number.isFinite(prId)) return res.status(400).json({ error: 'payload_recon_id is required' });
  res.status(200).json(listPayloadToolRunsByRecon(prId));
});

router.post('/payload/run', async (req, res) => {
  const { payload_recon_id: payloadReconId, cmd } = req.body || {};
  const prId = Number(payloadReconId);
  if (!Number.isFinite(prId)) {
    return res.status(400).json({ error: 'payload_recon_id is required' });
  }
  if (!cmd || typeof cmd !== 'string') {
    return res.status(400).json({ error: 'cmd is required' });
  }

  const jobId =
    Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

  try {
    const { runId, outputFile, tool } = await startPayloadToolRun({ payloadReconId: prId, jobId, cmd });
    res.status(202).json({ jobId, runId, outputFile, tool });
  } catch (err) {
    console.error('Failed to start payload run:', err);
    res.status(500).json({ error: err?.message || 'Failed to start payload run' });
  }
});

router.get('/result', (req, res) => {
  const rel = typeof req.query.path === 'string' ? req.query.path : '';
  if (!rel) return res.status(400).json({ error: 'path is required' });

  const baseDir = path.join(__dirname, '..', 'result');
  const abs = path.resolve(path.join(__dirname, '..', rel));

  // allow only files under backend/result
  if (!abs.startsWith(baseDir + path.sep)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  if (!fs.existsSync(abs)) {
    return res.status(404).json({ error: 'not found' });
  }

  try {
    const text = fs.readFileSync(abs, 'utf8');
    const ext = path.extname(abs).toLowerCase();
    res.setHeader('Content-Type', ext === '.json' ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8');
    res.status(200).send(text);
  } catch (err) {
    console.error('Failed to read result file:', err);
    res.status(500).json({ error: 'failed to read file' });
  }
});

module.exports = router;