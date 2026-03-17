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
const {
  listTargets,
  listKatanaByTarget,
  listFfufByTarget,
  getOrCreateTarget,
  getPayloadReconScanRound,
  insertPayloadRecon,
  listPayloadReconByTarget,
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

router.get('/targets/:targetId/payload-recon', (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!Number.isFinite(targetId)) {
    return res.status(400).json({ error: 'invalid targetId' });
  }
  res.status(200).json(listPayloadReconByTarget(targetId));
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
        insertPayloadRecon(target.target_id, rel, new Date().toISOString());
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
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(200).send(text);
  } catch (err) {
    console.error('Failed to read result file:', err);
    res.status(500).json({ error: 'failed to read file' });
  }
});

module.exports = router;