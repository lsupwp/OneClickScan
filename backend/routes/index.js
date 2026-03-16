const express = require('express');
const fs = require('fs');
const path = require('path');

const { startKatanaScan, getKatanaFlags } = require('../services/katana');
const { listTargets, listKatanaByTarget } = require('../db');

const router = express.Router();

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