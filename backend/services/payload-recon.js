const { URL } = require('url');
const cheerio = require('cheerio');

/**
 * Extract query params from a URL (?a=1&b=2) as flat key->firstValue map.
 */
function extractUrlParams(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const out = {};
    for (const [k, v] of u.searchParams.entries()) {
      if (!(k in out)) out[k] = v;
    }
    return Object.keys(out).length ? out : null;
  } catch {
    return null;
  }
}

function inferFieldName($el) {
  const candidates = [
    'name',
    'formcontrolname',
    'id',
    'placeholder',
    'aria-label',
  ];
  for (const attr of candidates) {
    const value = $el.attr(attr);
    if (!value) continue;
    const cleaned = String(value).trim().replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '');
    if (cleaned) return cleaned;
  }
  return null;
}

function extractFormsFromHtml(sourceUrl, html) {
  const $ = cheerio.load(html);
  const mapped = [];

  const baseUrl = sourceUrl.split('#')[0];

  $('form').each((_, form) => {
    const $form = $(form);
    const actionAttr = $form.attr('action') || '';
    const formId = ($form.attr('id') || '').trim() || null;
    const formName = ($form.attr('name') || '').trim() || null;

    let fullUrl;
    try {
      fullUrl = new URL(actionAttr || baseUrl, baseUrl).toString();
    } catch {
      fullUrl = baseUrl;
    }

    fullUrl = fullUrl.split('#')[0] || baseUrl;
    const method = ($form.attr('method') || 'GET').toUpperCase();

    const u = new URL(fullUrl, baseUrl);
    const queryParams = {};
    for (const [k, v] of u.searchParams.entries()) {
      if (!(k in queryParams)) queryParams[k] = v;
    }

    const bodyParams = {};
    $form.find('input, textarea, select').each((idx, el) => {
      const $el = $(el);
      const name = inferFieldName($el, idx);
      if (!name) return;
      const value = $el.attr('value') || '';
      bodyParams[name] = value;
    });

    mapped.push({
      target_action: u.origin + u.pathname,
      method,
      query_params: queryParams,
      body_params: bodyParams,
      form_id: formId,
      form_name: formName,
    });
  });

  if (mapped.length) return mapped;

  // Fallback: pages with inputs but no <form> (often SPA-style logins)
  const inputs = $('input, textarea, select');
  const passwordInputs = $('input[type="password"]');
  if (inputs.length && passwordInputs.length) {
    const bodyParams = {};
    inputs.each((idx, el) => {
      const $el = $(el);
      const name = inferFieldName($el, idx);
      if (!name) return;
      const value = $el.attr('value') || '';
      bodyParams[name] = value;
    });

    let u;
    try {
      u = new URL(baseUrl);
    } catch {
      u = null;
    }
    const queryParams = {};
    if (u) {
      for (const [k, v] of u.searchParams.entries()) {
        if (!(k in queryParams)) queryParams[k] = v;
      }
    }

    mapped.push({
      target_action: baseUrl.split('?')[0],
      method: 'POST',
      query_params: queryParams,
      body_params: bodyParams,
    });
  }

  return mapped;
}

async function httpGet(url, timeoutMs, extraHeaders) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  // Use global fetch if available (Node 18+), otherwise fall back to node-fetch.
  const doFetch =
    typeof fetch === 'function'
      ? fetch
      : (...args) =>
          import('node-fetch').then((m) => m.default(...args));

  try {
    const res = await doFetch(url, {
      method: 'GET',
      headers: extraHeaders || {},
      redirect: 'follow',
      signal: controller.signal,
    });
    const text = await res.text();
    return { status: res.status, url: res.url || url, text };
  } catch (err) {
    return { status: 0, url, text: '', error: err };
  } finally {
    clearTimeout(id);
  }
}

async function mapForms(url, { timeout = 5000, extraHeaders } = {}) {
  const targetUrl = url.split('#')[0];
  const resp = await httpGet(targetUrl, timeout, extraHeaders);

  if (resp.status === 404 || !resp.text) return [];

  let finalUrl = resp.url || targetUrl;
  try {
    const orig = new URL(targetUrl);
    const fin = new URL(finalUrl);
    const origPath = orig.pathname.toLowerCase().replace(/\/+$/, '');
    const finalPath = fin.pathname.toLowerCase().replace(/\/+$/, '');
    if (
      origPath !== finalPath &&
      (finalPath.includes('/login') ||
        finalPath.includes('/signin') ||
        finalPath.includes('/auth'))
    ) {
      return [];
    }
  } catch {
    // ignore URL parse errors
  }

  const html = resp.text || '';
  const mapped = extractFormsFromHtml(finalUrl, html);
  return mapped;
}

async function runPayloadRecon(paths, { timeout = 5000, extraHeaders } = {}) {
  const groupedForms = new Map(); // sig -> { details, paths:Set }
  const inferredByBase = new Map(); // basePath -> { params: {}, exampleUrls:Set }

  const uniquePaths = Array.from(new Set(paths.filter((p) => typeof p === 'string' && p)));

  for (const p of uniquePaths) {
    let formsFound = [];
    let uParams = null;
    try {
      // eslint-disable-next-line no-await-in-loop
      formsFound = await mapForms(p, { timeout, extraHeaders });
      uParams = extractUrlParams(p);
    } catch {
      continue;
    }

    for (const f of formsFound) {
      const qKeys = Object.keys(f.query_params || {}).sort();
      const bKeys = Object.keys(f.body_params || {}).sort();
      const sig = `${f.method}|${f.target_action}|FID${f.form_id || ''}|FNM${f.form_name || ''}|Q${qKeys.join(',')}|B${bKeys.join(',')}`;
      if (!groupedForms.has(sig)) {
        groupedForms.set(sig, {
          details: {
            target_action: f.target_action,
            method: f.method,
            query_params: { ...(f.query_params || {}) },
            body_params: { ...(f.body_params || {}) },
            form_id: f.form_id || null,
            form_name: f.form_name || null,
          },
          paths: new Set(),
        });
      }
      groupedForms.get(sig).paths.add(p);
    }

    if (uParams) {
      const basePath = p.split('?')[0];
      if (!inferredByBase.has(basePath)) {
        inferredByBase.set(basePath, {
          params: {},
          exampleUrls: new Set(),
        });
      }
      const info = inferredByBase.get(basePath);
      for (const [k, v] of Object.entries(uParams)) {
        if (!(k in info.params)) info.params[k] = v;
      }
      info.exampleUrls.add(p);
    }
  }

  const usedBases = new Set();
  // IMPORTANT: do NOT merge inferred URL query params into ALL forms with same action.
  // Example: wp-login.php?action=lostpassword would pollute the normal login form.
  for (const [, data] of groupedForms.entries()) {
    const details = data.details;
    details.example_urls = Array.from(data.paths).slice(0, 5);
    usedBases.add(details.target_action);
  }

  const out = [];

  for (const [, data] of groupedForms.entries()) {
    const details = data.details;
    out.push({
      found_in: Array.from(data.paths),
      action: details.target_action,
      method: details.method,
      query_string: details.query_params || {},
      payload: details.body_params || {},
      example_urls: details.example_urls || [],
      form_id: details.form_id || null,
      form_name: details.form_name || null,
    });
  }

  for (const [basePath, info] of inferredByBase.entries()) {
    if (usedBases.has(basePath)) continue;
    const params = info.params || {};
    out.push({
      found_in: Array.from(info.exampleUrls || []),
      action: basePath,
      method: 'GET',
      query_string: params,
      payload: {},
      example_urls: Array.from(info.exampleUrls || []),
    });
  }

  return out;
}

module.exports = {
  runPayloadRecon,
};

