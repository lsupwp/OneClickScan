import { useState } from 'react'
import Empty from './Empty'

function stripAnsi(str) {
  if (typeof str !== 'string') return str
  return str.replace(/\x1b\[[0-9;]*m/g, '')
}

/**
 * Parse one fingerprint token into { plugin, values[] }.
 * e.g. "HTTPServer[nginx/1.19.0]" -> { plugin: "HTTPServer", values: ["nginx/1.19.0"] }
 *      "Country[UNITED STATES][US]" -> { plugin: "Country", values: ["UNITED STATES", "US"] }
 *      "Adobe-Flash" -> { plugin: "Adobe-Flash", values: [] }
 */
function parseToken(token) {
  const idx = token.indexOf('[')
  if (idx === -1) {
    const p = token.trim()
    return p ? { plugin: p, values: [] } : null
  }
  const plugin = token.slice(0, idx).trim()
  const rest = token.slice(idx)
  const values = []
  let i = 0
  while (rest[i] === '[') {
    const end = rest.indexOf(']', i)
    if (end === -1) break
    values.push(rest.slice(i + 1, end))
    i = end + 1
  }
  return { plugin, values }
}

/** Split by ", " only when not inside brackets (values can contain commas). */
function splitFingerprintTokens(rest) {
  const tokens = []
  let current = ''
  let depth = 0
  for (let i = 0; i < rest.length; i++) {
    const c = rest[i]
    if (c === '[') depth += 1
    else if (c === ']') depth -= 1
    else if (c === ',' && rest[i + 1] === ' ' && depth === 0) {
      tokens.push(current.trim())
      current = ''
      i += 1
      continue
    }
    current += c
  }
  if (current.trim()) tokens.push(current.trim())
  return tokens
}

/**
 * Parse whatweb fingerprint line into URL + list of { plugin, values }.
 */
function parseFingerprintLine(line) {
  const urlMatch = line.match(/^(https?:\/\/[^\s]+)\s*\[(\d+\s+OK)\]/)
  const url = urlMatch ? urlMatch[1] : ''
  const status = urlMatch ? urlMatch[2] : ''
  let rest = line
  if (urlMatch) rest = line.slice(urlMatch[0].length).trim()
  const findings = []
  const tokens = splitFingerprintTokens(rest)
  for (const token of tokens) {
    const parsed = parseToken(token)
    if (parsed) findings.push(parsed)
  }
  return { url, status, findings }
}

function parseWhatwebLines(lines) {
  if (!lines?.length) return null
  const cleaned = lines.map((l) => stripAnsi(l))
  const raw = cleaned.join('\n')
  const urlLine = cleaned.find((l) => /^https?:\/\//.test(l.trim()) || /\[\d{3}\s+OK\]/.test(l) || (l.includes('[') && l.includes(']')))
  const plusLines = cleaned.filter((l) => l.trim().startsWith('[+]'))
  let url = ''
  let status = ''
  let findings = []
  if (urlLine) {
    const fp = parseFingerprintLine(urlLine.trim())
    url = fp.url
    status = fp.status
    findings = fp.findings
  }
  return { raw, urlLine, url, status, findings, plusLines }
}

export default function WhatWebOutput({ lines }) {
  const [showRaw, setShowRaw] = useState(false)
  const parsed = parseWhatwebLines(lines)

  if (!parsed || (!parsed.urlLine && !parsed.plusLines?.length && !lines?.length)) {
    if (!lines?.length) return <Empty text="No output yet." />
    return (
      <div className="bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-300 max-h-[520px] overflow-y-auto whitespace-pre-wrap">
        {lines.map((l, i) => <div key={i}>{stripAnsi(l)}</div>)}
      </div>
    )
  }

  const { url, status, findings, plusLines, raw } = parsed

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between flex-wrap gap-2">
          <span className="font-semibold text-slate-800 text-sm">WhatWeb Fingerprint</span>
        </div>
        {url && (
          <div className="px-4 py-2 border-b border-slate-100 flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-slate-600 break-all">{url}</span>
            {status && <span className="text-xs font-medium text-green-600 bg-green-50 px-2 py-0.5 rounded">{status}</span>}
          </div>
        )}
        {findings.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-slate-100 text-slate-500 uppercase tracking-wide">
                <tr>
                  <th className="px-3 py-2 text-left w-36">Plugin</th>
                  <th className="px-3 py-2 text-left">Value</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr key={i} className="border-t border-slate-100 hover:bg-slate-50">
                    <td className="px-3 py-2 font-medium text-slate-700 align-top">{f.plugin}</td>
                    <td className="px-3 py-2 text-slate-600 font-mono break-all">
                      {f.values.length ? f.values.join(', ') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {plusLines.length > 0 && (
          <div className="px-4 py-3 bg-green-50/30 border-t border-slate-100 space-y-1">
            <p className="text-xs font-semibold text-slate-600 mb-1">Detected versions</p>
            {plusLines.map((l, i) => (
              <div key={i} className="font-mono text-xs text-slate-700">
                {l.trim()}
              </div>
            ))}
          </div>
        )}
        <div className="px-4 py-2 border-t border-slate-100">
          <button
            type="button"
            onClick={() => setShowRaw((v) => !v)}
            className="text-xs text-slate-500 hover:text-slate-700"
          >
            {showRaw ? 'ซ่อน' : 'แสดง'} raw output
          </button>
          {showRaw && (
            <pre className="mt-2 font-mono text-[11px] text-slate-500 bg-slate-50 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
              {raw}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}
