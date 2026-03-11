import { useState } from 'react'
import Empty from './Empty'

/**
 * Parse nmap -sV output lines into { header, rows, footer, raw }.
 * rows: { port, state, service, version }[]
 */
function parseNmapLines(lines) {
  if (!lines?.length) return null
  const raw = lines.join('\n')
  const all = raw.split('\n')
  const header = []
  const rows = []
  let i = 0
  while (i < all.length) {
    const line = all[i]
    if (/^PORT\s+STATE\s+SERVICE/.test(line) || /^PORT\s+STATE\s+STATE\s+SERVICE/.test(line)) {
      i += 1
      while (i < all.length) {
        const rowLine = all[i]
        if (!rowLine.trim()) break
        if (/Service detection performed|Nmap done|^$/.test(rowLine)) break
        const match = rowLine.match(/^(\d+\/tcp)\s+(open|closed|filtered)\s+(.+)$/)
        if (match) {
          const [, port, state, rest] = match
          const parts = rest.trim().split(/\s{2,}/)
          const service = parts[0] || rest.trim()
          const version = parts.slice(1).join(' ').trim() || ''
          rows.push({ port, state, service, version })
        }
        i += 1
      }
      break
    }
    header.push(line)
    i += 1
  }
  const footer = all.slice(i).filter(Boolean)
  return { header, rows, footer, raw }
}

export default function NmapOutput({ lines }) {
  const [showRaw, setShowRaw] = useState(false)
  const parsed = parseNmapLines(lines)

  if (!parsed || (!parsed.rows.length && !parsed.raw.trim())) {
    if (!lines?.length) return <Empty text="No output yet." />
    return (
      <div className="bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-300 max-h-[520px] overflow-y-auto whitespace-pre-wrap">
        {lines.map((l, i) => <div key={i}>{l}</div>)}
      </div>
    )
  }

  const { header, rows, footer, raw } = parsed
  const openPorts = rows.filter((r) => r.state === 'open')

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between flex-wrap gap-2">
          <span className="font-semibold text-slate-800 text-sm">Nmap Service Scan</span>
          {rows.length > 0 && (
            <span className="text-xs text-slate-500">
              {openPorts.length} open · {rows.length} total
            </span>
          )}
        </div>
        {header.length > 0 && (
          <div className="px-4 py-2 border-b border-slate-100">
            <p className="font-mono text-xs text-slate-500 truncate">{header.find((l) => l.includes('Nmap scan report')) || header[0]}</p>
          </div>
        )}
        {rows.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-slate-100 text-slate-500 uppercase tracking-wide">
                <tr>
                  <th className="px-3 py-2 text-left w-24">Port</th>
                  <th className="px-3 py-2 text-left w-24">State</th>
                  <th className="px-3 py-2 text-left">Service</th>
                  <th className="px-3 py-2 text-left min-w-[120px]">Version</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="border-t border-slate-100 hover:bg-slate-50">
                    <td className="px-3 py-2 font-mono text-slate-700">{r.port}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`font-medium ${
                          r.state === 'open' ? 'text-green-600' : r.state === 'filtered' ? 'text-amber-600' : 'text-slate-500'
                        }`}
                      >
                        {r.state}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-700">{r.service}</td>
                    <td className="px-3 py-2 font-mono text-slate-600">{r.version || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {openPorts.length > 0 && (
          <div className="px-4 py-2 bg-green-50/50 border-t border-slate-100 flex flex-wrap gap-2">
            {openPorts.map((r, i) => (
              <span key={i} className="text-xs font-medium text-green-700 bg-green-100 px-2 py-0.5 rounded">
                {r.port} | {r.service} {r.version}
              </span>
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
