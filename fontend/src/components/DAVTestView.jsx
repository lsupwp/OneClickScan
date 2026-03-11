import Empty from './Empty'

/**
 * Parse DAVTest stdout into structured data.
 */
function parseDAVTestLines(lines) {
  if (!lines?.length) return null

  let probeSummary = ''
  let noPaths = false
  const vulnerable = []
  const safe = []
  let currentVuln = null

  for (const line of lines) {
    const t = line.trim()
    if (!t || t.startsWith('===')) continue

    if (t.startsWith('[*] DAVTest:')) {
      probeSummary = t.replace(/^\[\*\]\s*DAVTest:\s*/i, '').trim()
      continue
    }
    if (/No DAV-like paths found or tested/i.test(t)) {
      noPaths = true
      continue
    }
    if (/VULNERABLE.*PUT upload allowed/i.test(t)) {
      currentVuln = null
      continue
    }
    if (t.startsWith('[CRITICAL]')) {
      const url = t.replace(/^\[CRITICAL\]\s*/i, '').trim()
      currentVuln = { url, methods: '', putStatus: '', notes: [] }
      vulnerable.push(currentVuln)
      continue
    }
    if (currentVuln) {
      if (t.startsWith('Methods')) {
        currentVuln.methods = t.replace(/^Methods\s*:\s*/i, '').trim()
        continue
      }
      if (/^PUT\s*:/.test(t)) {
        currentVuln.putStatus = t.replace(/^PUT\s*:\s*/i, '').trim()
        continue
      }
      if (t.startsWith('Note')) {
        currentVuln.notes.push(t.replace(/^Note\s*:\s*/i, '').trim())
        continue
      }
      currentVuln = null
      continue
    }
    if (t.startsWith('[+]') && /DAV path.*found/i.test(t)) {
      continue
    }
    if (t.startsWith('[-]')) {
      const rest = t.replace(/^\[-\]\s*/, '').trim()
      const urlMatch = rest.match(/^(\S+)\s+methods=\[(.*?)\]\s+PUT=(.*)$/)
      if (urlMatch) {
        safe.push({
          url: urlMatch[1],
          methods: urlMatch[2] || '—',
          putStatus: urlMatch[3] || '—',
        })
      }
    }
  }

  return { probeSummary, noPaths, vulnerable, safe }
}

export default function DAVTestView({ lines }) {
  const parsed = parseDAVTestLines(lines)

  if (!parsed && !lines?.length) return <Empty text="No output yet." />
  if (!parsed) {
    return (
      <div className="bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-300 max-h-[520px] overflow-y-auto whitespace-pre-wrap">
        {lines.map((l, i) => <div key={i}>{l}</div>)}
      </div>
    )
  }

  const { probeSummary, noPaths, vulnerable, safe } = parsed

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        {probeSummary && (
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center gap-2">
            <span className="text-xs text-slate-500">Probe</span>
            <span className="font-mono text-sm text-slate-700">{probeSummary}</span>
          </div>
        )}

        {noPaths && (
          <div className="px-4 py-10 text-center">
            <div className="text-slate-400 text-sm">No DAV-like paths found or tested.</div>
            <div className="text-xs text-slate-400 mt-1">Paths are filtered by wordlist; none matched.</div>
          </div>
        )}

        {vulnerable.length > 0 && (
          <div className="border-b border-slate-200">
            <div className="px-4 py-2 bg-red-50 border-b border-red-100 flex items-center gap-2">
              <span className="text-red-600 font-semibold text-sm">⚠ PUT upload allowed</span>
              <span className="text-xs text-red-600 bg-red-100 px-2 py-0.5 rounded-full">
                {vulnerable.length} path{vulnerable.length !== 1 ? 's' : ''}
              </span>
            </div>
            <div className="divide-y divide-slate-100">
              {vulnerable.map((v, i) => (
                <div key={i} className="px-4 py-3 hover:bg-red-50/50">
                  <a
                    href={v.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-sm font-semibold text-red-700 hover:underline block mb-1.5"
                  >
                    {v.url}
                  </a>
                  <div className="flex flex-wrap gap-3 text-xs text-slate-600">
                    <span><span className="text-slate-400">Methods</span> {v.methods || '—'}</span>
                    <span><span className="text-slate-400">PUT</span> {v.putStatus}</span>
                  </div>
                  {v.notes?.length > 0 && (
                    <div className="mt-1.5 text-xs text-slate-500 space-y-0.5">
                      {v.notes.map((n, j) => <div key={j}>{n}</div>)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {safe.length > 0 && (
          <div>
            <div className="px-4 py-2 bg-slate-50 border-b border-slate-100 text-xs font-semibold text-slate-500 uppercase tracking-wide">
              DAV paths (PUT not allowed)
            </div>
            <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
              {safe.map((s, i) => (
                <div key={i} className="px-4 py-2 hover:bg-slate-50 flex items-center gap-3 flex-wrap">
                  <a
                    href={s.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-slate-700 hover:text-blue-600 hover:underline truncate min-w-0 flex-1"
                  >
                    {s.url}
                  </a>
                  <span className="text-xs text-slate-400 shrink-0">methods: {s.methods}</span>
                  <span className="text-xs text-slate-400 shrink-0">PUT: {s.putStatus}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {!noPaths && vulnerable.length === 0 && safe.length === 0 && (
          <div className="px-4 py-8 text-center text-slate-400 text-sm">
            No structured output to display.
          </div>
        )}
      </div>
    </div>
  )
}
