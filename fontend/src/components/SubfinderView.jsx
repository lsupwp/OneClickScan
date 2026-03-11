import Empty from './Empty'

/**
 * Parse subfinder stdout lines into { rootDomain, totalFound, aliveCount, urls }.
 */
function parseSubfinderLines(lines) {
  if (!lines?.length) return null
  let rootDomain = ''
  let totalFound = 0
  let aliveCount = 0
  const urls = []

  for (const line of lines) {
    const t = line.trim()
    if (!t || t.startsWith('===') || t.startsWith('[*]') || t.startsWith('[')) continue
    if (t.startsWith('Root domain:')) {
      rootDomain = t.replace(/^Root domain:\s*/i, '').trim()
      continue
    }
    if (t.startsWith('Total found:')) {
      const match = t.match(/Total found:\s*(\d+)\s*\|\s*Alive \(httpx\):\s*(\d+)/i)
      if (match) {
        totalFound = parseInt(match[1], 10)
        aliveCount = parseInt(match[2], 10)
      }
      continue
    }
    if (t.startsWith('http://') || t.startsWith('https://')) {
      urls.push(t)
      continue
    }
    if (t.startsWith('... and ') && t.endsWith(' more')) continue
  }

  return { rootDomain, totalFound, aliveCount, urls }
}

export default function SubfinderView({ lines }) {
  const parsed = parseSubfinderLines(lines)

  if (!parsed || (!parsed.rootDomain && !parsed.urls.length)) {
    if (!lines?.length) return <Empty text="No output yet." />
    return (
      <div className="bg-slate-900 rounded-xl p-4 font-mono text-xs text-slate-300 max-h-[520px] overflow-y-auto whitespace-pre-wrap">
        {lines.map((l, i) => <div key={i}>{l}</div>)}
      </div>
    )
  }

  const { rootDomain, totalFound, aliveCount, urls } = parsed

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center gap-3">
          {rootDomain && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500 uppercase tracking-wide">Root domain</span>
              <span className="font-mono text-sm font-semibold text-slate-800 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
                {rootDomain}
              </span>
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="text-xs bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full font-medium">
              {totalFound} found
            </span>
            <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full font-medium">
              {aliveCount} alive
            </span>
          </div>
        </div>

        <div className="px-4 py-2 border-b border-slate-100 text-xs text-slate-500">
          Subdomains that responded (httpx)
        </div>

        <div className="divide-y divide-slate-100 max-h-[480px] overflow-y-auto">
          {urls.length === 0 ? (
            <div className="px-4 py-8 text-center text-slate-400 text-sm">No alive subdomains</div>
          ) : (
            urls.map((u, i) => (
              <div
                key={i}
                className="px-4 py-2.5 hover:bg-slate-50 flex items-center gap-3 group"
              >
                <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                <a
                  href={u}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm text-blue-600 hover:text-blue-800 hover:underline truncate flex-1 min-w-0"
                >
                  {u}
                </a>
                <span className="text-slate-300 group-hover:text-slate-500 text-xs shrink-0">
                  ↗
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
