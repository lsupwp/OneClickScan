import Empty from './Empty'

export default function PathList({ paths }) {
  if (!paths?.length) return <Empty text="No paths discovered." />
  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center gap-3">
        <span className="text-xs font-semibold text-slate-600 uppercase tracking-wide">
          {paths.length} path{paths.length !== 1 ? 's' : ''} alive
        </span>
        <span className="text-xs text-green-600 bg-green-50 px-2 py-0.5 rounded-full font-medium">
          ✓ httpx filtered (404s removed)
        </span>
      </div>
      <div className="divide-y divide-slate-100 max-h-[520px] overflow-y-auto">
        {paths.map((p, i) => (
          <div key={i} className="px-4 py-1.5 font-mono text-xs text-slate-700 hover:bg-slate-50 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
            <a href={p} target="_blank" rel="noopener noreferrer"
              className="hover:text-blue-600 hover:underline truncate">{p}</a>
          </div>
        ))}
      </div>
    </div>
  )
}
