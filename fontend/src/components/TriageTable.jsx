import Empty from './Empty'

export default function TriageTable({ targets, onRunExploit, exploiting }) {
  const filtered = (targets || []).filter(t => t.suggested_commands?.length > 0)
  if (!filtered.length) return <Empty text="No actionable triage targets." />

  return (
    <div className="space-y-3">
      {filtered.map((t, i) => (
        <div key={i} className="bg-white rounded-xl border border-slate-200 p-4">
          <div className="flex items-start gap-4 flex-wrap">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded-full
                  ${t.confidence === 'high'   ? 'bg-red-100 text-red-700' :
                    t.confidence === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                                'bg-blue-100 text-blue-700'}`}>
                  {t.confidence || 'low'}
                </span>
                <span className="font-semibold text-slate-800 text-sm">{t.issue_type}</span>
              </div>
              <div className="text-xs text-slate-500 font-mono mt-1">{t.endpoint}</div>
              {t.description && (
                <div className="text-xs text-slate-600 mt-1.5">{t.description}</div>
              )}
            </div>
          </div>

          <div className="mt-3 space-y-1">
            <div className="text-xs font-semibold text-slate-500 mb-1">Suggested Commands</div>
            {t.suggested_commands.map((cmd, j) => (
              <div
                key={j}
                className="font-mono text-xs bg-slate-900 text-green-300 px-3 py-1.5 rounded-lg overflow-x-auto whitespace-pre"
              >
                {cmd}
              </div>
            ))}
          </div>
        </div>
      ))}

      {onRunExploit && (
        <div className="pt-2">
          <button
            onClick={onRunExploit}
            disabled={exploiting}
            className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-700
              disabled:opacity-50 text-white font-semibold text-sm rounded-xl shadow transition-all"
          >
            {exploiting
              ? <><span className="animate-spin">⚙️</span> Running exploits…</>
              : <>🔥 Run Exploits (executor --workers 6)</>}
          </button>
          <p className="text-xs text-slate-400 mt-1.5">
            Executes all suggested commands from triage.json with 6 workers.
          </p>
        </div>
      )}
    </div>
  )
}
