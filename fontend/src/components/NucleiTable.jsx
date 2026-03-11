import { SEV_COLOR } from '../constants'
import Empty from './Empty'

export default function NucleiTable({ findings }) {
  if (!findings?.length) return <Empty text="No Nuclei findings." />

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sorted = [...findings].sort(
    (a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9)
  )

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
      <table className="w-full text-xs">
        <thead className="bg-slate-100 text-slate-500 uppercase tracking-wide">
          <tr>
            <th className="px-3 py-2 text-left">Severity</th>
            <th className="px-3 py-2 text-left">Template</th>
            <th className="px-3 py-2 text-left">URL</th>
            <th className="px-3 py-2 text-left">Matched</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f, i) => (
            <tr key={i} className="border-t border-slate-100 hover:bg-slate-50">
              <td className={`px-3 py-1.5 font-semibold capitalize ${SEV_COLOR[f.severity] || 'text-slate-500'}`}>
                {f.severity}
              </td>
              <td className="px-3 py-1.5 text-slate-600 font-mono">{f.template_id}</td>
              <td className="px-3 py-1.5 text-slate-500 max-w-xs truncate">
                <a href={f.url} target="_blank" rel="noopener noreferrer"
                  className="hover:text-blue-600 hover:underline">{f.url}</a>
              </td>
              <td className="px-3 py-1.5 text-slate-500 max-w-xs truncate">{f.matched || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
