import Empty from './Empty'

// forms  = [{signature, method, action, body_params:{key:val}, query_params:{key:val}}]
// params = [{base_path, params:{key:val}}]

function sigUrl(sig = '') {
  // "METHOD|http://…/path|Q[…]|B[…]"
  return sig.split('|')[1] || sig
}

function toPath(fullUrl = '') {
  try { return new URL(fullUrl).pathname || fullUrl }
  catch { return fullUrl }
}

function ParamBadge({ name, value, variant }) {
  // variant: 'query' | 'body' | 'url'
  const styles = {
    query: 'bg-blue-50 text-blue-700',
    body:  'bg-purple-50 text-purple-700',
    url:   'bg-orange-50 text-orange-700',
  }
  const prefix = variant === 'query' ? '?' : ''
  const display = value && value !== '' ? `${prefix}${name}=${value}` : `${prefix}${name}`

  return (
    <span className={`text-xs px-2 py-0.5 rounded font-mono ${styles[variant] || styles.body}`}>
      {display}
    </span>
  )
}

export default function PayloadReconView({ forms, params }) {
  // normalise: accepts both array and legacy dict formats
  const formList  = Array.isArray(forms)  ? forms  : Object.values(forms  || {})
  const paramList = Array.isArray(params) ? params : Object.values(params || {})

  const hasForms  = formList.length  > 0
  const hasParams = paramList.length > 0

  if (!hasForms && !hasParams) return <Empty text="No forms or parameters found." />

  return (
    <div className="space-y-4">
      {hasForms && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
              Forms ({formList.length})
            </span>
          </div>

          <div className="divide-y divide-slate-100 max-h-[480px] overflow-y-auto">
            {formList.map((form, i) => {
              const url    = sigUrl(form.signature)
              const bpairs = Object.entries(form.body_params  || {})
              const qpairs = Object.entries(form.query_params || {})
              const method = (form.method || 'GET').toUpperCase()
              const foundPaths = form.found_on_paths || []

              const path   = toPath(url)
              const action = form.action && form.action !== '#' ? form.action : null
              const actionPath = action ? toPath(action) : null

              return (
                <div key={i} className="px-4 py-3 hover:bg-slate-50">
                  {/* ── "Found on" path(s) where this form was discovered ── */}
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-2">
                    <span className="text-xs text-slate-400 shrink-0">Found on</span>
                    {(foundPaths.length > 0 ? foundPaths : [url]).map((fp, j) => (
                      <a
                        key={j}
                        href={fp.startsWith('http') ? fp : url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs font-semibold text-slate-700 hover:text-blue-600 hover:underline"
                      >
                        {fp.startsWith('http') ? toPath(fp) : fp}
                      </a>
                    ))}
                  </div>

                  {/* ── method + action (always show where form submits) ── */}
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <span className={`text-xs font-bold px-1.5 py-0.5 rounded uppercase shrink-0
                      ${method === 'POST' ? 'bg-orange-100 text-orange-700' : 'bg-green-100 text-green-700'}`}>
                      {method}
                    </span>
                    <span className="text-xs text-slate-400">action</span>
                    {action && action !== '#' ? (
                      <a
                        href={action}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-blue-600 hover:underline"
                      >
                        {toPath(action)}
                      </a>
                    ) : (
                      <span className="font-mono text-xs text-slate-500"># (same page)</span>
                    )}
                  </div>

                  {/* ── params row ── */}
                  {(qpairs.length > 0 || bpairs.length > 0) && (
                    <div className="flex flex-wrap gap-1.5">
                      {qpairs.map(([k, v]) => (
                        <ParamBadge key={`q-${k}`} name={k} value={v} variant="query" />
                      ))}
                      {bpairs.map(([k, v]) => (
                        <ParamBadge key={`b-${k}`} name={k} value={v} variant="body" />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* legend */}
          <div className="px-4 py-1.5 bg-slate-50 border-t border-slate-100 flex gap-5 text-xs text-slate-400">
            <span>
              <span className="inline-block w-2 h-2 rounded bg-blue-200 mr-1" />
              ?param — query string
            </span>
            <span>
              <span className="inline-block w-2 h-2 rounded bg-purple-200 mr-1" />
              param — body field
            </span>
          </div>
        </div>
      )}

      {hasParams && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-4 py-2 bg-slate-50 border-b border-slate-200">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
              URL Entry Points ({paramList.length})
            </span>
          </div>

          <div className="divide-y divide-slate-100 max-h-80 overflow-y-auto">
            {paramList.map((ep, i) => (
              <div key={i} className="px-4 py-2.5 hover:bg-slate-50">
                <a
                  href={ep.base_path}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-slate-700 font-semibold hover:text-blue-600 hover:underline"
                >
                  {ep.base_path}
                </a>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {Object.entries(ep.params || {}).map(([k, v]) => (
                    <ParamBadge key={k} name={k} value={v} variant="url" />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
