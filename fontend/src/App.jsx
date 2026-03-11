import { useState, useRef, useEffect, useCallback } from 'react'

import { TOOLS, toolFor, EXPLOIT_SUBTOOLS } from './constants'
import { loadSession, saveSession, clearSession } from './lib/session'

import Empty            from './components/Empty'
import StatusDot        from './components/StatusDot'
import ToolCheckbox     from './components/ToolCheckbox'
import PathList         from './components/PathList'
import TextOutput       from './components/TextOutput'
import ExploitOutput    from './components/ExploitOutput'
import ScanningOverlay  from './components/ScanningOverlay'
import NucleiTable      from './components/NucleiTable'
import TriageTable      from './components/TriageTable'
import PayloadReconView from './components/PayloadReconView'
import SubfinderView from './components/SubfinderView'
import DAVTestView from './components/DAVTestView'
import NmapOutput from './components/NmapOutput'
import WhatWebOutput from './components/WhatWebOutput'

// ── Tab header helper ─────────────────────────────────────────────────────────
function TabHeader({ tool, status }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="text-xl">{tool?.icon}</span>
      <span className="font-bold text-slate-800 text-base">{tool?.label}</span>
      {status === 'running' && (
        <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full animate-pulse">
          Running…
        </span>
      )}
      {status === 'done' && (
        <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">Done</span>
      )}
    </div>
  )
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  // ── restore from localStorage on first render ────────────────────────────
  const _saved = loadSession()

  const [url, setUrl]             = useState(_saved?.url      ?? '')
  const [selected, setSelected]   = useState(_saved?.selected ?? { path_recon: true, payload_recon: true, ai_triage: true })
  const [running, setRunning]     = useState(false)
  const [activeTab, setActiveTab] = useState(_saved?.activeTab ?? null)
  const [scanningTool, setScanningTool] = useState(null)

  // per-tool: { status:'idle'|'running'|'done', lines:[], data:any }
  const [toolState, setToolState] = useState(() => {
    if (!_saved?.toolState) return {}
    const ts = { ..._saved.toolState }
    Object.keys(ts).forEach(k => {
      if (ts[k].status === 'running') ts[k] = { ...ts[k], status: 'done' }
    })
    return ts
  })
  const [result, setResult]           = useState(_saved?.result      ?? null)
  const [exploiting, setExploiting]   = useState(false)
  const [exploitLines, setExploitLines] = useState(_saved?.exploitLines ?? [])
  const [exploitSummary, setExploitSummary] = useState(_saved?.exploitSummary ?? null)

  const wsRef          = useRef(null)
  const exploitWsRef   = useRef(null)
  const currentToolRef = useRef(null)
  const exploitLinesRef = useRef([])
  const exploitSummaryRef = useRef(null)

  // ── persist to localStorage (not mid-scan) ────────────────────────────────
  useEffect(() => {
    if (running) return
    saveSession({ url, selected, toolState, result, exploitLines, exploitSummary, activeTab })
  }, [url, selected, toolState, result, exploitLines, exploitSummary, activeTab, running])

  // ── derived ───────────────────────────────────────────────────────────────
  const isExploitMode  = !!selected.run_exploit
  const selectedTools  = TOOLS.filter(t => selected[t.key])
  const selectedKeys   = selectedTools.map(t => t.key)
  // when run_exploit is active, sub-tools appear as tabs too
  const routingKeys    = isExploitMode
    ? [...new Set([...selectedKeys, ...EXPLOIT_SUBTOOLS])]
    : selectedKeys
  // visible tabs = selected tools + exploit sub-tools (if run_exploit and they have state)
  const visibleTabKeys = isExploitMode
    ? [...new Set([...selectedKeys, ...EXPLOIT_SUBTOOLS])]
    : selectedKeys
  const visibleTabs    = TOOLS.filter(t => visibleTabKeys.includes(t.key) && toolState[t.key]?.status)
  const showExploitTab = exploitLines.length > 0 || exploiting

  // ── tool selection ────────────────────────────────────────────────────────
  function toggleTool(key) {
    if (running) return
    if (key === 'run_exploit') {
      setSelected({ run_exploit: !selected.run_exploit })
      return
    }
    setSelected(prev => {
      const next = { ...prev }
      if (next.run_exploit) delete next.run_exploit
      next[key] = !next[key]
      return next
    })
  }

  const setPreset = (keys) => {
    if (running) return
    const s = {}
    keys.forEach(k => { s[k] = true })
    setSelected(s)
  }

  // ── tool state helpers ────────────────────────────────────────────────────
  function initToolStates() {
    clearSession()
    const init = {}
    // for run_exploit, also pre-create states for pipeline sub-tools so tabs can appear
    routingKeys.forEach(k => { init[k] = { status: 'idle', lines: [], data: null } })
    setToolState(init)
    setResult(null)
    setExploitLines([])
    setActiveTab(null)
    setScanningTool(null)
    currentToolRef.current = null
  }

  function markToolRunning(key) {
    setToolState(prev => ({ ...prev, [key]: { ...(prev[key] || { lines: [] }), status: 'running' } }))
    setScanningTool(key)
    setActiveTab(key)
  }

  function appendToolLine(key, line) {
    if (!key) return
    setToolState(prev => ({
      ...prev,
      [key]: { ...(prev[key] || { status: 'running' }), lines: [...(prev[key]?.lines || []), line] },
    }))
  }

  function markToolDone(key) {
    if (!key) return
    setToolState(prev => ({ ...prev, [key]: { ...(prev[key] || {}), status: 'done' } }))
  }

  // ── scan WebSocket ────────────────────────────────────────────────────────
  const startScan = useCallback(() => {
    if (!url.trim()) return
    initToolStates()
    setRunning(true)

    const ws = new WebSocket(`ws://${location.host}/ws/scan`)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify({
        url,
        options: { ...Object.fromEntries(selectedKeys.map(k => [k, true])), workers: 6 },
      }))
    }

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'error') { setRunning(false); return }
      if (msg.type === 'start') return

      if (msg.type === 'done') {
        markToolDone(currentToolRef.current)
        setRunning(false)
        const r = msg.result
        setResult(r)

        if (r) {
          setToolState(prev => {
            const next = { ...prev }
            if (r.paths?.length) {
              const pathSet = [...new Set(r.paths)]
              if (next.path_recon) next.path_recon = { ...next.path_recon, status: 'done', data: pathSet }
              if (next.gobuster)   next.gobuster   = { ...next.gobuster,   status: 'done', data: pathSet }
            }
            if (r.nuclei?.length && next.nuclei)
              next.nuclei = { ...next.nuclei, status: 'done', data: r.nuclei }
            if (r.triage?.targets?.length && next.ai_triage)
              next.ai_triage = { ...next.ai_triage, status: 'done', data: r.triage.targets }
            if ((r.forms || r.params) && next.payload_recon)
              next.payload_recon = { ...next.payload_recon, status: 'done', data: { forms: r.forms, params: r.params } }
            return next
          })
        }
        return
      }

      const line = msg.text || ''
      const detected = toolFor(line)
      if (detected && routingKeys.includes(detected)) {
        if (currentToolRef.current && currentToolRef.current !== detected)
          markToolDone(currentToolRef.current)
        currentToolRef.current = detected
        markToolRunning(detected)
      }
      appendToolLine(currentToolRef.current, line)
    }

    ws.onclose = () => { setRunning(false); if (currentToolRef.current) markToolDone(currentToolRef.current) }
    ws.onerror = () => setRunning(false)
  }, [url, selectedKeys])

  const stopScan = useCallback(() => {
    wsRef.current?.close()
    setRunning(false)
  }, [])

  // ── exploit WebSocket ─────────────────────────────────────────────────────
  const runExploits = useCallback(() => {
    if (exploiting) return
    exploitLinesRef.current = []
    setExploiting(true)
    setExploitLines([])
    setExploitSummary(null)
    setActiveTab('__exploits__')

    const ws = new WebSocket(`ws://${location.host}/ws/scan`)
    exploitWsRef.current = ws

    ws.onopen = () => ws.send(JSON.stringify({ exec_mode: true, options: { workers: 6 } }))
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'done' || msg.type === 'error') {
        if (msg.type === 'done' && msg.result?.summary) {
          exploitSummaryRef.current = msg.result.summary
          setExploitSummary(msg.result.summary)
        }
        setExploiting(false)
        return
      }
      if (msg.text) {
        exploitLinesRef.current.push(msg.text)
        setExploitLines(prev => [...prev, msg.text])
      }
    }
    ws.onclose = () => {
      const lines = exploitLinesRef.current
      const summary = exploitSummaryRef.current ?? exploitSummary
      setExploitLines(lines)
      setExploiting(false)
      saveSession({ url, selected, toolState, result, exploitLines: lines, exploitSummary: summary, activeTab: '__exploits__' })
    }
    ws.onerror = () => setExploiting(false)
  }, [exploiting])

  const [loadingLastResult, setLoadingLastResult] = useState(false)
  const loadLastExploitResult = useCallback(async () => {
    setLoadingLastResult(true)
    try {
      const r = await fetch('/api/exploit-last-result?gemini=1')
      const data = await r.json()
      if (data.error) {
        alert(data.message || data.error)
        return
      }
      if (data.summary) {
        setExploitSummary(data.summary)
        setExploitLines(['[*] โหลดผลลัพธ์จากรันล่าสุด (manual).', '[*] Done.'])
        setActiveTab('__exploits__')
        exploitSummaryRef.current = data.summary
        exploitLinesRef.current = ['[*] โหลดผลลัพธ์จากรันล่าสุด (manual).', '[*] Done.']
      }
    } catch (e) {
      alert('โหลดไม่สำเร็จ: ' + (e?.message || e))
    } finally {
      setLoadingLastResult(false)
    }
  }, [])

  // ── tab content ───────────────────────────────────────────────────────────
  function renderTab(key) {
    if (key === '__exploits__') return (
      <ExploitOutput
        lines={exploitLines}
        summary={exploitSummary}
        onLoadLastResult={loadLastExploitResult}
        loadingLastResult={loadingLastResult}
      />
    )

    const ts   = toolState[key]
    const tool = TOOLS.find(t => t.key === key)
    if (!ts) return <Empty text="Not started." />

    const header = <TabHeader tool={tool} status={ts.status} />

    switch (key) {
      case 'path_recon':
      case 'gobuster':
        return <div>{header}{ts.data ? <PathList paths={ts.data} /> : <TextOutput lines={ts.lines} />}</div>

      case 'payload_recon':
        return (
          <div>
            {header}
            {ts.data
              ? <PayloadReconView forms={ts.data.forms} params={ts.data.params} />
              : <TextOutput lines={ts.lines} />}
          </div>
        )

      case 'nuclei':
        return <div>{header}{ts.data ? <NucleiTable findings={ts.data} /> : <TextOutput lines={ts.lines} />}</div>

      case 'ai_triage':
        return (
          <div>
            {header}
            {ts.data
              ? <TriageTable targets={ts.data} onRunExploit={ts.status === 'done' ? runExploits : null} exploiting={exploiting} />
              : <TextOutput lines={ts.lines} />}
          </div>
        )

      case 'subfinder':
        return (
          <div>
            {header}
            <SubfinderView lines={ts.lines} />
          </div>
        )

      case 'davtest':
        return (
          <div>
            {header}
            <DAVTestView lines={ts.lines} />
          </div>
        )

      case 'nmap':
        return <div>{header}<NmapOutput lines={ts.lines} /></div>

      case 'whatweb':
        return <div>{header}<WhatWebOutput lines={ts.lines} /></div>

      case 'run_exploit':
        return (
          <div>
            {header}
            <TextOutput lines={ts.lines} />
          </div>
        )

      default:
        return <div>{header}<TextOutput lines={ts.lines} /></div>
    }
  }

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* ── header ── */}
      <header className="bg-white border-b border-slate-200 shadow-sm px-6 py-3 flex items-center gap-4">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <span className="text-2xl">🛡️</span>
          <h1 className="font-black text-slate-900 text-lg tracking-tight">OneClickScan</h1>
          <span className="hidden sm:block text-xs text-slate-400 ml-1">Web Pentest Suite</span>
        </div>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !running && startScan()}
            placeholder="https://target.example.com"
            disabled={running}
            className="flex-1 min-w-0 px-4 py-2 border border-slate-200 rounded-xl text-sm font-mono
              focus:outline-none focus:ring-2 focus:ring-blue-500 bg-slate-50"
          />
          {running
            ? <button onClick={stopScan}
                className="px-5 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-semibold rounded-xl shadow transition-all shrink-0">
                Stop
              </button>
            : <button onClick={startScan} disabled={!url.trim()}
                className="px-5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-sm font-semibold rounded-xl shadow transition-all shrink-0">
                Scan
              </button>}
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* ── sidebar ── */}
        <aside className="w-60 shrink-0 bg-white border-r border-slate-200 flex flex-col p-4 gap-3 overflow-y-auto">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-1">Tools</div>
          {TOOLS.map(t => (
            <ToolCheckbox
              key={t.key} tool={t}
              checked={!!selected[t.key]}
              onChange={toggleTool}
              disabled={running}
            />
          ))}

          <div className="pt-2 border-t border-slate-100">
            <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Presets</div>
            <div className="flex flex-col gap-1.5">
              {[
                { label: 'Quick Recon',  keys: ['path_recon', 'payload_recon'] },
                { label: 'Full Passive', keys: ['path_recon', 'payload_recon', 'gobuster', 'whatweb', 'subfinder'] },
                { label: 'CVE Scan',     keys: ['path_recon', 'nuclei'] },
                { label: 'AI Pentest',   keys: ['path_recon', 'payload_recon', 'gobuster', 'nuclei', 'ai_triage'] },
              ].map(p => (
                <button key={p.label} onClick={() => setPreset(p.keys)} disabled={running}
                  className="text-xs px-3 py-1.5 bg-slate-100 hover:bg-blue-50 hover:text-blue-700
                    text-slate-600 rounded-lg text-left transition-all disabled:opacity-40">
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* ── main panel ── */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {/* tab bar */}
          <div className="flex items-end gap-1 px-4 pt-3 bg-white border-b border-slate-200 overflow-x-auto shrink-0">
            {visibleTabs.map(t => {
              const ts = toolState[t.key]
              return (
                <button
                  key={t.key}
                  onClick={() => setActiveTab(t.key)}
                  className={`flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-t-lg border-t border-x
                    whitespace-nowrap transition-all
                    ${activeTab === t.key
                      ? 'bg-slate-50 border-slate-200 text-blue-700'
                      : 'bg-white border-transparent text-slate-500 hover:text-slate-800'}`}
                >
                  <StatusDot status={ts?.status} />
                  <span>{t.icon}</span>
                  <span>{t.label}</span>
                  {ts?.status === 'done' && ts.data && (
                    <span className="ml-1 text-xs bg-slate-200 text-slate-600 rounded-full px-1.5">
                      {Array.isArray(ts.data) ? ts.data.length : '✓'}
                    </span>
                  )}
                </button>
              )
            })}

            {showExploitTab && (
              <button
                onClick={() => setActiveTab('__exploits__')}
                className={`flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-t-lg border-t border-x
                  whitespace-nowrap transition-all
                  ${activeTab === '__exploits__'
                    ? 'bg-slate-50 border-slate-200 text-red-700'
                    : 'bg-white border-transparent text-slate-500 hover:text-slate-800'}`}
              >
                {exploiting && <span className="inline-block w-2 h-2 rounded-full bg-red-500 animate-pulse mr-1" />}
                🔥 Exploits
              </button>
            )}

            {visibleTabs.length === 0 && !showExploitTab && (
              <div className="text-sm text-slate-400 pb-2 px-2">
                {running ? 'Waiting for first tool to start…' : 'Select tools and click Scan'}
              </div>
            )}
          </div>

          {/* tab content */}
          <div className="flex-1 overflow-y-auto p-5">
            {activeTab && (activeTab === '__exploits__' || toolState[activeTab])
              ? renderTab(activeTab)
              : running
                ? <ScanningOverlay currentTool={scanningTool} />
                : (
                  <div className="flex flex-col items-center justify-center h-full text-slate-300 select-none">
                    <div className="text-6xl mb-4">🛡️</div>
                    <div className="text-lg font-semibold">OneClickScan</div>
                    <div className="text-sm mt-1">Enter a target URL and click Scan to begin</div>
                    <div className="flex flex-wrap gap-2 mt-6 justify-center max-w-sm">
                      {selectedTools.map(t => (
                        <span key={t.key} className="text-xs bg-slate-100 text-slate-500 px-2 py-1 rounded-full">
                          {t.icon} {t.label}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
          </div>
        </main>
      </div>
    </div>
  )
}
