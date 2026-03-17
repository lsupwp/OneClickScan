"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type PayloadEntry = {
  found_in: string[];
  form_id?: string | null;
  form_name?: string | null;
  action: string;
  method: string;
  query_string: Record<string, string>;
  payload: Record<string, string>;
};

type PayloadReconOutputProps = {
  payloadEntries: PayloadEntry[] | null;
  payloadReconId?: number | null;
  backend?: string;
};

type AnalyzeRec = {
  action: string;
  method: string;
  tool: "sqlmap" | "xsstrike" | "curl";
  risk: "Info" | "Low" | "Medium" | "High" | "Critical";
  cmd: string;
  what: string;
  why: string;
  notes?: string;
};

type PayloadRunRow = {
  id: number;
  payload_recon_id: number;
  tool: string;
  cmd: string;
  output_file: string;
  status: "running" | "done" | "error";
  exit_code: number | null;
  started_at: string;
  finished_at: string | null;
};

const RISK_ORDER: Record<AnalyzeRec["risk"], number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

function riskClass(risk: AnalyzeRec["risk"]) {
  switch (risk) {
    case "Critical":
      return "bg-red-100 text-red-800 border-red-200";
    case "High":
      return "bg-orange-100 text-orange-800 border-orange-200";
    case "Medium":
      return "bg-amber-100 text-amber-800 border-amber-200";
    case "Low":
      return "bg-emerald-100 text-emerald-800 border-emerald-200";
    default:
      return "bg-zinc-100 text-zinc-700 border-zinc-200";
  }
}

export default function PayloadReconOutput({ payloadEntries, payloadReconId = null, backend }: PayloadReconOutputProps) {
  const resolvedBackend = useMemo(
    () => backend || process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080",
    [backend]
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState<string | null>(null);
  const [recs, setRecs] = useState<AnalyzeRec[] | null>(null);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const autoRequestedRef = useRef(false);
  const lastReconIdRef = useRef<number | null>(null);
  const [runs, setRuns] = useState<PayloadRunRow[] | null>(null);
  const [runningIdx, setRunningIdx] = useState<number | null>(null);
  const [runLogsByIdx, setRunLogsByIdx] = useState<Record<number, string[]>>({});
  const [runOutFileByIdx, setRunOutFileByIdx] = useState<Record<number, string>>({});
  const [runTextByIdx, setRunTextByIdx] = useState<Record<number, string>>({});
  const wsRef = useRef<WebSocket | null>(null);

  const wsUrl = useMemo(() => {
    const fallback = "ws://127.0.0.1:8080";
    const b = String(resolvedBackend || "").trim();
    if (!b) return fallback;
    try {
      const u = new URL(b);
      u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
      return u.toString();
    } catch {
      if (b.startsWith("wss://") || b.startsWith("ws://")) return b;
      if (b.startsWith("https://")) return b.replace("https://", "wss://");
      if (b.startsWith("http://")) return b.replace("http://", "ws://");
      return fallback;
    }
  }, [resolvedBackend]);

  const sortedRecs = useMemo(() => {
    if (!recs) return null;
    return [...recs].sort((a, b) => (RISK_ORDER[b.risk] ?? 0) - (RISK_ORDER[a.risk] ?? 0));
  }, [recs]);

  useEffect(() => {
    if (!payloadReconId) return;
    if (lastReconIdRef.current !== payloadReconId) {
      lastReconIdRef.current = payloadReconId;
      autoRequestedRef.current = false;
      setAnalyzeError(null);
      setRecs(null);
      setRuns(null);
      setRunningIdx(null);
      setRunLogsByIdx({});
      setRunOutFileByIdx({});
      setRunTextByIdx({});
    }
  }, [payloadReconId]);

  useEffect(() => {
    if (!payloadReconId) return;
    fetch(`${resolvedBackend}/api/payload/runs?payload_recon_id=${encodeURIComponent(String(payloadReconId))}`, { cache: "no-store" })
      .then((r) => r.json())
      .then((data) => setRuns(Array.isArray(data) ? (data as PayloadRunRow[]) : []))
      .catch(() => setRuns([]));
  }, [payloadReconId, resolvedBackend]);

  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    if (!payloadReconId) return;
    if (recs) return;
    if (analyzing) return;
    if (autoRequestedRef.current) return;
    autoRequestedRef.current = true;

    (async () => {
      setAnalyzing(true);
      setAnalyzeError(null);
      try {
        // 1) Try fetch existing analysis by id (no entries needed)
        const res1 = await fetch(`${resolvedBackend}/api/payload/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload_recon_id: payloadReconId }),
        });
        const data1 = await res1.json();
        if (res1.ok) {
          setRecs(Array.isArray(data1) ? (data1 as AnalyzeRec[]) : []);
          return;
        }

        // 2) If no cached analysis, and we have entries, run analysis now
        if (!payloadEntries || payloadEntries.length === 0) {
          throw new Error(data1?.error || "analyze failed");
        }
        const res2 = await fetch(`${resolvedBackend}/api/payload/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload_recon_id: payloadReconId, entries: payloadEntries }),
        });
        const data2 = await res2.json();
        if (!res2.ok) throw new Error(data2?.error || "analyze failed");
        setRecs(Array.isArray(data2) ? (data2 as AnalyzeRec[]) : []);
      } catch (e) {
        setAnalyzeError((e as Error).message);
      } finally {
        setAnalyzing(false);
      }
    })();
  }, [payloadEntries, payloadReconId, recs, analyzing, resolvedBackend]);

  if (payloadEntries === null) {
    return <p className="text-sm text-zinc-500">กำลังโหลด…</p>;
  }
  if (payloadEntries.length === 0) {
    return <p className="text-sm text-zinc-500">ไม่พบ forms / params</p>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">AI วิเคราะห์</p>
          <p className="text-sm text-zinc-600">ให้ Gemini แนะนำเครื่องมือ + คำสั่งทดสอบ</p>
        </div>
        <button
          type="button"
          disabled={analyzing || !payloadEntries?.length}
          onClick={async () => {
            setAnalyzing(true);
            setAnalyzeError(null);
            setRecs(null);
            try {
              const res = await fetch(`${resolvedBackend}/api/payload/analyze`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ payload_recon_id: payloadReconId, entries: payloadEntries }),
              });
              const data = await res.json();
              if (!res.ok) throw new Error(data?.error || "analyze failed");
              setRecs(Array.isArray(data) ? (data as AnalyzeRec[]) : []);
            } catch (e) {
              setAnalyzeError((e as Error).message);
            } finally {
              setAnalyzing(false);
            }
          }}
          className={`rounded-xl px-4 py-2 text-sm font-semibold shadow-sm transition ${
            analyzing
              ? "cursor-not-allowed bg-zinc-200 text-zinc-500"
              : "bg-gradient-to-r from-violet-600 to-violet-700 text-white hover:from-violet-700 hover:to-violet-800"
          }`}
        >
          {analyzing ? "กำลังวิเคราะห์..." : recs ? "วิเคราะห์แล้ว" : "AI วิเคราะห์"}
        </button>
      </div>

      {analyzeError && (
        <p className="text-sm text-red-600">{analyzeError}</p>
      )}

      {sortedRecs && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
            คำแนะนำจาก AI — {sortedRecs.length} รายการ
          </p>
          <div className="grid gap-3">
            {sortedRecs.map((r, idx) => (
              <div key={idx} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-lg border px-2.5 py-0.5 text-xs font-bold ${riskClass(r.risk)}`}>
                    {r.risk}
                  </span>
                  <span className="rounded-lg bg-zinc-100 px-2.5 py-0.5 text-xs font-semibold text-zinc-700">
                    {r.tool}
                  </span>
                  <span className="rounded-md bg-violet-100 px-2 py-0.5 text-xs font-semibold text-violet-800">
                    {r.method}
                  </span>
                  <span className="font-mono text-xs text-zinc-600 break-all">{r.action}</span>
                </div>
                <p className="mt-2 text-sm text-zinc-700">
                  <span className="font-semibold">ทดสอบอะไร:</span> {r.what}
                </p>
                <p className="mt-1 text-sm text-zinc-600">
                  <span className="font-semibold">ทำไมเลือกเครื่องมือนี้:</span> {r.why}
                </p>
                {r.notes && (
                  <p className="mt-1 text-xs text-zinc-500">{r.notes}</p>
                )}
                <div className="mt-3 rounded-xl bg-zinc-900 p-3 text-xs font-mono text-zinc-100 overflow-x-auto">
                  {r.cmd || "—"}
                </div>
                {runLogsByIdx[idx]?.length ? (
                  <details className="mt-3 rounded-xl border border-zinc-200 bg-white/60">
                    <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-100/60">
                      Log ระหว่างรัน ({runLogsByIdx[idx].length})
                    </summary>
                    <pre className="border-t border-zinc-200 p-3 text-xs font-mono text-zinc-900 max-h-64 overflow-auto whitespace-pre-wrap break-all">
                      {runLogsByIdx[idx].join("")}
                    </pre>
                  </details>
                ) : null}
                {runOutFileByIdx[idx] && runTextByIdx[idx] ? (
                  <details className="mt-3 rounded-xl border border-zinc-200 bg-white/60">
                    <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-zinc-700 hover:bg-zinc-100/60">
                      Output (.txt)
                    </summary>
                    <pre className="border-t border-zinc-200 p-3 text-xs font-mono text-zinc-900 max-h-80 overflow-auto whitespace-pre-wrap break-all">
                      {runTextByIdx[idx]}
                    </pre>
                  </details>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={!r.cmd}
                    onClick={async () => {
                      if (!r.cmd) return;
                      try {
                        await navigator.clipboard.writeText(r.cmd);
                        setCopiedIdx(idx);
                        window.setTimeout(() => setCopiedIdx((cur) => (cur === idx ? null : cur)), 1200);
                      } catch {}
                    }}
                    className={`rounded-lg px-3 py-2 text-xs font-semibold transition ${
                      r.cmd
                        ? "cursor-pointer bg-zinc-900 text-white hover:bg-zinc-800 active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-violet-400/40"
                        : "bg-zinc-200 text-zinc-500 cursor-not-allowed"
                    }`}
                  >
                    {copiedIdx === idx ? "Copied!" : "Copy Command"}
                  </button>
                  <button
                    type="button"
                    disabled={!payloadReconId || !r.cmd || analyzing || runningIdx === idx}
                    onClick={async () => {
                      if (!payloadReconId || !r.cmd) return;
                      setRunningIdx(idx);
                      setRunLogsByIdx((p) => ({ ...p, [idx]: [] }));
                      try {
                        wsRef.current?.close();
                        const ws = new WebSocket(wsUrl);
                        wsRef.current = ws;

                        const start = async () => {
                          const res = await fetch(`${resolvedBackend}/api/payload/run`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ payload_recon_id: payloadReconId, cmd: r.cmd }),
                          });
                          const data = (await res.json()) as { jobId?: string; runId?: number; outputFile?: string; error?: string };
                          if (!data.jobId) throw new Error(data.error || "start run failed");
                          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
                          if (data.outputFile) setRunOutFileByIdx((p) => ({ ...p, [idx]: data.outputFile! }));
                        };

                        ws.onmessage = (ev) => {
                          try {
                            const msg = JSON.parse(ev.data as string);
                            if (msg.type === "progress" && typeof msg.message === "string") {
                              setRunLogsByIdx((p) => ({ ...p, [idx]: [...(p[idx] || []), msg.message] }));
                            }
                            if (msg.type === "done" && msg.outputFile) {
                              const pth = String(msg.outputFile);
                              setRunOutFileByIdx((p) => ({ ...p, [idx]: pth }));
                              fetch(`${resolvedBackend}/api/result?path=${encodeURIComponent(pth)}`, { cache: "no-store" })
                                .then((rr) => rr.text())
                                .then((txt) => setRunTextByIdx((p) => ({ ...p, [idx]: txt })))
                                .catch(() => {});
                              fetch(`${resolvedBackend}/api/payload/runs?payload_recon_id=${encodeURIComponent(String(payloadReconId))}`, { cache: "no-store" })
                                .then((rr) => rr.json())
                                .then((d) => setRuns(Array.isArray(d) ? (d as PayloadRunRow[]) : []))
                                .catch(() => {});
                              setRunningIdx((cur) => (cur === idx ? null : cur));
                            }
                            if (msg.type === "error") {
                              if (msg.outputFile) {
                                const pth = String(msg.outputFile);
                                setRunOutFileByIdx((p) => ({ ...p, [idx]: pth }));
                                fetch(`${resolvedBackend}/api/result?path=${encodeURIComponent(pth)}`, { cache: "no-store" })
                                  .then((rr) => rr.text())
                                  .then((txt) => setRunTextByIdx((p) => ({ ...p, [idx]: txt })))
                                  .catch(() => {});
                              }
                              setRunningIdx((cur) => (cur === idx ? null : cur));
                            }
                          } catch {}
                        };
                        ws.onopen = () => void start();
                        ws.onerror = () => setRunningIdx((cur) => (cur === idx ? null : cur));
                      } catch (e) {
                        setAnalyzeError((e as Error).message);
                        setRunningIdx(null);
                      }
                    }}
                    className={`rounded-lg px-3 py-2 text-xs font-semibold transition ${
                      !payloadReconId || !r.cmd || analyzing || runningIdx === idx
                        ? "bg-zinc-200 text-zinc-500 cursor-not-allowed"
                        : "bg-white border border-zinc-200 text-zinc-800 hover:bg-zinc-50 active:scale-[0.98]"
                    }`}
                  >
                    {runningIdx === idx ? "Running..." : "Run Test"}
                  </button>
                </div>
                {runs && runs.some((x) => x.cmd === r.cmd && x.status === "done") && (
                  <p className="mt-2 text-[11px] text-emerald-700 font-semibold">สถานะ: เคยรันแล้ว</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {payloadEntries.map((entry, idx) => (
        <div key={idx} className="rounded-2xl border border-violet-100 bg-violet-50/30 p-4">
          <div className="flex items-center gap-2">
            <span className="rounded-md bg-violet-200 px-2 py-0.5 text-xs font-semibold text-violet-800">
              {entry.method}
            </span>
            <span className="font-mono text-sm text-zinc-800 break-all">{entry.action}</span>
          </div>
          {(entry.form_id || entry.form_name) && (
            <p className="mt-1 text-[11px] text-zinc-500">
              Form:{" "}
              <span className="font-mono">
                {entry.form_id ? `#${entry.form_id}` : ""}
                {entry.form_id && entry.form_name ? " " : ""}
                {entry.form_name ? `name=\"${entry.form_name}\"` : ""}
              </span>
            </p>
          )}
          {(Object.keys(entry.query_string || {}).length > 0 || Object.keys(entry.payload || {}).length > 0) && (
            <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
              {Object.keys(entry.query_string || {}).length > 0 && (
                <div>
                  <span className="font-medium text-zinc-600">Query:</span>
                  <pre className="mt-0.5 rounded-lg bg-white p-2 font-mono text-zinc-800 overflow-x-auto">
                    {JSON.stringify(entry.query_string, null, 2)}
                  </pre>
                </div>
              )}
              {Object.keys(entry.payload || {}).length > 0 && (
                <div>
                  <span className="font-medium text-zinc-600">Payload:</span>
                  <pre className="mt-0.5 rounded-lg bg-white p-2 font-mono text-zinc-800 overflow-x-auto">
                    {JSON.stringify(entry.payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
          {entry.found_in && entry.found_in.length > 0 && (
            <p className="mt-2 text-[11px] text-zinc-500">
              Found in: {entry.found_in.slice(0, 3).join(", ")}
              {entry.found_in.length > 3 && ` +${entry.found_in.length - 3} more`}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
