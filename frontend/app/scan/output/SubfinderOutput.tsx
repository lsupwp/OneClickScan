"use client";

import { useEffect, useMemo, useState } from "react";

type SubfinderResultRow = {
  host: string;
  input: string;
  source: string | null;
  url: string;
  status_code: number;
};

type SubfinderFileShape = {
  domain: string;
  scheme: "http" | "https";
  httpxTimeout: number;
  results: SubfinderResultRow[];
};

function severityColor(status: number) {
  if (status === 200) return "bg-emerald-100 text-emerald-800 border-emerald-200";
  return "bg-zinc-100 text-zinc-800 border-zinc-200";
}

export default function SubfinderOutput({
  phase,
  logs,
  resultFile,
  backend,
}: {
  phase: "running" | "done" | "error";
  logs: string[];
  resultFile?: string | null;
  backend?: string;
}) {
  const resolvedBackend = useMemo(() => backend || "", [backend]);
  const [data, setData] = useState<SubfinderFileShape | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (phase !== "done" || !resultFile || !resolvedBackend) {
      setData(null);
      setLoadError(null);
      return;
    }
    let cancelled = false;
    setLoadError(null);
    fetch(`${resolvedBackend}/api/result?path=${encodeURIComponent(resultFile)}`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("โหลดผล subfinder ไม่สำเร็จ");
        return r.json();
      })
      .then((json: unknown) => {
        if (cancelled) return;
        setData((json as SubfinderFileShape) || null);
      })
      .catch((e) => {
        if (!cancelled) setLoadError(e?.message || "โหลดผลไม่สำเร็จ");
      });
    return () => {
      cancelled = true;
    };
  }, [phase, resultFile, resolvedBackend]);

  if (phase === "running") {
    return (
      <div className="space-y-4">
        <p className="text-sm text-zinc-600">กำลังรัน subfinder + httpx…</p>
        <pre className="rounded-xl bg-zinc-900 p-3 text-xs font-mono text-zinc-100 max-h-80 overflow-auto whitespace-pre-wrap break-all">
          {logs.length ? logs.join("\n") : "ยังไม่มี log"}
        </pre>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="space-y-4">
        {logs.length > 0 && (
          <pre className="rounded-xl bg-zinc-900 p-3 text-xs font-mono text-zinc-100 max-h-80 overflow-auto whitespace-pre-wrap break-all">
            {logs.join("\n")}
          </pre>
        )}
      </div>
    );
  }

  const results = data?.results || [];
  const sorted = [...results].sort((a, b) => a.host.localeCompare(b.host));

  return (
    <div className="space-y-4">
      {loadError && <p className="text-sm text-red-600">{loadError}</p>}
      {data && (
        <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Summary</p>
          <p className="mt-2 text-sm text-zinc-800">
            <span className="font-semibold">Domain:</span> <span className="font-mono">{data.domain}</span>
          </p>
          <p className="mt-1 text-sm text-zinc-800">
            <span className="font-semibold">Scheme:</span> {data.scheme} • <span className="font-semibold">httpx timeout:</span>{" "}
            {data.httpxTimeout}s
          </p>
        </div>
      )}

      <div className="space-y-3">
        <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Alive (200) — {sorted.length}</p>
        {sorted.length === 0 ? (
          <p className="text-sm text-zinc-500">ไม่พบ subdomain ที่ตอบ 200</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {sorted.map((r) => (
              <div key={r.host} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
                <div className="flex items-center justify-between gap-3">
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sm font-semibold text-zinc-900 break-all hover:underline underline-offset-4"
                  >
                    {r.host}
                  </a>
                  <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severityColor(r.status_code)}`}>
                    {r.status_code}
                  </span>
                </div>
                <a
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 block text-xs font-mono text-sky-700 break-all hover:underline underline-offset-4"
                >
                  {r.url}
                </a>
                {r.source && <p className="mt-2 text-xs text-zinc-500">source: {r.source}</p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

