"use client";

import { useEffect, useMemo, useState } from "react";

type WhatWebResult = {
  target?: string;
  http_status?: number;
  request_config?: unknown;
  plugins?: Record<string, unknown>;
};

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return !!x && typeof x === "object" && !Array.isArray(x);
}

function formatValue(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.map(formatValue).filter(Boolean).join(", ");
  if (isPlainObject(v)) {
    // whatweb plugins often look like: { string: ["..."], module: ["..."] }
    const parts: string[] = [];
    for (const [k, val] of Object.entries(v)) {
      const s = formatValue(val);
      if (s) parts.push(`${k}: ${s}`);
    }
    return parts.join(" • ");
  }
  return String(v);
}

export default function WhatWebOutput({
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
  const [data, setData] = useState<WhatWebResult[] | null>(null);
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
        if (!r.ok) throw new Error("โหลดผล whatweb ไม่สำเร็จ");
        return r.json();
      })
      .then((json: unknown) => {
        if (cancelled) return;
        setData(Array.isArray(json) ? (json as WhatWebResult[]) : []);
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
        <p className="text-sm text-zinc-600">กำลังรัน whatweb…</p>
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

  const first = data?.[0];
  const plugins = isPlainObject(first?.plugins) ? (first?.plugins as Record<string, unknown>) : {};
  const pluginEntries = useMemo(() => {
    return Object.entries(plugins)
      .map(([name, val]) => {
        const rendered = formatValue(val).trim();
        return { name, rendered };
      })
      .filter((x) => x.rendered.length > 0)
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [plugins]);

  return (
    <div className="space-y-4">
      {loadError && <p className="text-sm text-red-600">{loadError}</p>}
      {first && (
        <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Summary</p>
          <p className="mt-2 text-sm text-zinc-800">
            <span className="font-semibold">Target:</span>{" "}
            <span className="font-mono break-all">{first.target || "—"}</span>
          </p>
          <p className="mt-1 text-sm text-zinc-800">
            <span className="font-semibold">HTTP:</span> {first.http_status ?? "—"}
          </p>
        </div>
      )}

      <div className="space-y-3">
        <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
          Plugins — {pluginEntries.length}
        </p>
        {pluginEntries.length === 0 ? (
          <p className="text-sm text-zinc-500">ไม่มีข้อมูล plugins</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {pluginEntries.map((p) => (
              <div key={p.name} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
                <p className="text-sm font-semibold text-zinc-900">{p.name}</p>
                <p className="mt-2 text-xs font-mono text-zinc-700 whitespace-pre-wrap break-words">
                  {p.rendered}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

