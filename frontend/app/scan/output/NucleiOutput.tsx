"use client";

import { useEffect, useMemo, useState } from "react";

type Finding = {
  name: string | null;
  severity: string | null;
  matchedAt: string | null;
  templateId: string | null;
  description: string | null;
  cve: string | null;
};

const SEV_ORDER: Record<string, number> = {
  critical: 6,
  high: 5,
  medium: 4,
  low: 3,
  info: 2,
  unknown: 1,
};

function sevClass(sev: string) {
  switch (sev) {
    case "critical":
      return "bg-red-100 text-red-800 border-red-200";
    case "high":
      return "bg-orange-100 text-orange-800 border-orange-200";
    case "medium":
      return "bg-amber-100 text-amber-800 border-amber-200";
    case "low":
      return "bg-emerald-100 text-emerald-800 border-emerald-200";
    case "info":
      return "bg-sky-100 text-sky-800 border-sky-200";
    default:
      return "bg-zinc-100 text-zinc-700 border-zinc-200";
  }
}

export default function NucleiOutput({
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
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (phase !== "done" || !resultFile || !resolvedBackend) {
      setFindings(null);
      setLoadError(null);
      return;
    }
    let cancelled = false;
    setLoadError(null);
    fetch(`${resolvedBackend}/api/result?path=${encodeURIComponent(resultFile)}`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("โหลดผล nuclei ไม่สำเร็จ");
        return r.json();
      })
      .then((data: unknown) => {
        if (cancelled) return;
        const arr = Array.isArray(data) ? (data as Finding[]) : [];
        const normalized = arr.map((x) => ({
          name: x?.name ?? null,
          severity: (x?.severity ?? "unknown") as string,
          matchedAt: x?.matchedAt ?? null,
          templateId: x?.templateId ?? null,
          description: x?.description ?? null,
          cve: x?.cve ?? null,
        }));
        normalized.sort((a, b) => (SEV_ORDER[String(b.severity || "unknown").toLowerCase()] ?? 0) - (SEV_ORDER[String(a.severity || "unknown").toLowerCase()] ?? 0));
        setFindings(normalized);
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
        <p className="text-sm text-zinc-600">กำลังรัน nuclei…</p>
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

  return (
    <div className="space-y-4">
      {loadError && <p className="text-sm text-red-600">{loadError}</p>}
      {findings && (
        <>
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
            Findings — {findings.length}
          </p>
          <div className="grid gap-3">
            {findings.map((f, idx) => {
              const sev = String(f.severity || "unknown").toLowerCase();
              return (
                <div key={idx} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-lg border px-2.5 py-0.5 text-xs font-bold ${sevClass(sev)}`}>
                      {sev}
                    </span>
                    {f.cve && (
                      <span className="rounded-lg bg-zinc-100 px-2.5 py-0.5 text-xs font-semibold text-zinc-700">
                        {f.cve}
                      </span>
                    )}
                    {f.templateId && (
                      <span className="rounded-lg bg-zinc-100 px-2.5 py-0.5 text-xs font-semibold text-zinc-700">
                        {f.templateId}
                      </span>
                    )}
                  </div>
                  <p className="mt-2 text-sm font-semibold text-zinc-900">
                    {f.name || "—"}
                  </p>
                  {f.matchedAt && (
                    <p className="mt-1 text-xs text-zinc-500 font-mono break-all">
                      matchedAt: {f.matchedAt}
                    </p>
                  )}
                  {f.description && (
                    <p className="mt-2 text-sm text-zinc-600 whitespace-pre-wrap">
                      {f.description}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

