"use client";

import { useEffect, useState } from "react";
import { LogView } from "./logView";

type ScoredEntry = {
  url: string;
  status?: number | null;
  score?: number | null;
  level?: string | null;
  reason?: string | null;
};

type FfufOutputProps = {
  phase: "running" | "done" | "error";
  logs: string[];
  resultFile?: string | null;
  backend?: string;
};

const ACCENT = "bg-sky-100 text-sky-800";

const SCORE_COLOR: Record<number, string> = {
  5: "bg-red-100 text-red-800 border-red-200",
  4: "bg-orange-100 text-orange-800 border-orange-200",
  3: "bg-amber-100 text-amber-800 border-amber-200",
  2: "bg-yellow-100 text-yellow-800 border-yellow-200",
  1: "bg-emerald-100 text-emerald-800 border-emerald-200",
};

export default function FfufOutput({ phase, logs, resultFile, backend }: FfufOutputProps) {
  const [scored, setScored] = useState<ScoredEntry[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (phase !== "done" || !resultFile || !backend) {
      setScored(null);
      setLoadError(null);
      return;
    }
    let cancelled = false;
    setLoadError(null);
    fetch(`${backend}/api/result?path=${encodeURIComponent(resultFile)}`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error(r.status === 404 ? "ไม่พบไฟล์ผล" : "โหลดผลไม่สำเร็จ");
        return r.json();
      })
      .then((data: unknown) => {
        if (cancelled) return;
        const arr = Array.isArray(data) ? data : [];
        const withScore = arr.filter((x: ScoredEntry) => x != null && typeof x.url === "string");
        const sorted = [...withScore].sort((a, b) => {
          const sa = a.score != null ? a.score : -1;
          const sb = b.score != null ? b.score : -1;
          return sb - sa;
        });
        setScored(sorted);
      })
      .catch((e) => {
        if (!cancelled) setLoadError(e?.message || "โหลดผลไม่สำเร็จ");
      });
    return () => {
      cancelled = true;
    };
  }, [phase, resultFile, backend]);

  if (phase === "running") {
    return (
      <div className="space-y-4">
        {logs.length === 0 && (
          <p className="text-sm text-sky-700/80">กำลังสแกน hidden path… log จะแสดงเมื่อมีข้อมูล</p>
        )}
        <LogView logs={logs} accentClass={ACCENT} emptyMessage="ยังไม่มี log" />
      </div>
    );
  }

  if (phase === "done" && (scored != null || loadError)) {
    return (
      <div className="space-y-6">
        {loadError && (
          <p className="text-sm text-red-600">{loadError}</p>
        )}
        {scored != null && scored.length > 0 && (
          <div className="space-y-3">
            <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
              คะแนนจาก Gemini (เรียงจากมากไปน้อย) — {scored.length} รายการ
            </p>
            <div className="space-y-2 max-h-[50vh] overflow-y-auto pr-1">
              {scored.map((entry, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-zinc-200 bg-white p-3 shadow-sm hover:border-sky-200 transition"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    {entry.score != null && (
                      <span
                        className={`rounded-lg border px-2.5 py-0.5 text-sm font-bold ${
                          SCORE_COLOR[entry.score] ?? "bg-zinc-100 text-zinc-800 border-zinc-200"
                        }`}
                      >
                        {entry.score}
                      </span>
                    )}
                    {entry.level && (
                      <span className="rounded-md bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-700">
                        {entry.level}
                      </span>
                    )}
                    {entry.status != null && (
                      <span className="text-xs text-zinc-400">{entry.status}</span>
                    )}
                  </div>
                  <a
                    href={entry.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-1.5 block font-mono text-sm text-sky-700 hover:text-sky-800 break-all underline underline-offset-2"
                  >
                    {entry.url}
                  </a>
                  {entry.reason && (
                    <p className="mt-2 text-sm text-zinc-600 leading-snug">
                      {entry.reason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        {scored != null && scored.length === 0 && !loadError && (
          <p className="text-sm text-zinc-500">ไม่มีผลคะแนน</p>
        )}
        {scored != null && logs.length > 0 && (
          <details className="rounded-xl border border-zinc-200 bg-zinc-50/50 overflow-hidden">
            <summary className="px-3 py-2 text-xs font-medium text-zinc-600 cursor-pointer hover:bg-zinc-100/80">
              Crawl log ({logs.length} บรรทัด)
            </summary>
            <div className="p-3 border-t border-zinc-200 max-h-64 overflow-auto">
              <LogView logs={logs} accentClass={ACCENT} emptyMessage="ไม่มี log" />
            </div>
          </details>
        )}
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="space-y-3">
        {logs.length > 0 && <LogView logs={logs} accentClass={ACCENT} emptyMessage="ไม่มี log" />}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-zinc-500">กำลังโหลดผล…</p>
      {logs.length > 0 && <LogView logs={logs} accentClass={ACCENT} emptyMessage="ไม่มี log" />}
    </div>
  );
}
