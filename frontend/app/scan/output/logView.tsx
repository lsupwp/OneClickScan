"use client";

import { useState } from "react";

export type LogEntry = {
  timestamp?: string;
  request?: { method?: string; endpoint?: string; raw?: string };
  response?: { status_code?: number; headers?: Record<string, string>; body?: string };
};

export function parseLogLines(logs: string[]): { entries: LogEntry[]; rawLines: string[] } {
  const entries: LogEntry[] = [];
  const rawLines: string[] = [];
  const allText = logs.join("\n");
  const lines = allText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as unknown;
      if (obj && typeof obj === "object" && "request" in obj && "response" in obj) {
        entries.push(obj as LogEntry);
      } else {
        rawLines.push(line);
      }
    } catch {
      rawLines.push(line);
    }
  }
  return { entries, rawLines };
}

function LogEntryCard({ entry, accentClass }: { entry: LogEntry; accentClass: string }) {
  const [expanded, setExpanded] = useState(false);
  const method = entry.request?.method ?? "—";
  const endpoint = entry.request?.endpoint ?? "—";
  const status = entry.response?.status_code;
  const body = entry.response?.body?.trim() ?? "";
  const hasBody = body.length > 0;

  return (
    <div className="rounded-xl border border-zinc-200 bg-white shadow-sm overflow-hidden">
      <div
        className="flex flex-wrap items-center gap-2 p-3 cursor-pointer hover:bg-zinc-50/80 transition"
        onClick={() => setExpanded(!expanded)}
      >
        <span className={`rounded-md px-2 py-0.5 text-xs font-semibold ${accentClass}`}>
          {method}
        </span>
        {typeof status === "number" && (
          <span
            className={`rounded-md px-2 py-0.5 text-xs font-semibold ${
              status >= 200 && status < 300
                ? "bg-emerald-100 text-emerald-800"
                : status >= 400
                  ? "bg-amber-100 text-amber-800"
                  : "bg-zinc-100 text-zinc-700"
            }`}
          >
            {status}
          </span>
        )}
        <span className="font-mono text-sm text-zinc-800 break-all flex-1 min-w-0">
          {endpoint}
        </span>
        {entry.timestamp && (
          <span className="text-[11px] text-zinc-400 shrink-0">
            {new Date(entry.timestamp).toLocaleTimeString()}
          </span>
        )}
        {hasBody && (
          <span className="text-zinc-400 shrink-0">
            {expanded ? "▼" : "▶"}
          </span>
        )}
      </div>
      {(expanded || !hasBody) && hasBody && (
        <div className="border-t border-zinc-100 bg-zinc-50/50 px-3 py-2">
          <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">Response body</p>
          <pre className="text-xs font-mono text-zinc-700 whitespace-pre-wrap break-words max-h-48 overflow-auto rounded-lg bg-white p-2 border border-zinc-100">
            {body}
          </pre>
        </div>
      )}
      {expanded && entry.response?.headers && Object.keys(entry.response.headers).length > 0 && (
        <div className="border-t border-zinc-100 bg-zinc-50/30 px-3 py-2">
          <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1">Headers</p>
          <pre className="text-[11px] font-mono text-zinc-600 whitespace-pre-wrap break-all overflow-x-auto">
            {JSON.stringify(entry.response.headers, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export function LogView({
  logs,
  accentClass,
  emptyMessage = "ไม่มี log",
}: {
  logs: string[];
  accentClass: string;
  emptyMessage?: string;
}) {
  const { entries, rawLines } = parseLogLines(logs);

  if (entries.length === 0 && rawLines.length === 0) {
    return <p className="text-sm text-zinc-500">{emptyMessage}</p>;
  }

  return (
    <div className="space-y-3">
      {entries.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
            {entries.length} รายการ
          </p>
          <div className="space-y-2 max-h-[60vh] overflow-y-auto pr-1">
            {entries.map((entry, i) => (
              <LogEntryCard key={i} entry={entry} accentClass={accentClass} />
            ))}
          </div>
        </div>
      )}
      {rawLines.length > 0 && (
        <details className="rounded-xl border border-zinc-200 bg-zinc-50/50 overflow-hidden">
          <summary className="px-3 py-2 text-xs font-medium text-zinc-600 cursor-pointer hover:bg-zinc-100/80">
            Raw log ({rawLines.length} บรรทัด)
          </summary>
          <pre className="p-3 text-xs font-mono text-zinc-600 whitespace-pre-wrap break-all max-h-48 overflow-auto border-t border-zinc-200">
            {rawLines.join("\n")}
          </pre>
        </details>
      )}
    </div>
  );
}
