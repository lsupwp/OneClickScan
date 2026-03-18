"use client";

import { useEffect, useMemo, useState } from "react";
import { LogView } from "./logView";

type PortEntry = {
  port: string;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
};

type HostEntry = {
  ip: string | null;
  hostname: string | null;
  os: string | null;
  ports: PortEntry[];
};

type NmapResult = {
  hosts: HostEntry[];
  summary?: { totalHosts: number; openPorts: number };
};

const ACCENT = "bg-teal-100 text-teal-800";

export default function NmapOutput({
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
  const [data, setData] = useState<NmapResult | null>(null);
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
        if (!r.ok) throw new Error("โหลดผล nmap ไม่สำเร็จ");
        return r.json();
      })
      .then((json: unknown) => {
        if (cancelled) return;
        const obj = json as NmapResult;
        setData(obj?.hosts ? obj : { hosts: [], summary: { totalHosts: 0, openPorts: 0 } });
      })
      .catch((e) => {
        if (!cancelled) setLoadError((e as Error).message || "โหลดผลไม่สำเร็จ");
      });
    return () => {
      cancelled = true;
    };
  }, [phase, resultFile, resolvedBackend]);

  if (phase === "running") {
    return (
      <div className="space-y-4">
        <p className="text-sm text-teal-700/80">กำลังรัน nmap…</p>
        <LogView logs={logs} accentClass={ACCENT} emptyMessage="ยังไม่มี log" />
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="space-y-4">
        {logs.length > 0 && (
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-zinc-900 p-3 text-xs font-mono text-zinc-100">
            {logs.join("\n")}
          </pre>
        )}
      </div>
    );
  }

  const hosts = data?.hosts ?? [];
  const summary = data?.summary;

  return (
    <div className="space-y-4">
      {loadError && <p className="text-sm text-red-600">{loadError}</p>}
      {summary && (
        <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Summary</p>
          <p className="mt-2 text-sm text-zinc-800">
            Hosts: <span className="font-semibold">{summary.totalHosts}</span> • Open ports:{" "}
            <span className="font-semibold">{summary.openPorts}</span>
          </p>
        </div>
      )}
      {hosts.length === 0 && !loadError && (
        <p className="text-sm text-zinc-500">ไม่มีผลลัพธ์</p>
      )}
      {hosts.map((host, idx) => (
        <div key={idx} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-zinc-900">{host.ip || "—"}</span>
            {host.hostname && (
              <span className="text-xs text-zinc-500">{host.hostname}</span>
            )}
            {host.os && (
              <span className="rounded-lg border border-zinc-200 bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-700">
                {host.os}
              </span>
            )}
          </div>
          <div className="mt-3 space-y-2">
            {host.ports.length === 0 ? (
              <p className="text-xs text-zinc-500">ไม่มี port เปิด</p>
            ) : (
              host.ports.map((p) => (
                <div
                  key={`${p.port}-${p.protocol}`}
                  className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-100 bg-zinc-50/50 px-3 py-2 text-sm"
                >
                  <span className="font-mono font-semibold text-zinc-800">
                    {p.port}/{p.protocol}
                  </span>
                  {p.service && (
                    <span className="text-zinc-700">{p.service}</span>
                  )}
                  {(p.product || p.version) && (
                    <span className="text-xs text-zinc-600">
                      {[p.product, p.version].filter(Boolean).join(" ")}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
