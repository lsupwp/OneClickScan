"use client";

import { useEffect, useState } from "react";

type LanOutputProps = {
  phase: "running" | "done" | "error";
  logs?: string[];
  resultFile?: string | null;
  backend?: string;
};

type LanPort = {
  port: number;
  state: string;
  service?: string | null;
  banner?: string | null;
  rtt_ms?: number | null;
};

type LanHost = {
  ip: string;
  active: boolean;
  hostname?: string | null;
  mac?: string | null;
  vendor?: string | null;
  os_guess?: string | null;
  open_ports: LanPort[];
};

type LanScanResult = {
  meta?: {
    cidr?: string;
    mode?: string;
    ports_count?: number;
    timestamp?: number;
    host_count?: number;
    active_count?: number;
  };
  results?: LanHost[];
};

export default function LanOutput({ phase, logs = [], resultFile, backend = "" }: LanOutputProps) {
  const [data, setData] = useState<LanScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!resultFile || !backend || phase !== "done") return;

    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch(`${backend}/api/result?path=${encodeURIComponent(resultFile)}`, { cache: "no-store" });
        if (!res.ok) {
          if (cancelled) return;
          setError("โหลดผลลัพธ์ไม่สำเร็จ");
          return;
        }
        const json = (await res.json()) as LanScanResult;
        if (cancelled) return;
        setData(json);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError((e as Error).message);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [backend, resultFile, phase]);

  const meta = data?.meta;
  const hosts = data?.results || [];
  const activeHosts = hosts.filter((h) => h.active);

  return (
    <div className="space-y-4 text-sm text-zinc-800">
      {phase === "running" && logs.length > 0 && (
        <pre className="max-h-64 overflow-auto rounded-xl bg-zinc-950/90 p-3 text-xs text-zinc-100">
          {logs.join("\n")}
        </pre>
      )}

      {phase === "done" && (
        <>
          {error && (
            <p className="text-sm font-medium text-red-600">
              ⚠ {error}
            </p>
          )}

          {meta && (
            <div className="rounded-2xl border border-emerald-100 bg-emerald-50/70 p-4 text-sm">
              <div className="flex flex-wrap gap-3">
                <div>
                  <span className="text-xs font-semibold uppercase text-emerald-700">CIDR</span>
                  <div className="text-sm font-mono text-emerald-900">{meta.cidr || "-"}</div>
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase text-emerald-700">Mode</span>
                  <div className="text-sm text-emerald-900">{meta.mode || "-"}</div>
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase text-emerald-700">Hosts</span>
                  <div className="text-sm text-emerald-900">
                    {meta.active_count ?? activeHosts.length} / {meta.host_count ?? hosts.length} active
                  </div>
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase text-emerald-700">Ports</span>
                  <div className="text-sm text-emerald-900">
                    {meta.ports_count != null ? `${meta.ports_count} ports` : "-"}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="rounded-2xl border border-zinc-200 bg-white">
            <div className="border-b border-zinc-200 px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">
              Active hosts
            </div>
            {activeHosts.length === 0 ? (
              <div className="px-4 py-6 text-sm text-zinc-500">
                ไม่พบ host ที่ตอบสนองในช่วง IP นี้
              </div>
            ) : (
              <div className="max-h-80 overflow-auto">
                <table className="min-w-full text-xs">
                  <thead className="bg-zinc-50">
                    <tr>
                      <th className="sticky top-0 z-10 border-b border-zinc-200 px-3 py-2 text-left font-semibold text-zinc-700">IP</th>
                      <th className="sticky top-0 z-10 border-b border-zinc-200 px-3 py-2 text-left font-semibold text-zinc-700">MAC / Vendor</th>
                      <th className="sticky top-0 z-10 border-b border-zinc-200 px-3 py-2 text-left font-semibold text-zinc-700">Hostname / OS</th>
                      <th className="sticky top-0 z-10 border-b border-zinc-200 px-3 py-2 text-left font-semibold text-zinc-700">Open ports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeHosts.map((h) => {
                      const ports = h.open_ports || [];
                      const portsText = ports
                        .slice(0, 12)
                        .map((p) => `${p.port}${p.service ? ` (${p.service})` : ""}`)
                        .join(", ");
                      const more = ports.length > 12 ? `, +${ports.length - 12}` : "";
                      return (
                        <tr key={h.ip} className="border-b border-zinc-100">
                          <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-zinc-900">{h.ip}</td>
                          <td className="px-3 py-2 align-top">
                            <div className="text-[11px] font-mono text-zinc-800">
                              {h.mac || "-"}
                            </div>
                            <div className="mt-0.5 text-[11px] text-zinc-500">
                              {h.vendor || ""}
                            </div>
                          </td>
                          <td className="px-3 py-2 align-top">
                            <div className="text-[11px] text-zinc-800">
                              {h.hostname || "-"}
                            </div>
                            <div className="mt-0.5 text-[11px] text-zinc-500">
                              {h.os_guess || ""}
                            </div>
                          </td>
                          <td className="px-3 py-2 align-top text-[11px] text-zinc-800">
                            {ports.length === 0 ? "-" : portsText + more}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

