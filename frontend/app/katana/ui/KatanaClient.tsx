"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type KatanaFlagDefinition = {
  name: string;
  label: string;
  type: "string" | "number" | "boolean";
  required?: boolean;
  default?: unknown;
  multiple?: boolean;
  description?: string;
};

type KatanaFlagsResponse = {
  name: string;
  description?: string;
  defaultFlags?: string[];
  flags?: KatanaFlagDefinition[];
};

type ScoredUrl = {
  url: string;
  score: number;
  level?: string;
  reason?: string;
};

type WsEvent =
  | {
      type: "subscribed";
      jobId: string;
    }
  | {
      type: "status";
      jobId: string;
      status: string;
      message?: string;
    }
  | {
      type: "progress";
      jobId: string;
      message: string;
      stream?: "stderr";
    }
  | {
      type: "done";
      jobId: string;
      status: "completed";
      resultFile?: string;
      totalUrls?: number;
      scoredUrls?: number;
      scanAt?: string;
    }
  | {
      type: "error";
      jobId: string;
      message: string;
    };

type ScanPhase = "idle" | "starting" | "processing" | "scoring" | "done" | "error";

function getBackendBaseUrl() {
  return process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
}

function getWsUrl() {
  const fromEnv = process.env.NEXT_PUBLIC_WS_URL;
  if (fromEnv) return fromEnv;
  // derive from backend url
  const base = getBackendBaseUrl();
  if (base.startsWith("https://")) return base.replace("https://", "wss://");
  if (base.startsWith("http://")) return base.replace("http://", "ws://");
  return "ws://127.0.0.1:8080";
}

function cn(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

function scoreColor(score: number) {
  if (score >= 5) return "bg-red-600";
  if (score === 4) return "bg-orange-500";
  if (score === 3) return "bg-amber-400";
  if (score === 2) return "bg-sky-500";
  return "bg-zinc-400";
}

function scoreLabel(score: number) {
  if (score >= 5) return "Critical";
  if (score === 4) return "High";
  if (score === 3) return "Medium";
  if (score === 2) return "Low";
  return "Info";
}

export default function KatanaClient() {
  const backend = getBackendBaseUrl();
  const wsUrl = getWsUrl();

  const [targetUrl, setTargetUrl] = useState("http://113.45.171.231/");
  const [flagValues, setFlagValues] = useState<Record<string, unknown>>({});
  const [enabledFlags, setEnabledFlags] = useState<Record<string, boolean>>({});

  const [flagsMeta, setFlagsMeta] = useState<KatanaFlagsResponse | null>(null);
  const [flagsLoading, setFlagsLoading] = useState(false);

  const [jobId, setJobId] = useState<string | null>(null);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [statusText, setStatusText] = useState<string>("");

  const [logs, setLogs] = useState<string[]>([]);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const [resultFile, setResultFile] = useState<string | null>(null);
  const [results, setResults] = useState<ScoredUrl[] | null>(null);
  const [resultsLoading, setResultsLoading] = useState(false);

  const [minScore, setMinScore] = useState(1);
  const [query, setQuery] = useState("");

  const socketRef = useRef<WebSocket | null>(null);

  function isScanPhase(x: string): x is Extract<
    ScanPhase,
    "starting" | "processing" | "scoring"
  > {
    return x === "starting" || x === "processing" || x === "scoring";
  }

  useEffect(() => {
    let cancelled = false;
    async function loadFlags() {
      setFlagsLoading(true);
      try {
        const res = await fetch(`${backend}/api/tools/katana/flags`, {
          cache: "no-store",
        });
        const data = (await res.json()) as KatanaFlagsResponse;
        if (!cancelled) {
          setFlagsMeta(data);

          const nextEnabled: Record<string, boolean> = {};
          const nextValues: Record<string, unknown> = {};

          for (const f of data.flags || []) {
            if (f.type === "boolean") {
              const d = typeof f.default === "boolean" ? f.default : false;
              nextEnabled[f.name] = d;
              nextValues[f.name] = d;
            } else if (f.type === "number") {
              const d = typeof f.default === "number" ? f.default : undefined;
              nextEnabled[f.name] = d !== undefined;
              if (d !== undefined) nextValues[f.name] = d;
            } else {
              const d = typeof f.default === "string" ? f.default : "";
              nextEnabled[f.name] = Boolean(d);
              if (d) nextValues[f.name] = d;
            }
          }

          // ensure depth has a sane default
          if (nextValues["-depth"] === undefined) {
            nextEnabled["-depth"] = true;
            nextValues["-depth"] = 5;
          }

          setEnabledFlags(nextEnabled);
          setFlagValues(nextValues);
        }
      } catch (e) {
        if (!cancelled) {
          setFlagsMeta(null);
          setLogs((prev) => [
            ...prev,
            `Failed to load flags: ${(e as Error).message}`,
          ]);
        }
      } finally {
        if (!cancelled) setFlagsLoading(false);
      }
    }
    loadFlags();
    return () => {
      cancelled = true;
    };
  }, [backend]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs]);

  useEffect(() => {
    return () => {
      if (socketRef.current) socketRef.current.close();
    };
  }, []);

  const filteredResults = useMemo(() => {
    if (!results) return null;
    const q = query.trim().toLowerCase();
    return results
      .filter((r) => r.score >= minScore)
      .filter((r) => (q ? r.url.toLowerCase().includes(q) : true))
      .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url));
  }, [results, minScore, query]);

  function buildFlagsArray() {
    const flags: string[] = [];

    // always set depth if enabled
    const depthEnabled = enabledFlags["-depth"];
    if (depthEnabled) {
      const v = Number(flagValues["-depth"]);
      if (Number.isFinite(v) && v > 0) {
        flags.push("-d", String(v));
      }
    }

    for (const def of flagsMeta?.flags || []) {
      const name = def.name;
      if (name === "-u" || name === "-depth") continue;
      if (!enabledFlags[name]) continue;

      if (def.type === "boolean") {
        const checked = Boolean(flagValues[name]);
        if (checked) flags.push(name);
        continue;
      }

      if (def.multiple) {
        const raw = String(flagValues[name] || "");
        const lines = raw
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean);
        for (const line of lines) {
          flags.push(name, line);
        }
        continue;
      }

      if (def.type === "number") {
        const v = Number(flagValues[name]);
        if (Number.isFinite(v)) flags.push(name, String(v));
        continue;
      }

      const v = String(flagValues[name] || "").trim();
      if (v) flags.push(name, v);
    }

    return flags;
  }

  async function startScan() {
    setLogs([]);
    setResults(null);
    setResultFile(null);
    setPhase("starting");
    setStatusText("Starting...");

    // connect websocket first (avoid missing early events)
    try {
      if (socketRef.current) socketRef.current.close();
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(String(event.data)) as WsEvent;
          if (msg.type === "status") {
            setPhase(isScanPhase(msg.status) ? msg.status : "starting");
            if (msg.message) setStatusText(msg.message);
          } else if (msg.type === "progress") {
            if (msg.message?.trim()) {
              setLogs((prev) => [...prev, msg.message.trimEnd()]);
            }
          } else if (msg.type === "done") {
            setPhase("done");
            setStatusText(
              `Completed. Scored ${msg.scoredUrls ?? "?"}/${msg.totalUrls ?? "?"}`,
            );
            if (msg.resultFile) {
              setResultFile(msg.resultFile);
              void loadResultFile(msg.resultFile);
            }
          } else if (msg.type === "error") {
            setPhase("error");
            setStatusText(msg.message);
          }
        } catch {
          // ignore
        }
      };

      ws.onopen = async () => {
        try {
          const flags = buildFlagsArray();
          const res = await fetch(`${backend}/api/scan/katana`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target_url: targetUrl,
              flags,
            }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            setPhase("error");
            setStatusText(data.error || "Failed to start scan");
            return;
          }
          setJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setStatusText("Subscribed. Waiting for scan output...");
        } catch (e) {
          setPhase("error");
          setStatusText((e as Error).message);
        }
      };

      ws.onerror = () => {
        setPhase("error");
        setStatusText("WebSocket error");
      };
    } catch (e) {
      setPhase("error");
      setStatusText((e as Error).message);
    }
  }

  async function loadResultFile(file: string) {
    setResultsLoading(true);
    try {
      const res = await fetch(
        `${backend}/api/result?path=${encodeURIComponent(file)}`,
        { cache: "no-store" },
      );
      if (!res.ok) {
        throw new Error(`Failed to load result file (${res.status})`);
      }
      const data = (await res.json()) as ScoredUrl[];
      setResults(data);
    } catch (e) {
      setResults(null);
      setLogs((prev) => [...prev, `Failed to load results: ${(e as Error).message}`]);
    } finally {
      setResultsLoading(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
      <section className="lg:col-span-2">
        <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-zinc-900">Target</h2>
          <label className="mt-3 block text-xs font-medium text-zinc-600">
            URL
          </label>
          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://example.com/"
            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm outline-none ring-sky-200 focus:ring-4"
          />

          <div className="mt-4">
            <button
              onClick={startScan}
              className={cn(
                "w-full rounded-xl px-4 py-2 text-sm font-semibold shadow-sm transition",
                phase === "starting" || phase === "processing" || phase === "scoring"
                  ? "cursor-not-allowed bg-sky-300 text-white"
                  : "bg-sky-600 text-white hover:bg-sky-700",
              )}
              disabled={
                phase === "starting" || phase === "processing" || phase === "scoring"
              }
            >
              Start scan
            </button>
          </div>

          <div className="mt-4 rounded-xl border border-zinc-200 bg-zinc-50 p-3">
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs font-semibold text-zinc-700">Status</p>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-[11px] font-semibold",
                  phase === "idle" && "bg-zinc-200 text-zinc-700",
                  phase === "done" && "bg-emerald-100 text-emerald-700",
                  phase === "error" && "bg-red-100 text-red-700",
                  (phase === "starting" ||
                    phase === "processing" ||
                    phase === "scoring") &&
                    "bg-sky-100 text-sky-700",
                )}
              >
                {phase}
              </span>
            </div>
            <p className="mt-2 text-xs leading-5 text-zinc-600">{statusText}</p>
            {jobId ? (
              <p className="mt-1 text-[11px] text-zinc-500">
                jobId: <span className="font-mono">{jobId}</span>
              </p>
            ) : null}
            {resultFile ? (
              <p className="mt-1 text-[11px] text-zinc-500">
                result: <span className="font-mono">{resultFile}</span>
              </p>
            ) : null}
          </div>

          <div className="mt-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-zinc-900">Katana flags</h2>
              {flagsLoading ? (
                <span className="text-xs text-zinc-500">loading...</span>
              ) : null}
            </div>
            <div className="mt-3 rounded-xl border border-zinc-200 bg-white p-3">
              <p className="text-xs text-zinc-600">
                Default:{" "}
                <span className="font-mono">
                  {(flagsMeta?.defaultFlags || []).join(" ")}
                </span>
              </p>
              <div className="mt-4 space-y-3">
                {(flagsMeta?.flags || [])
                  .filter((f) => f.name !== "-u")
                  .map((f) => {
                    const enabled = Boolean(enabledFlags[f.name]);
                    const id = `flag-${f.name.replace(/[^a-zA-Z0-9_-]/g, "")}`;

                    return (
                      <div
                        key={f.name}
                        className="rounded-xl border border-zinc-200 bg-zinc-50 p-3"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <label
                            htmlFor={id}
                            className="flex items-start gap-2 text-sm font-semibold text-zinc-900"
                          >
                            <input
                              id={id}
                              type="checkbox"
                              className="mt-1"
                              checked={enabled}
                              onChange={(e) =>
                                setEnabledFlags((prev) => ({
                                  ...prev,
                                  [f.name]: e.target.checked,
                                }))
                              }
                            />
                            <span>
                              <span className="font-mono">{f.name}</span>{" "}
                              <span className="text-zinc-700">{f.label}</span>
                            </span>
                          </label>
                        </div>
                        {f.description ? (
                          <p className="mt-1 text-xs text-zinc-600">
                            {f.description}
                          </p>
                        ) : null}

                        {f.type === "boolean" ? (
                          <div className="mt-2 text-xs text-zinc-600">
                            จะถูกส่งเมื่อเปิดใช้งาน
                          </div>
                        ) : f.multiple ? (
                          <textarea
                            disabled={!enabled}
                            value={String(flagValues[f.name] || "")}
                            onChange={(e) =>
                              setFlagValues((prev) => ({
                                ...prev,
                                [f.name]: e.target.value,
                              }))
                            }
                            placeholder="ใส่ 1 ค่า / 1 บรรทัด (เช่น Authorization: Bearer xxx)"
                            className="mt-2 h-20 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4 disabled:bg-zinc-100"
                          />
                        ) : (
                          <input
                            disabled={!enabled}
                            type={f.type === "number" ? "number" : "text"}
                            value={
                              f.type === "number"
                                ? String(flagValues[f.name] ?? "")
                                : String(flagValues[f.name] ?? "")
                            }
                            placeholder={
                              f.name === "-timeout"
                                ? "ตัวอย่าง: 10 (วินาที)"
                                : f.name === "-c"
                                  ? "ตัวอย่าง: 10 (จำนวน concurrent fetchers)"
                                  : f.name === "-s"
                                    ? "ตัวอย่าง: depth-first หรือ breadth-first"
                                    : undefined
                            }
                            onChange={(e) =>
                              setFlagValues((prev) => ({
                                ...prev,
                                [f.name]:
                                  f.type === "number"
                                    ? Number(e.target.value)
                                    : e.target.value,
                              }))
                            }
                            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4 disabled:bg-zinc-100"
                          />
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        </div>

        <div className="mt-6 rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-zinc-900">Live log</h2>
          <div className="mt-3 h-64 overflow-auto rounded-xl border border-zinc-200 bg-zinc-950 p-3 font-mono text-[11px] leading-5 text-zinc-100">
            {logs.length ? (
              logs.map((l, i) => <div key={i}>{l}</div>)
            ) : (
              <div className="text-zinc-400">
                กด Start scan แล้วดู output ที่นี่
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>
      </section>

      <section className="lg:col-span-3">
        <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900">Results</h2>
              <p className="mt-1 text-xs text-zinc-600">
                แสดง URL ที่ได้คะแนนจาก Gemini (ยิ่งมากยิ่งเสี่ยง)
              </p>
            </div>

            <div className="flex flex-wrap gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-zinc-600">
                  Min score
                </label>
                <select
                  value={minScore}
                  onChange={(e) => setMinScore(Number(e.target.value))}
                  className="mt-1 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4"
                >
                  {[1, 2, 3, 4, 5].map((s) => (
                    <option key={s} value={s}>
                      {s}+
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-zinc-600">
                  Search
                </label>
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="wp-admin, xmlrpc..."
                  className="mt-1 w-56 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4"
                />
              </div>
            </div>
          </div>

          <div className="mt-4">
            {resultsLoading ? (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
                Loading result file...
              </div>
            ) : null}

            {!results && !resultsLoading ? (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
                ยังไม่มีผลลัพธ์ (รอ scan เสร็จแล้วระบบจะโหลดไฟล์อัตโนมัติ)
              </div>
            ) : null}

            {filteredResults ? (
              <div className="mt-3 overflow-hidden rounded-2xl border border-zinc-200">
                <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
                  <div className="col-span-2">Score</div>
                  <div className="col-span-10">URL</div>
                </div>
                <div className="divide-y divide-zinc-100">
                  {filteredResults.map((r) => (
                    <div
                      key={r.url}
                      className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
                    >
                      <div className="col-span-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              "inline-flex h-2.5 w-2.5 rounded-full",
                              scoreColor(r.score),
                            )}
                          />
                          <span className="text-sm font-semibold text-zinc-900">
                            {r.score}
                          </span>
                          <span className="hidden text-[11px] text-zinc-500 sm:inline">
                            {r.level || scoreLabel(r.score)}
                          </span>
                        </div>
                      </div>
                      <div className="col-span-10">
                        <a
                          href={r.url}
                          target="_blank"
                          rel="noreferrer"
                          className="block truncate text-sm font-medium text-sky-700 hover:underline"
                          title={r.url}
                        >
                          {r.url}
                        </a>
                        {r.reason ? (
                          <p className="mt-1 line-clamp-2 text-xs leading-5 text-zinc-600">
                            {r.reason}
                          </p>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}

