"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import ErrorModal from "../../components/ErrorModal";
import { validateUrl } from "../../lib/validateUrl";

type ScoredUrl = {
  url: string;
  score: number;
  level?: string;
  reason?: string;
  status?: number | null;
};

type WsEvent =
  | { type: "subscribed"; jobId: string }
  | { type: "status"; jobId: string; status: string; message?: string }
  | { type: "progress"; jobId: string; message: string; stream?: "stderr" }
  | {
      type: "done";
      jobId: string;
      status: "completed";
      resultFile?: string;
      totalUrls?: number;
      scoredUrls?: number;
      scanAt?: string;
    }
  | { type: "error"; jobId: string; message: string };

type ScanPhase = "idle" | "starting" | "processing" | "scoring" | "done" | "error";

function getBackendBaseUrl() {
  return process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
}

function getWsUrl() {
  const fromEnv = process.env.NEXT_PUBLIC_WS_URL;
  if (fromEnv) return fromEnv;
  const base = getBackendBaseUrl();
  if (base.startsWith("https://")) return base.replace("https://", "wss://");
  if (base.startsWith("http://")) return base.replace("http://", "ws://");
  return "ws://127.0.0.1:8080";
}

function cn(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

function formatFetchError(err: Error): string {
  if (err.message === "Failed to fetch") {
    return "ไม่สามารถเชื่อมต่อ backend ได้ — ตรวจสอบว่า backend รันอยู่ และ NEXT_PUBLIC_BACKEND_URL ถูกต้อง";
  }
  return err.message;
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

export default function FfufClient() {
  const backend = getBackendBaseUrl();
  const wsUrl = getWsUrl();

  const [targetUrl, setTargetUrl] = useState("http://113.45.171.231/");
  const [wordlistMode, setWordlistMode] = useState<"default" | "upload">("default");
  const [uploadedFileId, setUploadedFileId] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const [mc, setMc] = useState("");
  const [fc, setFc] = useState("");
  const [threads, setThreads] = useState<number | "">("");
  const [rate, setRate] = useState<number | "">("");
  const [extensions, setExtensions] = useState("");
  const [followRedirects, setFollowRedirects] = useState(false);
  const [autoCalibrate, setAutoCalibrate] = useState(false);
  const [errorModalMessage, setErrorModalMessage] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);

  function isScanPhase(
    x: string
  ): x is "starting" | "processing" | "scoring" {
    return x === "starting" || x === "processing" || x === "scoring";
  }

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

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const ext = file.name.toLowerCase().endsWith(".txt");
    if (!ext) {
      setLogs((prev) => [...prev, "รับเฉพาะไฟล์ .txt เท่านั้น"]);
      return;
    }
    setUploading(true);
    setUploadedFileId(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${backend}/api/upload/wordlist`, {
        method: "POST",
        body: form,
      });
      const data = (await res.json()) as { fileId?: string; error?: string };
      if (!res.ok || !data.fileId) {
        throw new Error(data.error || "Upload failed");
      }
      setUploadedFileId(data.fileId);
      setWordlistMode("upload");
      setLogs((prev) => [...prev, `อัปโหลด wordlist สำเร็จ: ${file.name}`]);
    } catch (err) {
      setLogs((prev) => [...prev, `Upload error: ${(err as Error).message}`]);
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  }

  async function startScan() {
    const urlError = validateUrl(targetUrl);
    if (urlError) {
      setErrorModalMessage(urlError);
      return;
    }

    setLogs([]);
    setResults(null);
    setResultFile(null);
    setPhase("starting");
    setStatusText("Starting...");

    const wordlist =
      wordlistMode === "default"
        ? "default"
        : uploadedFileId
          ? { fileId: uploadedFileId }
          : "default";

    if (wordlistMode === "upload" && !uploadedFileId) {
      setPhase("error");
      setStatusText("กรุณาอัปโหลดไฟล์ wordlist (.txt) ก่อน");
      setErrorModalMessage("กรุณาอัปโหลดไฟล์ wordlist (.txt) ก่อน");
      return;
    }

    const flags: string[] = [];
    if (mc.trim()) {
      flags.push("-mc", mc.trim());
    }
    if (fc.trim()) {
      flags.push("-fc", fc.trim());
    }
    if (threads !== "" && Number(threads) > 0) {
      flags.push("-t", String(threads));
    }
    if (rate !== "" && Number(rate) > 0) {
      flags.push("-rate", String(rate));
    }
    if (extensions.trim()) {
      flags.push("-e", extensions.trim());
    }
    if (followRedirects) {
      flags.push("-r");
    }
    if (autoCalibrate) {
      flags.push("-ac");
    }

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
              `Completed. Scored ${msg.scoredUrls ?? "?"}/${msg.totalUrls ?? "?"}`
            );
            if (msg.resultFile) {
              setResultFile(msg.resultFile);
              void loadResultFile(msg.resultFile);
            }
          } else if (msg.type === "error") {
            setPhase("error");
            setStatusText(msg.message);
            setErrorModalMessage(msg.message);
          }
        } catch {
          // ignore
        }
      };

      ws.onopen = async () => {
        try {
          const res = await fetch(`${backend}/api/scan/ffuf`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target_url: targetUrl,
              wordlist,
              flags,
            }),
          });
          const data = (await res.json()) as { jobId?: string; error?: string };
          if (!data.jobId) {
            const errMsg = data.error || "Failed to start scan";
            setPhase("error");
            setStatusText(errMsg);
            setErrorModalMessage(errMsg);
            return;
          }
          setJobId(data.jobId);
          ws.send(JSON.stringify({ type: "subscribe", jobId: data.jobId }));
          setStatusText("Subscribed. Waiting for scan output...");
        } catch (e) {
          const msg = (e as Error).message;
          setPhase("error");
          setStatusText(msg);
          setErrorModalMessage(msg);
        }
      };

      ws.onerror = () => {
        setPhase("error");
        setStatusText("WebSocket error");
        setErrorModalMessage("WebSocket error");
      };
    } catch (e) {
      const msg = (e as Error).message;
      setPhase("error");
      setStatusText(msg);
      setErrorModalMessage(msg);
    }
  }

  async function loadResultFile(file: string) {
    setResultsLoading(true);
    try {
      const res = await fetch(
        `${backend}/api/result?path=${encodeURIComponent(file)}`,
        { cache: "no-store" }
      );
      if (!res.ok) throw new Error(`Failed to load result (${res.status})`);
      const data = (await res.json()) as ScoredUrl[];
      setResults(data);
    } catch (e) {
      const msg = formatFetchError(e as Error);
      setResults(null);
      setLogs((prev) => [...prev, `Failed to load results: ${msg}`]);
      setErrorModalMessage(msg);
    } finally {
      setResultsLoading(false);
    }
  }

  return (
    <>
      <ErrorModal
        open={!!errorModalMessage}
        message={errorModalMessage ?? ""}
        onClose={() => setErrorModalMessage(null)}
      />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <section className="lg:col-span-2">
        <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-zinc-900">Target</h2>
          <label className="mt-3 block text-xs font-medium text-zinc-600">
            URL (ต้องลงท้ายด้วย / ถ้าต้องการ path ตาม wordlist)
          </label>
          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://example.com/"
            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm outline-none ring-sky-200 focus:ring-4"
          />

          <h2 className="mt-5 text-sm font-semibold text-zinc-900">
            Wordlist
          </h2>
          <div className="mt-3 space-y-3">
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="wordlist"
                checked={wordlistMode === "default"}
                onChange={() => setWordlistMode("default")}
              />
              <span className="text-sm">Default (SecLists common.txt)</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="wordlist"
                checked={wordlistMode === "upload"}
                onChange={() => setWordlistMode("upload")}
              />
              <span className="text-sm">อัปโหลดไฟล์ .txt</span>
            </label>
            {wordlistMode === "upload" && (
              <div className="flex items-center gap-2">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt"
                  className="hidden"
                  onChange={handleFileSelect}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={uploading}
                  className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50 disabled:opacity-50"
                >
                  {uploading ? "Uploading..." : "เลือกไฟล์ .txt"}
                </button>
                {uploadedFileId && (
                  <span className="text-xs text-zinc-500">
                    อัปโหลดแล้ว (จะลบหลังสแกนเสร็จ)
                  </span>
                )}
              </div>
            )}
          </div>

          <h2 className="mt-5 text-sm font-semibold text-zinc-900">
            Advanced flags
          </h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            Optional ffuf options to tune hidden path fuzzing.
          </p>
          <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
            <div>
              <label className="block font-semibold text-zinc-600">
                -mc (match codes)
              </label>
              <input
                value={mc}
                onChange={(e) => setMc(e.target.value)}
                placeholder="เช่น 200,301,302,403"
                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>
            <div>
              <label className="block font-semibold text-zinc-600">
                -fc (filter codes)
              </label>
              <input
                value={fc}
                onChange={(e) => setFc(e.target.value)}
                placeholder="เช่น 404,500"
                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>
            <div>
              <label className="block font-semibold text-zinc-600">
                -t (threads)
              </label>
              <input
                type="number"
                min={1}
                value={threads}
                onChange={(e) =>
                  setThreads(
                    e.target.value === "" ? "" : Number(e.target.value),
                  )
                }
                placeholder="เช่น 40"
                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>
            <div>
              <label className="block font-semibold text-zinc-600">
                -rate (req/s)
              </label>
              <input
                type="number"
                min={1}
                value={rate}
                onChange={(e) =>
                  setRate(
                    e.target.value === "" ? "" : Number(e.target.value),
                  )
                }
                placeholder="0 = ไม่จำกัด"
                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>
            <div className="col-span-2">
              <label className="block font-semibold text-zinc-600">
                -e (extensions)
              </label>
              <input
                value={extensions}
                onChange={(e) => setExtensions(e.target.value)}
                placeholder="เช่น php,html,txt"
                className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>
            <div className="col-span-2">
              <label className="flex items-center gap-2 font-semibold text-zinc-600">
                <input
                  type="checkbox"
                  checked={followRedirects}
                  onChange={(e) => setFollowRedirects(e.target.checked)}
                />
                <span>
                  -r (follow redirects){" "}
                  <span className="font-normal text-zinc-500">
                    follow HTTP redirects while fuzzing
                  </span>
                </span>
              </label>
            </div>
            <div className="col-span-2">
              <label className="flex items-center gap-2 font-semibold text-zinc-600">
                <input
                  type="checkbox"
                  checked={autoCalibrate}
                  onChange={(e) => setAutoCalibrate(e.target.checked)}
                />
                <span>
                  -ac (auto-calibrate){" "}
                  <span className="font-normal text-zinc-500">
                    automatically calibrate filters to ignore noisy responses
                  </span>
                </span>
              </label>
            </div>
          </div>

          <div className="mt-4">
            <button
              onClick={startScan}
              className={cn(
                "w-full rounded-xl px-4 py-2 text-sm font-semibold shadow-sm transition",
                phase === "starting" ||
                  phase === "processing" ||
                  phase === "scoring"
                  ? "cursor-not-allowed bg-sky-300 text-white"
                  : "bg-sky-600 text-white hover:bg-sky-700"
              )}
              disabled={
                phase === "starting" ||
                phase === "processing" ||
                phase === "scoring"
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
                    "bg-sky-100 text-sky-700"
                )}
              >
                {phase}
              </span>
            </div>
            <p className="mt-2 text-xs leading-5 text-zinc-600">{statusText}</p>
            {jobId && (
              <p className="mt-1 text-[11px] text-zinc-500">
                jobId: <span className="font-mono">{jobId}</span>
              </p>
            )}
            {resultFile && (
              <p className="mt-1 text-[11px] text-zinc-500">
                result: <span className="font-mono">{resultFile}</span>
              </p>
            )}
          </div>
        </div>

        <div className="mt-6 rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-zinc-900">Live log</h2>
          <div className="mt-3 h-64 overflow-auto rounded-xl border border-zinc-200 bg-zinc-950 p-3 font-mono text-[11px] leading-5 text-zinc-100">
            {logs.length ? (
              logs.map((l, i) => <div key={i}>{l}</div>)
            ) : (
              <div className="text-zinc-400">กด Start scan แล้วดู output ที่นี่</div>
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
                  placeholder="wp-admin, login..."
                  className="mt-1 w-56 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4"
                />
              </div>
            </div>
          </div>

          <div className="mt-4">
            {resultsLoading && (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
                Loading result file...
              </div>
            )}
            {!results && !resultsLoading && (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
                ยังไม่มีผลลัพธ์ (รอ scan เสร็จแล้วระบบจะโหลดอัตโนมัติ)
              </div>
            )}
            {filteredResults && (
              <div className="mt-3 overflow-hidden rounded-2xl border border-zinc-200">
                <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
                  <div className="col-span-1">Status</div>
                  <div className="col-span-2">Score</div>
                  <div className="col-span-9">URL</div>
                </div>
                <div className="divide-y divide-zinc-100">
                  {filteredResults.map((r) => (
                    <div
                      key={r.url}
                      className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
                    >
                      <div className="col-span-1">
                        {r.status != null ? (
                          <span className="font-mono text-xs font-medium text-zinc-700">
                            {r.status}
                          </span>
                        ) : (
                          <span className="text-zinc-400">—</span>
                        )}
                      </div>
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
                      <div className="col-span-9">
                        <a
                          href={r.url}
                          target="_blank"
                          rel="noreferrer"
                          className="block truncate text-sm font-medium text-sky-700 hover:underline"
                          title={r.url}
                        >
                          {r.url}
                        </a>
                        {r.reason && (
                          <p className="mt-1 line-clamp-2 text-xs leading-5 text-zinc-600">
                            {r.reason}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>
      </div>
    </>
  );
}
