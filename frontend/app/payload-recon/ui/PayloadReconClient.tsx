"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import ErrorModal from "../../components/ErrorModal";
import { validateUrl } from "../../lib/validateUrl";

type ToolSource = "ffuf" | "katana" | "both";

type ScoredUrl = {
  url: string;
  score: number;
  level?: string;
  reason?: string;
  status?: number | null;
};

type PayloadEntry = {
  found_in: string[];
  action: string;
  method: string;
  query_string: Record<string, string>;
  payload: Record<string, string>;
  example_urls?: string[];
};

function getBackendBaseUrl() {
  return process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
}

function cn(...xs: Array<string | false | undefined | null>) {
  return xs.filter(Boolean).join(" ");
}

function isStaticAssetUrl(url: string) {
  const path = url.split("?")[0].toLowerCase();
  return path.endsWith(".js") || path.endsWith(".css");
}

function formatFetchError(err: Error): string {
  if (err.message === "Failed to fetch") {
    return "ไม่สามารถเชื่อมต่อ backend ได้ — ตรวจสอบว่า backend รันอยู่ และ NEXT_PUBLIC_BACKEND_URL ถูกต้อง";
  }
  return err.message;
}

export default function PayloadReconClient() {
  const backend = getBackendBaseUrl();

  const [tool, setTool] = useState<ToolSource>("ffuf");
  const [targetUrl, setTargetUrl] = useState("http://113.45.171.231/");
  const [minScore, setMinScore] = useState(1);
  const [query, setQuery] = useState("");

  const [results, setResults] = useState<ScoredUrl[] | null>(null);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [resultsError, setResultsError] = useState<string | null>(null);

  const [selectedUrls, setSelectedUrls] = useState<Record<string, boolean>>({});

  const [payloadEntries, setPayloadEntries] = useState<PayloadEntry[] | null>(
    null,
  );
  const [payloadLoading, setPayloadLoading] = useState(false);
  const [payloadError, setPayloadError] = useState<string | null>(null);

  const [showTargetNotFoundModal, setShowTargetNotFoundModal] = useState(false);
  const [autoScanLoading, setAutoScanLoading] = useState(false);
  const [errorModalMessage, setErrorModalMessage] = useState<string | null>(null);

  const filteredResults = useMemo(() => {
    if (!results) return null;
    const q = query.trim().toLowerCase();
    return results
      .filter((r) => !isStaticAssetUrl(r.url))
      .filter((r) => r.score >= minScore)
      .filter((r) => (q ? r.url.toLowerCase().includes(q) : true))
      .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url));
  }, [results, minScore, query]);

  const allResultUrls = useMemo(
    () =>
      results
        ? Array.from(
            new Set(
              results
                .filter((r) => !isStaticAssetUrl(r.url))
                .map((r) => r.url),
            ),
          ).sort()
        : [],
    [results],
  );

  const anySelectedUrl = useMemo(
    () => allResultUrls.some((u) => selectedUrls[u]),
    [allResultUrls, selectedUrls],
  );

  function toggleSelectUrl(url: string) {
    setSelectedUrls((prev) => ({ ...prev, [url]: !prev[url] }));
  }

  function toggleSelectAllUrls() {
    if (!allResultUrls.length) return;
    const selectAll = !anySelectedUrl;
    const next: Record<string, boolean> = {};
    for (const u of allResultUrls) {
      next[u] = selectAll;
    }
    setSelectedUrls(next);
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

  function formatParamValue(v: string | undefined | null) {
    if (v && v.trim() !== "") return v;
    return "null";
  }

  async function loadToolResults() {
    const urlError = validateUrl(targetUrl);
    if (urlError) {
      setErrorModalMessage(urlError);
      return;
    }

    setResultsLoading(true);
    setResultsError(null);
    setResults(null);
    setSelectedUrls({});
    setPayloadEntries(null);
    setPayloadError(null);

    try {
      const res = await fetch(`${backend}/api/targets`, {
        cache: "no-store",
      });
      if (!res.ok) {
        throw new Error(`Failed to list targets (${res.status})`);
      }
      const targets = (await res.json()) as {
        target_id: number;
        target_name: string;
      }[];

      const normalizeUrl = (u: string) =>
        u.replace(/\/+$/, "") || u || "/";
      const inputNorm = normalizeUrl(targetUrl.trim());

      const matching = targets.find(
        (t) => normalizeUrl(t.target_name) === inputNorm,
      );
      if (!matching) {
        const err = new Error("ไม่พบ target นี้ในฐานข้อมูล (ต้องสแกนก่อนด้วย Katana/FFuf)");
        (err as Error & { code?: string }).code = "TARGET_NOT_FOUND";
        throw err;
      }

      const loadOneTool = async (which: "ffuf" | "katana") => {
        const scansRes = await fetch(
          `${backend}/api/targets/${matching.target_id}/${which}`,
          { cache: "no-store" },
        );
        if (!scansRes.ok) {
          throw new Error(
            `Failed to load ${which} scans for target (${scansRes.status})`,
          );
        }
        const scans = (await scansRes.json()) as {
          result_file: string;
        }[];
        if (!scans.length) {
          return [] as ScoredUrl[];
        }
        const latest = scans[0];
        const fileRes = await fetch(
          `${backend}/api/result?path=${encodeURIComponent(latest.result_file)}`,
          { cache: "no-store" },
        );
        if (!fileRes.ok) {
          throw new Error(`Failed to load result file (${fileRes.status})`);
        }
        const data = (await fileRes.json()) as ScoredUrl[];
        // ตัด status 403 / 302 ที่ไม่อยากใช้เป็น entry point ทิ้ง
        return data.filter(
          (r) => !(r.status === 403 || r.status === 302),
        );
      };

      let combined: ScoredUrl[] = [];
      if (tool === "both") {
        const fromFfuf = await loadOneTool("ffuf");
        const fromKatana = await loadOneTool("katana");
        const byUrl = new Map<string, ScoredUrl>();
        for (const r of [...fromFfuf, ...fromKatana]) {
          if (!byUrl.has(r.url)) {
            byUrl.set(r.url, r);
          }
        }
        combined = Array.from(byUrl.values());
        if (!combined.length) {
          throw new Error("ยังไม่มีผล FFuf หรือ Katana สำหรับ target นี้");
        }
      } else {
        combined = await loadOneTool(tool);
        if (!combined.length) {
          throw new Error(
            `ยังไม่มีผล ${tool === "ffuf" ? "FFuf" : "Katana"} สำหรับ target นี้`,
          );
        }
      }

      setResults(combined);
    } catch (e) {
      const err = e as Error & { code?: string };
      setResults(null);
      if (err.code === "TARGET_NOT_FOUND" || err.message?.includes("ไม่พบ target นี้ในฐานข้อมูล")) {
        setResultsError(null);
        setShowTargetNotFoundModal(true);
      } else {
        setResultsError(null);
        setErrorModalMessage(formatFetchError(err));
      }
    } finally {
      setResultsLoading(false);
    }
  }

  async function startDefaultScan() {
    const urlError = validateUrl(targetUrl);
    if (urlError) {
      setErrorModalMessage(urlError);
      return;
    }
    const url = targetUrl.trim();
    setAutoScanLoading(true);
    try {
      if (tool === "ffuf") {
        const res = await fetch(`${backend}/api/scan/ffuf`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target_url: url,
            wordlist: "default",
            flags: [],
          }),
        });
        const data = (await res.json()) as { jobId?: string; error?: string };
        if (!res.ok || !data.jobId) throw new Error(data.error || "Failed to start FFuf");
      } else if (tool === "katana") {
        const res = await fetch(`${backend}/api/scan/katana`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_url: url, flags: [] }),
        });
        const data = (await res.json()) as { jobId?: string; error?: string };
        if (!res.ok || !data.jobId) throw new Error(data.error || "Failed to start Katana");
      } else {
        const [katanaRes, ffufRes] = await Promise.all([
          fetch(`${backend}/api/scan/katana`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: url, flags: [] }),
          }),
          fetch(`${backend}/api/scan/ffuf`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target_url: url,
              wordlist: "default",
              flags: [],
            }),
          }),
        ]);
        const katanaData = (await katanaRes.json()) as { jobId?: string; error?: string };
        const ffufData = (await ffufRes.json()) as { jobId?: string; error?: string };
        if (!katanaRes.ok || !katanaData.jobId) throw new Error(katanaData.error || "Failed to start Katana");
        if (!ffufRes.ok || !ffufData.jobId) throw new Error(ffufData.error || "Failed to start FFuf");
      }
      setShowTargetNotFoundModal(false);
      setResultsError(
        tool === "both"
          ? "เริ่มสแกน Katana และ FFuf ให้แล้ว (ค่า default). รอสักครู่แล้วกดโหลดผลอีกครั้ง"
          : `เริ่มสแกน ${tool === "ffuf" ? "FFuf" : "Katana"} ให้แล้ว (ค่า default). รอสักครู่แล้วกดโหลดผลอีกครั้ง`,
      );
    } catch (e) {
      setErrorModalMessage(formatFetchError(e as Error));
    } finally {
      setAutoScanLoading(false);
    }
  }

  function closeTargetNotFoundModal() {
    setShowTargetNotFoundModal(false);
    setResultsError("ไม่พบ target นี้ในฐานข้อมูล (ต้องสแกนก่อนด้วย Katana/FFuf)");
  }

  async function runPayloadReconScan(mode: "all" | "selected") {
    if (!results || !results.length) {
      setPayloadError("ยังไม่มีผลจาก tool ให้โหลดผลก่อน");
      setPayloadEntries(null);
      return;
    }

    const urlsFromResults = Array.from(
      new Set(
        results
          .filter((r) => !isStaticAssetUrl(r.url))
          .map((r) => r.url),
      ),
    );
    const urls =
      mode === "all"
        ? urlsFromResults
        : urlsFromResults.filter((u) => selectedUrls[u]);

    if (!urls.length) {
      setPayloadError("กรุณาเลือก URL อย่างน้อย 1 รายการ");
      setPayloadEntries(null);
      return;
    }

    setPayloadLoading(true);
    setPayloadError(null);
    try {
      const res = await fetch(`${backend}/api/payload/recon`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls }),
      });
      const data = (await res.json()) as
        | PayloadEntry[]
        | { error?: string };
      if (!res.ok || !Array.isArray(data)) {
        const msg =
          !Array.isArray(data) && data?.error
            ? data.error
            : "Payload recon failed";
        setPayloadError(null);
        setErrorModalMessage(msg);
        setPayloadEntries(null);
        return;
      }
      setPayloadEntries(data);
    } catch (e) {
      setPayloadError(null);
      setErrorModalMessage(formatFetchError(e as Error));
      setPayloadEntries(null);
    } finally {
      setPayloadLoading(false);
    }
  }

  return (
    <>
      <ErrorModal
        open={!!errorModalMessage}
        message={errorModalMessage ?? ""}
        onClose={() => setErrorModalMessage(null)}
      />

      {showTargetNotFoundModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white p-6 shadow-xl">
            <h3 className="text-base font-semibold text-zinc-900">
              ไม่พบ target ในฐานข้อมูล
            </h3>
            <p className="mt-2 text-sm text-zinc-600">
              ยังไม่มีผลสแกนสำหรับ target นี้ ต้องการให้ระบบสแกนให้ด้วยค่า
              default เลย หรือจะไปสแกนเองที่หน้า Katana/FFuf?
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={startDefaultScan}
                disabled={autoScanLoading}
                className={cn(
                  "rounded-xl px-4 py-2 text-sm font-semibold shadow-sm",
                  autoScanLoading
                    ? "cursor-not-allowed bg-zinc-200 text-zinc-500"
                    : "bg-sky-600 text-white hover:bg-sky-700",
                )}
              >
                {autoScanLoading ? "กำลังเริ่มสแกน..." : "สแกนให้เลย (ค่า default)"}
              </button>
              <button
                type="button"
                onClick={closeTargetNotFoundModal}
                disabled={autoScanLoading}
                className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 shadow-sm hover:bg-zinc-50 disabled:opacity-50"
              >
                ไปสแกนเอง
              </button>
            </div>
            <p className="mt-4 text-xs text-zinc-500">
              ไปสแกนเอง:{" "}
              <Link
                href="/katana"
                className="font-medium text-sky-600 hover:underline"
              >
                Katana
              </Link>{" "}
              หรือ{" "}
              <Link
                href="/ffuf"
                className="font-medium text-sky-600 hover:underline"
              >
                FFuf
              </Link>
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <section className="lg:col-span-2">
          <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
            <h2 className="text-sm font-semibold text-zinc-900">
              เลือก Tool และ Target
            </h2>
          <p className="mt-1 text-xs text-zinc-600">
            ดึง URLs จากผลสแกน Katana หรือ FFuf ที่มีอยู่ แล้วหาว่าแต่ละ path
            มี form / params อะไรบ้าง
          </p>

          <div className="mt-4 space-y-3 text-sm">
            <div>
              <label className="block text-xs font-semibold text-zinc-600">
                Tool source
              </label>
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  onClick={() => setTool("ffuf")}
                  className={cn(
                    "flex-1 rounded-xl border px-3 py-2 text-xs font-semibold shadow-sm",
                    tool === "ffuf"
                      ? "border-sky-500 bg-sky-50 text-sky-700"
                      : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50",
                  )}
                >
                  FFuf Hidden Path
                </button>
                <button
                  type="button"
                  onClick={() => setTool("katana")}
                  className={cn(
                    "flex-1 rounded-xl border px-3 py-2 text-xs font-semibold shadow-sm",
                    tool === "katana"
                      ? "border-sky-500 bg-sky-50 text-sky-700"
                      : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50",
                  )}
                >
                  Katana Scan
                </button>
                <button
                  type="button"
                  onClick={() => setTool("both")}
                  className={cn(
                    "flex-1 rounded-xl border px-3 py-2 text-xs font-semibold shadow-sm",
                    tool === "both"
                      ? "border-sky-500 bg-sky-50 text-sky-700"
                      : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50",
                  )}
                >
                  ทั้ง FFuf + Katana
                </button>
              </div>
            </div>

            <div>
              <label className="mt-3 block text-xs font-semibold text-zinc-600">
                Target URL (ต้องตรงกับที่ใช้สแกน)
              </label>
              <input
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://example.com/"
                className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm outline-none ring-sky-200 focus:ring-4"
              />
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={loadToolResults}
                className="w-full rounded-xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-sky-700"
                disabled={resultsLoading}
              >
                {tool === "both"
                  ? "โหลดผลจาก FFuf + Katana"
                  : `โหลดผลจาก ${tool === "ffuf" ? "FFuf" : "Katana"}`}
              </button>
            </div>
          </div>

          <div className="mt-4 rounded-xl border border-zinc-200 bg-zinc-50 p-3">
            {resultsLoading ? (
              <p className="text-xs text-zinc-700">
                กำลังโหลดผล{" "}
                {tool === "both"
                  ? "FFuf + Katana"
                  : tool === "ffuf"
                    ? "FFuf"
                    : "Katana"}
                ...
              </p>
            ) : resultsError ? (
              <p className="text-xs text-red-700">{resultsError}</p>
            ) : results && results.length > 0 ? (
              <p className="text-xs text-zinc-700">
                พบ {results.length} URL จาก{" "}
                {tool === "both"
                  ? "FFuf + Katana"
                  : tool === "ffuf"
                    ? "FFuf"
                    : "Katana"}{" "}
                สำหรับ target นี้ (merged)
              </p>
            ) : (
              <p className="text-xs text-zinc-600">
                ยังไม่ได้โหลดผล — เลือก tool และ target แล้วกดปุ่มด้านบน
              </p>
            )}
          </div>

          <div className="mt-5 rounded-2xl border border-zinc-200 bg-white p-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h3 className="text-xs font-semibold text-zinc-800">
                  Filter URLs ก่อน payload recon
                </h3>
              </div>
              <div className="flex gap-3">
                <div>
                  <label className="block text-[11px] font-semibold text-zinc-600">
                    Min score
                  </label>
                  <select
                    value={minScore}
                    onChange={(e) => setMinScore(Number(e.target.value))}
                    className="mt-1 rounded-xl border border-zinc-200 bg-white px-3 py-1.5 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
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
                    className="mt-1 w-40 rounded-xl border border-zinc-200 bg-white px-3 py-1.5 text-xs shadow-sm outline-none ring-sky-200 focus:ring-4"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="lg:col-span-3">
        <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900">
                เลือก URL สำหรับ Payload recon
              </h2>
              <p className="mt-1 text-xs text-zinc-600">
                ใช้ผลจาก {tool === "ffuf" ? "FFuf" : "Katana"} แล้วเลือก path
                ที่ต้องการดึง forms / params
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => runPayloadReconScan("selected")}
                disabled={payloadLoading}
                className={cn(
                  "rounded-xl px-3 py-1.5 text-xs font-semibold shadow-sm",
                  payloadLoading
                    ? "cursor-not-allowed bg-zinc-200 text-zinc-500"
                    : "bg-sky-600 text-white hover:bg-sky-700",
                )}
              >
                Scan เฉพาะที่เลือก
              </button>
              <button
                type="button"
                onClick={() => runPayloadReconScan("all")}
                disabled={payloadLoading}
                className={cn(
                  "rounded-xl px-3 py-1.5 text-xs font-semibold shadow-sm",
                  payloadLoading
                    ? "cursor-not-allowed bg-zinc-200 text-zinc-500"
                    : "bg-zinc-900 text-white hover:bg-zinc-800",
                )}
              >
                Scan ทั้งหมด
              </button>
            </div>
          </div>

          <div className="mt-4">
            {resultsLoading && (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-700">
                กำลังโหลดผลสแกน...
              </div>
            )}
            {!results && !resultsLoading && (
              <div className="rounded-xl border border-dashed border-zinc-200 bg-zinc-50 p-4 text-xs text-zinc-600">
                ยังไม่มีผลจาก tool — เลือก tool และ target ทางซ้ายก่อน
              </div>
            )}
            {filteredResults && (
              <div className="mt-3 overflow-hidden rounded-2xl border border-zinc-200">
                <div className="grid grid-cols-12 items-center bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
                  <div className="col-span-1">
                    <input
                      type="checkbox"
                      checked={allResultUrls.length > 0 && anySelectedUrl}
                      onChange={toggleSelectAllUrls}
                      aria-label="เลือกทั้งหมด"
                    />
                  </div>
                  <div className="col-span-1">Status</div>
                  <div className="col-span-2">Score</div>
                  <div className="col-span-8">URL</div>
                </div>
                <div className="divide-y divide-zinc-100">
                  {filteredResults.map((r) => (
                    <div
                      key={r.url}
                      className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
                    >
                      <div className="col-span-1">
                        <input
                          type="checkbox"
                          checked={Boolean(selectedUrls[r.url])}
                          onChange={() => toggleSelectUrl(r.url)}
                          aria-label={`เลือก ${r.url}`}
                        />
                      </div>
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
                      <div className="col-span-8">
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

          <div className="mt-6 space-y-3">
            {payloadError && (
              <div className="rounded-xl border border-red-200 bg-red-50 p-3 text-xs text-red-700">
                {payloadError}
              </div>
            )}
            {payloadLoading && (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-700">
                กำลังดึงข้อมูล forms / params จาก URL ที่เลือก...
              </div>
            )}
          </div>
        </div>

        <div className="mt-6 rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-zinc-900">
            Forms &amp; URL params
          </h2>
          <p className="mt-1 text-xs text-zinc-600">
            สรุปจุดที่ยิง payload ได้จาก HTML forms และ query string (ลบ path ซ้ำให้แล้ว)
          </p>

          <div className="mt-4">
            {payloadEntries && payloadEntries.length === 0 && !payloadLoading && (
              <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-700">
                ไม่พบ forms หรือ query params จาก URLs ที่เลือก
              </div>
            )}
            {payloadEntries && payloadEntries.length > 0 && !payloadLoading && (
              <div className="space-y-3">
                {payloadEntries.map((entry, idx) => (
                  <div
                    key={`${entry.action}-${entry.method}-${idx}`}
                    className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-xs text-zinc-800"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="font-semibold text-zinc-900">
                          {entry.method} {entry.action}
                        </div>
                        <div className="mt-1 text-[11px] text-zinc-500">
                          พบจาก {entry.found_in.length} path
                        </div>
                      </div>
                    </div>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div>
                        <div className="text-[11px] font-semibold text-zinc-700">
                          Query string
                        </div>
                        {Object.keys(entry.query_string || {}).length === 0 ? (
                          <div className="mt-1 text-[11px] text-zinc-500">
                            (none)
                          </div>
                        ) : (
                          <div className="mt-1 space-y-0.5">
                            {Object.entries(entry.query_string).map(
                              ([k, v]) => (
                                <div
                                  key={k}
                                  className="flex items-center justify-between gap-2 rounded-lg bg-white px-2 py-1"
                                >
                                  <span className="font-mono text-[11px] text-zinc-700">
                                    {k}
                                  </span>
                                  <span className="font-mono text-[11px] text-zinc-900">
                                    {formatParamValue(v)}
                                  </span>
                                </div>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                      <div>
                        <div className="text-[11px] font-semibold text-zinc-700">
                          Payload (body params)
                        </div>
                        {Object.keys(entry.payload || {}).length === 0 ? (
                          <div className="mt-1 text-[11px] text-zinc-500">
                            (none)
                          </div>
                        ) : (
                          <div className="mt-1 space-y-0.5">
                            {Object.entries(entry.payload).map(([k, v]) => (
                              <div
                                key={k}
                                className="flex items-center justify-between gap-2 rounded-lg bg-white px-2 py-1"
                              >
                                <span className="font-mono text-[11px] text-zinc-700">
                                  {k}
                                </span>
                                <span className="font-mono text-[11px] text-zinc-900">
                                  {formatParamValue(v)}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    {entry.found_in.length > 0 && (
                      <div className="mt-3 text-[11px] text-zinc-600">
                        <span className="font-semibold text-zinc-700">
                          Found in:
                        </span>{" "}
                        {entry.found_in.slice(0, 3).map((u, i) => (
                          <span key={u}>
                            {i > 0 && ", "}
                            <span className="font-mono">{u}</span>
                          </span>
                        ))}
                        {entry.found_in.length > 3 && (
                          <span className="text-zinc-500">
                            {" "}
                            (+{entry.found_in.length - 3} more)
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            {!payloadEntries && !payloadLoading && (
              <div className="rounded-xl border border-dashed border-zinc-200 bg-zinc-50 p-4 text-xs text-zinc-600">
                ยังไม่ได้รัน payload recon — เลือก URL ทางด้านบนแล้วกดปุ่ม Scan
              </div>
            )}
          </div>
        </div>
      </section>
      </div>
    </>
  );
}

