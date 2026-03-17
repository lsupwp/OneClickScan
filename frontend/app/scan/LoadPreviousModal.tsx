"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type ToolId = "katana" | "ffuf" | "payload_recon";

type TargetRow = { target_id: number; target_name: string };
type KatanaScanRow = { id: number; target_id: number; result_file: string; flags_json?: string | null; scan_at: string };
type FfufScanRow = { id: number; target_id: number; result_file: string; wordlist_source?: string | null; scan_at: string };
type PayloadReconScanRow = { id: number; target_id: number; result_file: string; scan_at: string };

type LoadPreviousSelection = {
  katana?: KatanaScanRow | null;
  ffuf?: FfufScanRow | null;
  payload_recon?: PayloadReconScanRow | null;
};

export default function LoadPreviousModal({
  open,
  onClose,
  backend,
  targetUrl,
  onApply,
}: {
  open: boolean;
  onClose: () => void;
  backend: string;
  targetUrl: string;
  onApply: (sel: LoadPreviousSelection) => void;
}) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState<TargetRow | null>(null);
  const [katanaScans, setKatanaScans] = useState<KatanaScanRow[]>([]);
  const [ffufScans, setFfufScans] = useState<FfufScanRow[]>([]);
  const [payloadScans, setPayloadScans] = useState<PayloadReconScanRow[]>([]);
  const [pick, setPick] = useState<LoadPreviousSelection>({ katana: null, ffuf: null, payload_recon: null });

  const normalizedUrl = useMemo(() => normalizeUrl(targetUrl), [targetUrl]);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setTarget(null);
    setKatanaScans([]);
    setFfufScans([]);
    setPayloadScans([]);
    setPick({ katana: null, ffuf: null, payload_recon: null });

    const url = normalizedUrl;
    if (!url) {
      setError("กรุณาใส่ URL ก่อน");
      return;
    }

    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const tRes = await fetch(`${backend}/api/targets?q=${encodeURIComponent(url)}&limit=50`, { cache: "no-store" });
        const tData = (await tRes.json()) as TargetRow[];
        const exact = (tData || []).find((t) => normalizeUrl(t.target_name) === url) || null;
        if (cancelled) return;
        if (!exact) {
          setTarget(null);
          setLoading(false);
          return;
        }
        setTarget(exact);

        const [kRes, fRes, pRes] = await Promise.all([
          fetch(`${backend}/api/targets/${exact.target_id}/katana`, { cache: "no-store" }),
          fetch(`${backend}/api/targets/${exact.target_id}/ffuf`, { cache: "no-store" }),
          fetch(`${backend}/api/targets/${exact.target_id}/payload-recon`, { cache: "no-store" }),
        ]);
        const kData = (await kRes.json()) as KatanaScanRow[];
        const fData = (await fRes.json()) as FfufScanRow[];
        const pData = (await pRes.json()) as PayloadReconScanRow[];
        if (cancelled) return;
        setKatanaScans(Array.isArray(kData) ? kData.slice(0, 10) : []);
        setFfufScans(Array.isArray(fData) ? fData.slice(0, 10) : []);
        setPayloadScans(Array.isArray(pData) ? pData.slice(0, 10) : []);
        setLoading(false);
      } catch (e) {
        if (!cancelled) {
          setLoading(false);
          setError((e as Error).message || "โหลดข้อมูลเดิมไม่สำเร็จ");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, backend, normalizedUrl]);

  if (!open) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === overlayRef.current) onClose();
  };

  const hasAny = katanaScans.length > 0 || ffufScans.length > 0 || payloadScans.length > 0;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-900/60 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      onClick={handleOverlayClick}
    >
      <div
        className="w-full max-w-3xl max-h-[90vh] overflow-hidden rounded-3xl border border-zinc-200/80 bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-zinc-100 bg-gradient-to-r from-slate-50 to-zinc-50 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-zinc-900">โหลดข้อมูลเดิม</h2>
              <p className="mt-0.5 text-sm text-zinc-500">เลือกผลสแกนล่าสุดมาใช้แทนการรันใหม่</p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="rounded-full p-2 text-zinc-500 hover:bg-white/80 hover:text-zinc-700 transition"
              aria-label="ปิด"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <p className="mt-2 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
            Target: <span className="font-mono normal-case text-zinc-700">{normalizedUrl || "—"}</span>
          </p>
        </div>

        <div className="overflow-y-auto max-h-[calc(90vh-160px)] px-6 py-5 space-y-6">
          {loading && <p className="text-sm text-zinc-500">กำลังโหลด…</p>}
          {error && <p className="text-sm text-red-600">{error}</p>}

          {!loading && !error && !target && (
            <div className="rounded-2xl border border-zinc-200 bg-zinc-50/50 p-5">
              <p className="text-sm font-medium text-zinc-700">ไม่พบข้อมูลเดิมของ URL นี้</p>
              <p className="mt-1 text-sm text-zinc-500">ถ้าเคยสแกนแล้ว ลองใส่ URL ให้ตรงกับที่เคยใช้ (รวม http/https และ / ท้าย URL)</p>
            </div>
          )}

          {!loading && !error && target && (
            <>
              <section className="rounded-2xl border border-amber-100 bg-amber-50/40 p-4">
                <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                  <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-amber-100 text-amber-700 text-xs font-bold">K</span>
                  Katana
                </h3>
                {katanaScans.length === 0 ? (
                  <p className="mt-2 text-sm text-zinc-500">ยังไม่มีประวัติ Katana</p>
                ) : (
                  <div className="mt-3 space-y-3">
                    <div className="flex items-center justify-between gap-3 rounded-xl border border-amber-100 bg-white p-3">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-zinc-800">
                          {pick.katana ? `Scan #${pick.katana.id}` : "ยังไม่ได้เลือก"}
                        </p>
                        <p className="mt-0.5 text-xs text-zinc-500 truncate">
                          {pick.katana ? `${new Date(pick.katana.scan_at).toLocaleString()} • ${pick.katana.result_file}` : "—"}
                        </p>
                      </div>
                      <select
                        value={pick.katana?.id ?? ""}
                        onChange={(e) => {
                          const id = Number(e.target.value);
                          const row = katanaScans.find((x) => x.id === id) || null;
                          setPick((p) => ({ ...p, katana: row }));
                        }}
                        className="shrink-0 rounded-lg border border-amber-200 bg-white px-3 py-2 text-xs font-semibold text-amber-800"
                      >
                        <option value="">เลือกสแกน…</option>
                        {katanaScans.map((s) => (
                          <option key={s.id} value={s.id}>
                            #{s.id} • {new Date(s.scan_at).toLocaleString()}
                          </option>
                        ))}
                      </select>
                    </div>
                    <details className="rounded-xl border border-amber-100 bg-white/60">
                      <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-amber-800 hover:bg-amber-50/40">
                        ดูรายการทั้งหมด ({katanaScans.length})
                      </summary>
                      <div className="border-t border-amber-100 p-2 max-h-48 overflow-auto">
                        {katanaScans.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => setPick((p) => ({ ...p, katana: s }))}
                            className={`w-full text-left rounded-lg px-3 py-2 text-xs transition ${
                              pick.katana?.id === s.id ? "bg-amber-50 text-amber-900" : "hover:bg-amber-50/40 text-zinc-700"
                            }`}
                          >
                            <span className="font-semibold">#{s.id}</span>{" "}
                            <span className="text-zinc-500">{new Date(s.scan_at).toLocaleString()}</span>
                            <span className="block font-mono text-[11px] text-zinc-500 break-all">{s.result_file}</span>
                          </button>
                        ))}
                      </div>
                    </details>
                  </div>
                )}
              </section>

              <section className="rounded-2xl border border-sky-100 bg-sky-50/40 p-4">
                <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                  <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-sky-100 text-sky-700 text-xs font-bold">F</span>
                  FFuf
                </h3>
                {ffufScans.length === 0 ? (
                  <p className="mt-2 text-sm text-zinc-500">ยังไม่มีประวัติ FFuf</p>
                ) : (
                  <div className="mt-3 space-y-3">
                    <div className="flex items-center justify-between gap-3 rounded-xl border border-sky-100 bg-white p-3">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-zinc-800">
                          {pick.ffuf ? `Scan #${pick.ffuf.id}` : "ยังไม่ได้เลือก"}
                        </p>
                        <p className="mt-0.5 text-xs text-zinc-500 truncate">
                          {pick.ffuf ? `${new Date(pick.ffuf.scan_at).toLocaleString()} • ${pick.ffuf.result_file}` : "—"}
                        </p>
                      </div>
                      <select
                        value={pick.ffuf?.id ?? ""}
                        onChange={(e) => {
                          const id = Number(e.target.value);
                          const row = ffufScans.find((x) => x.id === id) || null;
                          setPick((p) => ({ ...p, ffuf: row }));
                        }}
                        className="shrink-0 rounded-lg border border-sky-200 bg-white px-3 py-2 text-xs font-semibold text-sky-800"
                      >
                        <option value="">เลือกสแกน…</option>
                        {ffufScans.map((s) => (
                          <option key={s.id} value={s.id}>
                            #{s.id} • {new Date(s.scan_at).toLocaleString()}
                          </option>
                        ))}
                      </select>
                    </div>
                    <details className="rounded-xl border border-sky-100 bg-white/60">
                      <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-sky-800 hover:bg-sky-50/40">
                        ดูรายการทั้งหมด ({ffufScans.length})
                      </summary>
                      <div className="border-t border-sky-100 p-2 max-h-48 overflow-auto">
                        {ffufScans.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => setPick((p) => ({ ...p, ffuf: s }))}
                            className={`w-full text-left rounded-lg px-3 py-2 text-xs transition ${
                              pick.ffuf?.id === s.id ? "bg-sky-50 text-sky-900" : "hover:bg-sky-50/40 text-zinc-700"
                            }`}
                          >
                            <span className="font-semibold">#{s.id}</span>{" "}
                            <span className="text-zinc-500">{new Date(s.scan_at).toLocaleString()}</span>
                            <span className="block font-mono text-[11px] text-zinc-500 break-all">{s.result_file}</span>
                          </button>
                        ))}
                      </div>
                    </details>
                  </div>
                )}
              </section>

              <section className="rounded-2xl border border-violet-100 bg-violet-50/40 p-4">
                <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                  <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-violet-100 text-violet-700 text-xs font-bold">P</span>
                  Payload Recon
                </h3>
                {payloadScans.length === 0 ? (
                  <p className="mt-2 text-sm text-zinc-500">ยังไม่มีประวัติ Payload Recon</p>
                ) : (
                  <div className="mt-3 space-y-3">
                    <div className="flex items-center justify-between gap-3 rounded-xl border border-violet-100 bg-white p-3">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-zinc-800">
                          {pick.payload_recon ? `Scan #${pick.payload_recon.id}` : "ยังไม่ได้เลือก"}
                        </p>
                        <p className="mt-0.5 text-xs text-zinc-500 truncate">
                          {pick.payload_recon ? `${new Date(pick.payload_recon.scan_at).toLocaleString()} • ${pick.payload_recon.result_file}` : "—"}
                        </p>
                      </div>
                      <select
                        value={pick.payload_recon?.id ?? ""}
                        onChange={(e) => {
                          const id = Number(e.target.value);
                          const row = payloadScans.find((x) => x.id === id) || null;
                          setPick((p) => ({ ...p, payload_recon: row }));
                        }}
                        className="shrink-0 rounded-lg border border-violet-200 bg-white px-3 py-2 text-xs font-semibold text-violet-800"
                      >
                        <option value="">เลือกสแกน…</option>
                        {payloadScans.map((s) => (
                          <option key={s.id} value={s.id}>
                            #{s.id} • {new Date(s.scan_at).toLocaleString()}
                          </option>
                        ))}
                      </select>
                    </div>
                    <details className="rounded-xl border border-violet-100 bg-white/60">
                      <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-violet-800 hover:bg-violet-50/40">
                        ดูรายการทั้งหมด ({payloadScans.length})
                      </summary>
                      <div className="border-t border-violet-100 p-2 max-h-48 overflow-auto">
                        {payloadScans.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => setPick((p) => ({ ...p, payload_recon: s }))}
                            className={`w-full text-left rounded-lg px-3 py-2 text-xs transition ${
                              pick.payload_recon?.id === s.id ? "bg-violet-50 text-violet-900" : "hover:bg-violet-50/40 text-zinc-700"
                            }`}
                          >
                            <span className="font-semibold">#{s.id}</span>{" "}
                            <span className="text-zinc-500">{new Date(s.scan_at).toLocaleString()}</span>
                            <span className="block font-mono text-[11px] text-zinc-500 break-all">{s.result_file}</span>
                          </button>
                        ))}
                      </div>
                    </details>
                  </div>
                )}
              </section>

              {!hasAny && (
                <p className="text-sm text-zinc-500">ยังไม่มีผลสแกนให้เลือก</p>
              )}
            </>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-zinc-100 bg-zinc-50/30 px-6 py-4">
          <p className="text-xs text-zinc-500">
            Tip: เลือกเฉพาะ tool ที่อยาก reuse แล้วกด “นำมาใช้”
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
            >
              ยกเลิก
            </button>
            <button
              type="button"
              disabled={!pick.katana && !pick.ffuf && !pick.payload_recon}
              onClick={() => {
                onApply(pick);
                onClose();
              }}
              className={`rounded-xl px-5 py-2.5 text-sm font-semibold shadow-lg transition ${
                !pick.katana && !pick.ffuf && !pick.payload_recon
                  ? "cursor-not-allowed bg-zinc-300 text-zinc-500"
                  : "bg-gradient-to-r from-amber-500 to-amber-600 text-white hover:from-amber-600 hover:to-amber-700"
              }`}
            >
              นำมาใช้
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function normalizeUrl(raw: string): string {
  const v = (raw || "").trim();
  if (!v) return "";
  try {
    const u = new URL(v);
    u.hash = "";
    // keep query as-is (some targets may include it)
    const s = u.toString();
    return s.endsWith("/") ? s : s + "/";
  } catch {
    return v.endsWith("/") ? v : v + "/";
  }
}

