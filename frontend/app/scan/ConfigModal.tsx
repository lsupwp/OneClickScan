"use client";

import { useRef } from "react";

type ToolId = "katana" | "ffuf" | "payload_recon" | "nuclei";
type KatanaFlagDef = {
  name: string;
  label: string;
  type: "string" | "number" | "boolean";
  default?: unknown;
  multiple?: boolean;
};
type KatanaFlagsMeta = { defaultFlags?: string[]; flags?: KatanaFlagDef[] };

type ConfigModalProps = {
  open: boolean;
  tool: ToolId | null;
  onClose: () => void;
  // Katana
  katanaFlagsMeta: KatanaFlagsMeta | null;
  katanaEnabled: Record<string, boolean>;
  katanaValues: Record<string, unknown>;
  setKatanaEnabled: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  setKatanaValues: React.Dispatch<React.SetStateAction<Record<string, unknown>>>;
  // FFuf
  ffufWordlistMode: "default" | "upload";
  setFfufWordlistMode: (v: "default" | "upload") => void;
  ffufUploadedFileId: string | null;
  ffufFileInputRef: React.RefObject<HTMLInputElement | null>;
  onFfufFileSelect: (e: React.ChangeEvent<HTMLInputElement>) => void;
  ffufMc: string;
  setFfufMc: (v: string) => void;
  ffufFc: string;
  setFfufFc: (v: string) => void;
  ffufThreads: number | "";
  setFfufThreads: (v: number | "") => void;
  ffufRate: number | "";
  setFfufRate: (v: number | "") => void;
  ffufExtensions: string;
  setFfufExtensions: (v: string) => void;
  ffufFollowRedirects: boolean;
  setFfufFollowRedirects: (v: boolean) => void;
  ffufAutoCalibrate: boolean;
  setFfufAutoCalibrate: (v: boolean) => void;
};

export default function ConfigModal({
  open,
  tool,
  onClose,
  katanaFlagsMeta,
  katanaEnabled,
  katanaValues,
  setKatanaEnabled,
  setKatanaValues,
  ffufWordlistMode,
  setFfufWordlistMode,
  ffufUploadedFileId,
  ffufFileInputRef,
  onFfufFileSelect,
  ffufMc,
  setFfufMc,
  ffufFc,
  setFfufFc,
  ffufThreads,
  setFfufThreads,
  ffufRate,
  setFfufRate,
  ffufExtensions,
  setFfufExtensions,
  ffufFollowRedirects,
  setFfufFollowRedirects,
  ffufAutoCalibrate,
  setFfufAutoCalibrate,
}: ConfigModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);

  if (!open || !tool) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === overlayRef.current) onClose();
  };

  const title = tool === "katana" ? "Katana" : tool === "ffuf" ? "FFuf" : "Payload Recon";
  const title2 = tool === "katana" ? "Katana" : tool === "ffuf" ? "FFuf" : tool === "nuclei" ? "Nuclei" : "Payload Recon";
  const subtitle =
    tool === "katana"
      ? "ตั้งค่า flags สำหรับ crawl"
      : tool === "ffuf"
        ? "ตั้งค่า wordlist และ options"
        : tool === "nuclei"
          ? "สแกนด้วย templates และเก็บผลแบบ filtered JSON"
          : "รันหลัง Katana/FFuf เสร็จ";

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-900/60 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      onClick={handleOverlayClick}
    >
      <div
        className="w-full max-w-2xl max-h-[90vh] overflow-hidden rounded-3xl border border-zinc-200/80 bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-zinc-100 bg-gradient-to-r from-slate-50 to-zinc-50 px-6 py-4">
          <h2 className="text-lg font-semibold text-zinc-900">ตั้งค่า {title2}</h2>
          <p className="mt-0.5 text-sm text-zinc-500">{subtitle}</p>
        </div>

        <div className="overflow-y-auto max-h-[calc(90vh-140px)] px-6 py-5">
          {tool === "katana" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-amber-100 text-amber-700 text-xs font-bold">K</span>
                Katana
              </h3>
              <p className="mt-1 text-xs text-zinc-500">Default: {(katanaFlagsMeta?.defaultFlags || []).join(" ")}</p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                {(katanaFlagsMeta?.flags || [])
                  .filter((f) => f.name !== "-u")
                  .slice(0, 8)
                  .map((f) => (
                    <div key={f.name} className="rounded-xl border border-zinc-200/80 bg-white p-3">
                      <label className="flex items-center gap-2 text-xs font-medium text-zinc-700">
                        <input
                          type="checkbox"
                          checked={!!katanaEnabled[f.name]}
                          onChange={(e) => setKatanaEnabled((prev) => ({ ...prev, [f.name]: e.target.checked }))}
                          className="rounded border-zinc-300 text-amber-600 focus:ring-amber-500"
                        />
                        <span className="font-mono">{f.name}</span> {f.label}
                      </label>
                      {f.type !== "boolean" && katanaEnabled[f.name] && (
                        <input
                          type={f.type === "number" ? "number" : "text"}
                          value={String(katanaValues[f.name] ?? "")}
                          onChange={(e) =>
                            setKatanaValues((prev) => ({
                              ...prev,
                              [f.name]: f.type === "number" ? Number(e.target.value) : e.target.value,
                            }))
                          }
                          className="mt-2 w-full rounded-lg border border-zinc-200 px-2.5 py-1.5 text-xs focus:border-amber-400 focus:ring-1 focus:ring-amber-400"
                        />
                      )}
                    </div>
                  ))}
              </div>
            </section>
          )}

          {tool === "ffuf" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-sky-100 text-sky-700 text-xs font-bold">F</span>
                FFuf
              </h3>
              <div className="mt-4 space-y-4">
                <div className="flex flex-wrap gap-4">
                  <label className="flex items-center gap-2 text-sm text-zinc-700 cursor-pointer">
                    <input type="radio" checked={ffufWordlistMode === "default"} onChange={() => setFfufWordlistMode("default")} className="text-sky-600" />
                    Default (SecLists)
                  </label>
                  <label className="flex items-center gap-2 text-sm text-zinc-700 cursor-pointer">
                    <input type="radio" checked={ffufWordlistMode === "upload"} onChange={() => setFfufWordlistMode("upload")} className="text-sky-600" />
                    อัปโหลด .txt
                  </label>
                  {ffufWordlistMode === "upload" && (
                    <>
                      <input ref={ffufFileInputRef} type="file" accept=".txt" className="hidden" onChange={onFfufFileSelect} />
                      <button
                        type="button"
                        onClick={() => ffufFileInputRef.current?.click()}
                        className="rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50"
                      >
                        เลือกไฟล์
                      </button>
                      {ffufUploadedFileId && <span className="text-xs text-emerald-600 font-medium">อัปโหลดแล้ว</span>}
                    </>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <label className="block text-xs font-medium text-zinc-600">-mc</label>
                    <input value={ffufMc} onChange={(e) => setFfufMc(e.target.value)} placeholder="200,301" className="mt-1 w-full rounded-lg border border-zinc-200 px-2.5 py-1.5 text-xs" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-600">-fc</label>
                    <input value={ffufFc} onChange={(e) => setFfufFc(e.target.value)} placeholder="404" className="mt-1 w-full rounded-lg border border-zinc-200 px-2.5 py-1.5 text-xs" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-600">-t</label>
                    <input type="number" value={ffufThreads} onChange={(e) => setFfufThreads(e.target.value === "" ? "" : Number(e.target.value))} placeholder="40" className="mt-1 w-full rounded-lg border border-zinc-200 px-2.5 py-1.5 text-xs" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-600">-e</label>
                    <input value={ffufExtensions} onChange={(e) => setFfufExtensions(e.target.value)} placeholder="php,html" className="mt-1 w-full rounded-lg border border-zinc-200 px-2.5 py-1.5 text-xs" />
                  </div>
                </div>
                <div className="flex flex-wrap gap-4 text-xs">
                  <label className="flex items-center gap-2 text-zinc-700 cursor-pointer">
                    <input type="checkbox" checked={ffufFollowRedirects} onChange={(e) => setFfufFollowRedirects(e.target.checked)} className="rounded text-sky-600" />
                    -r follow redirects
                  </label>
                  <label className="flex items-center gap-2 text-zinc-700 cursor-pointer">
                    <input type="checkbox" checked={ffufAutoCalibrate} onChange={(e) => setFfufAutoCalibrate(e.target.checked)} className="rounded text-sky-600" />
                    -ac auto-calibrate
                  </label>
                </div>
              </div>
            </section>
          )}

          {tool === "payload_recon" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-violet-100 text-violet-700 text-xs font-bold">P</span>
                Payload Recon
              </h3>
              <p className="mt-2 text-xs text-zinc-600">จะรันอัตโนมัติหลัง Katana / FFuf เสร็จ โดยใช้ผลจากรอบนี้</p>
            </section>
          )}

          {tool === "nuclei" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-zinc-200 text-zinc-800 text-xs font-bold">N</span>
                Nuclei
              </h3>
              <p className="mt-2 text-xs text-zinc-600">
                รัน nuclei ใน container แล้วแปลง output JSONL ให้เหลือ fields สำคัญ:{" "}
                <span className="font-mono">name,severity,matchedAt,templateId,description,cve</span>
              </p>
            </section>
          )}
        </div>

        <div className="flex justify-end border-t border-zinc-100 bg-zinc-50/30 px-6 py-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-zinc-200 bg-white px-5 py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
          >
            ปิด
          </button>
        </div>
      </div>
    </div>
  );
}
