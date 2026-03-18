"use client";

import { useRef } from "react";

type ToolId = "katana" | "ffuf" | "payload_recon" | "nuclei" | "whatweb" | "subfinder" | "lan" | "nmap";
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
  // WhatWeb
  whatwebAggression: 1 | 3 | 4;
  setWhatwebAggression: (v: 1 | 3 | 4) => void;
  // Subfinder
  subfinderHttpxTimeoutSec: number | "";
  setSubfinderHttpxTimeoutSec: (v: number | "") => void;
  // LAN
  lanCidr: string;
  setLanCidr: (v: string) => void;
  lanMode: "fast" | "accurate";
  setLanMode: (v: "fast" | "accurate") => void;
  lanPortsPreset: "top100" | "top1000" | "custom";
  setLanPortsPreset: (v: "top100" | "top1000" | "custom") => void;
  lanCustomPorts: string;
  setLanCustomPorts: (v: string) => void;
  // Nmap
  nmapPortPreset: "default" | "fast" | "top100" | "top1000" | "custom";
  setNmapPortPreset: (v: "default" | "fast" | "top100" | "top1000" | "custom") => void;
  nmapCustomPorts: string;
  setNmapCustomPorts: (v: string) => void;
  nmapTiming: "T3" | "T4" | "T5";
  setNmapTiming: (v: "T3" | "T4" | "T5") => void;
  nmapNoPing: boolean;
  setNmapNoPing: (v: boolean) => void;
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
  whatwebAggression,
  setWhatwebAggression,
  subfinderHttpxTimeoutSec,
  setSubfinderHttpxTimeoutSec,
  lanCidr,
  setLanCidr,
  lanMode,
  setLanMode,
  lanPortsPreset,
  setLanPortsPreset,
  lanCustomPorts,
  setLanCustomPorts,
  nmapPortPreset,
  setNmapPortPreset,
  nmapCustomPorts,
  setNmapCustomPorts,
  nmapTiming,
  setNmapTiming,
  nmapNoPing,
  setNmapNoPing,
}: ConfigModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);

  if (!open || !tool) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === overlayRef.current) onClose();
  };

  const title2 =
    tool === "katana"
      ? "Katana"
      : tool === "ffuf"
        ? "FFuf"
        : tool === "nuclei"
          ? "Nuclei"
          : tool === "whatweb"
            ? "WhatWeb"
            : tool === "subfinder"
              ? "Subfinder"
              : tool === "lan"
                ? "LAN Scanner"
                : tool === "nmap"
                  ? "Nmap"
                  : "Payload Recon";
  const subtitle =
    tool === "katana"
      ? "ตั้งค่า flags สำหรับ crawl"
      : tool === "ffuf"
        ? "ตั้งค่า wordlist และ options"
        : tool === "nuclei"
          ? "สแกนด้วย templates และเก็บผลแบบ filtered JSON"
          : tool === "whatweb"
            ? "Fingerprint และสรุป plugins แบบ dynamic JSON"
          : tool === "subfinder"
            ? "หา subdomains ด้วย subfinder และเช็ค alive ด้วย httpx (เก็บเฉพาะ status 200)"
          : tool === "lan"
            ? "สแกน LAN จาก CIDR แล้วสรุป host + ports"
            : tool === "nmap"
              ? "ดึง host จาก URL แล้วสแกน port, service version, OS (เพิ่ม option ได้)"
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

          {tool === "whatweb" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4 space-y-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-zinc-200 text-zinc-800 text-xs font-bold">W</span>
                WhatWeb
              </h3>

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-zinc-600">Aggression (-a)</label>
                  <select
                    value={whatwebAggression}
                    onChange={(e) => setWhatwebAggression(Number(e.target.value) as 1 | 3 | 4)}
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-800"
                  >
                    <option value={1}>1 (Stealthy)</option>
                    <option value={3}>3 (Aggressive)</option>
                    <option value={4}>4 (Heavy)</option>
                  </select>
                  <p className="mt-2 text-[11px] text-zinc-500">WhatWeb 0.6.3 รองรับแค่ 1, 3, 4</p>
                </div>
                <div className="sm:col-span-1">
                  <p className="text-xs font-semibold text-zinc-600">Plugins</p>
                  <p className="mt-1 text-[11px] text-zinc-500">
                    ค่า default จะให้ WhatWeb ตรวจทั้งหมดและ output จะถูกบันทึกเป็น JSON โดย UI จะ loop แสดง key ต่างๆ แบบ dynamic ไม่ตัดทิ้ง
                  </p>
                </div>
              </div>
            </section>
          )}

          {tool === "subfinder" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4 space-y-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-zinc-200 text-zinc-800 text-xs font-bold">S</span>
                Subfinder
              </h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-zinc-600">httpx timeout (seconds)</label>
                  <input
                    type="number"
                    min={1}
                    value={subfinderHttpxTimeoutSec}
                    onChange={(e) => setSubfinderHttpxTimeoutSec(e.target.value === "" ? "" : Number(e.target.value))}
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-800"
                    placeholder="5"
                  />
                  <p className="mt-2 text-[11px] text-zinc-500">
                    จะใช้ scheme ตาม URL ที่ใส่มา (http/https) แล้วเก็บเฉพาะ subdomain ที่ตอบ status 200
                  </p>
                </div>
              </div>
            </section>
          )}

          {tool === "lan" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4 space-y-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-emerald-100 text-emerald-700 text-xs font-bold">
                  L
                </span>
                LAN Scanner
              </h3>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="sm:col-span-1">
                  <label className="block text-xs font-semibold text-zinc-600">CIDR</label>
                  <input
                    type="text"
                    value={lanCidr}
                    onChange={(e) => setLanCidr(e.target.value)}
                    placeholder="192.168.1.0/24"
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-mono text-zinc-900"
                  />
                  <p className="mt-1 text-[11px] text-zinc-500">
                    ใช้รูปแบบ CIDR เช่น <span className="font-mono">192.168.1.0/24</span>
                  </p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-zinc-600">Mode</label>
                  <div className="mt-1 flex gap-3 text-xs">
                    <label className="flex items-center gap-2 cursor-pointer text-zinc-700">
                      <input
                        type="radio"
                        checked={lanMode === "fast"}
                        onChange={() => setLanMode("fast")}
                        className="text-emerald-600"
                      />
                      fast
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-zinc-700">
                      <input
                        type="radio"
                        checked={lanMode === "accurate"}
                        onChange={() => setLanMode("accurate")}
                        className="text-emerald-600"
                      />
                      accurate
                    </label>
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-500">
                    fast = ไวกว่า, accurate = retry + TTL OS guess
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-semibold text-zinc-600">Ports</label>
                <div className="flex flex-wrap gap-4 text-xs">
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-700">
                    <input
                      type="radio"
                      checked={lanPortsPreset === "top100"}
                      onChange={() => setLanPortsPreset("top100")}
                      className="text-emerald-600"
                    />
                    top100
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-700">
                    <input
                      type="radio"
                      checked={lanPortsPreset === "top1000"}
                      onChange={() => setLanPortsPreset("top1000")}
                      className="text-emerald-600"
                    />
                    top1000
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-700">
                    <input
                      type="radio"
                      checked={lanPortsPreset === "custom"}
                      onChange={() => setLanPortsPreset("custom")}
                      className="text-emerald-600"
                    />
                    custom
                  </label>
                </div>
                {lanPortsPreset === "custom" && (
                  <input
                    type="text"
                    value={lanCustomPorts}
                    onChange={(e) => setLanCustomPorts(e.target.value)}
                    placeholder="22,80,443,445,3389 หรือ 20-25,80,443"
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-mono text-zinc-900"
                  />
                )}
              </div>
            </section>
          )}

          {tool === "nmap" && (
            <section className="rounded-2xl border border-zinc-100 bg-zinc-50/50 p-4 space-y-4">
              <h3 className="text-sm font-semibold text-zinc-800 flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-teal-100 text-teal-700 text-xs font-bold">N</span>
                Nmap
              </h3>
              <p className="text-xs text-zinc-600">
                ใช้ URL ด้านบนดึง host แล้วรัน <span className="font-mono">-sV -O --osscan-guess</span> (port, service/version, OS)
              </p>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-zinc-600">Port</label>
                  <select
                    value={nmapPortPreset}
                    onChange={(e) => setNmapPortPreset(e.target.value as "default" | "fast" | "top100" | "top1000" | "custom")}
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-800"
                  >
                    <option value="default">Default (nmap default ports)</option>
                    <option value="fast">Fast (-F fewer ports)</option>
                    <option value="top100">Top 100 (--top-ports 100)</option>
                    <option value="top1000">Top 1000 (--top-ports 1000)</option>
                    <option value="custom">Custom (-p ...)</option>
                  </select>
                  {nmapPortPreset === "custom" && (
                    <input
                      type="text"
                      value={nmapCustomPorts}
                      onChange={(e) => setNmapCustomPorts(e.target.value)}
                      placeholder="80,443 หรือ 1-1000"
                      className="mt-2 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-mono text-zinc-900"
                    />
                  )}
                </div>
                <div>
                  <label className="block text-xs font-semibold text-zinc-600">Timing (-T)</label>
                  <select
                    value={nmapTiming}
                    onChange={(e) => setNmapTiming(e.target.value as "T3" | "T4" | "T5")}
                    className="mt-1 w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-800"
                  >
                    <option value="T3">T3 (Normal)</option>
                    <option value="T4">T4 (Aggressive)</option>
                    <option value="T5">T5 (Insane)</option>
                  </select>
                  <p className="mt-1 text-[11px] text-zinc-500">ยิ่งสูงยิ่งเร็ว</p>
                </div>
              </div>
              <div>
                <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold text-zinc-700">
                  <input
                    type="checkbox"
                    checked={nmapNoPing}
                    onChange={(e) => setNmapNoPing(e.target.checked)}
                    className="rounded border-zinc-300 text-teal-600"
                  />
                  -Pn (Skip host discovery / treat as online)
                </label>
                <p className="mt-1 text-[11px] text-zinc-500">เหมาะกับเว็บที่ block ping</p>
              </div>
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
