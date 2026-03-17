"use client";

import KatanaOutput from "./output/KatanaOutput";
import FfufOutput from "./output/FfufOutput";
import PayloadReconOutput from "./output/PayloadReconOutput";

export type PayloadEntry = {
  found_in: string[];
  action: string;
  method: string;
  query_string: Record<string, string>;
  payload: Record<string, string>;
};

type OutputModalProps = {
  open: boolean;
  onClose: () => void;
  toolId: "katana" | "ffuf" | "payload_recon";
  title: string;
  phase: "running" | "done" | "error";
  status: string;
  logs?: string[];
  resultFile?: string | null;
  backend?: string;
  payloadEntries?: PayloadEntry[] | null;
  payloadReconId?: number | null;
};

const TOOL_STYLE: Record<string, { bg: string; accent: string; label: string }> = {
  katana: { bg: "bg-amber-50", accent: "text-amber-700", label: "Katana" },
  ffuf: { bg: "bg-sky-50", accent: "text-sky-700", label: "FFuf" },
  payload_recon: { bg: "bg-violet-50", accent: "text-violet-700", label: "Payload Recon" },
};

export default function OutputModal({
  open,
  onClose,
  toolId,
  title,
  phase,
  status,
  logs = [],
  resultFile = null,
  backend = "",
  payloadEntries = null,
  payloadReconId = null,
}: OutputModalProps) {
  if (!open) return null;

  const style = TOOL_STYLE[toolId] || { bg: "bg-zinc-50", accent: "text-zinc-700", label: title };
  const subTitle = phase === "running" ? "Log" : "Output";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-900/60 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="w-full max-w-3xl max-h-[85vh] overflow-hidden rounded-3xl border border-zinc-200/80 bg-white shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`border-b border-zinc-100 px-6 py-4 ${style.bg}`}>
          <div className="flex items-center justify-between">
            <h2 className={`text-lg font-semibold ${style.accent}`}>
              {style.label} — {subTitle}
            </h2>
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
          <p className={`mt-1 text-sm font-medium ${phase === "error" ? "text-red-600" : style.accent}`}>
            {phase === "running" ? "⏳ " : phase === "error" ? "⚠ " : "✓ "}
            {status}
          </p>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          {toolId === "katana" && <KatanaOutput phase={phase} logs={logs} resultFile={resultFile} backend={backend} />}
          {toolId === "ffuf" && <FfufOutput phase={phase} logs={logs} resultFile={resultFile} backend={backend} />}
          {toolId === "payload_recon" && <PayloadReconOutput payloadEntries={payloadEntries} payloadReconId={payloadReconId} backend={backend} />}
        </div>
      </div>
    </div>
  );
}
