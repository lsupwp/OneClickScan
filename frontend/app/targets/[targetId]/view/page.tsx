"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useMemo, useEffect, useState, Suspense } from "react";
import NucleiOutput from "@/app/scan/output/NucleiOutput";
import WhatWebOutput from "@/app/scan/output/WhatWebOutput";
import SubfinderOutput from "@/app/scan/output/SubfinderOutput";
import PayloadReconOutput from "@/app/scan/output/PayloadReconOutput";
import NmapOutput from "@/app/scan/output/NmapOutput";
import type { PayloadEntry } from "@/app/scan/OutputModal";

const BACKEND = () =>
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";

const TOOL_LABEL: Record<string, string> = {
  nuclei: "Nuclei",
  whatweb: "WhatWeb",
  subfinder: "Subfinder",
  payload_recon: "Payload Recon",
  nmap: "Nmap",
};

function ViewContent({
  targetId,
  tool,
  path,
  reconId,
}: {
  targetId: string;
  tool: string | null;
  path: string | null;
  reconId: string | null;
}) {
  const backend = useMemo(() => BACKEND(), []);
  const [payloadEntries, setPayloadEntries] = useState<PayloadEntry[] | null>(null);
  const [payloadError, setPayloadError] = useState<string | null>(null);

  useEffect(() => {
    if (tool !== "payload_recon" || !path || !backend) return;
    let cancelled = false;
    setPayloadError(null);
    fetch(`${backend}/api/result?path=${encodeURIComponent(path)}`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("โหลดผลไม่สำเร็จ");
        return r.json();
      })
      .then((data: unknown) => {
        if (cancelled) return;
        const arr = Array.isArray(data) ? data : [];
        setPayloadEntries(arr as PayloadEntry[]);
      })
      .catch((e) => {
        if (!cancelled) setPayloadError((e as Error).message || "โหลดผลไม่สำเร็จ");
      });
    return () => {
      cancelled = true;
    };
  }, [tool, path, backend]);

  if (!tool || !path) {
    return (
      <div className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
        <p className="text-sm text-red-600">ไม่มี tool หรือ path</p>
        <Link href={`/targets/${targetId}`} className="mt-4 inline-block text-sm font-medium text-sky-700 hover:underline">
          ← กลับไป Target
        </Link>
      </div>
    );
  }

  if (!["nuclei", "whatweb", "subfinder", "payload_recon", "nmap"].includes(tool)) {
    return (
      <div className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
        <p className="text-sm text-red-600">เครื่องมือไม่รองรับ: {tool}</p>
        <Link href={`/targets/${targetId}`} className="mt-4 inline-block text-sm font-medium text-sky-700 hover:underline">
          ← กลับไป Target
        </Link>
      </div>
    );
  }

  const label = TOOL_LABEL[tool] || tool;

  if (tool === "payload_recon") {
    if (payloadError) {
      return (
        <div className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
          <p className="text-sm text-red-600">{payloadError}</p>
          <Link href={`/targets/${targetId}`} className="mt-4 inline-block text-sm font-medium text-sky-700 hover:underline">
            ← กลับไป Target
          </Link>
        </div>
      );
    }
    return (
      <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
        <PayloadReconOutput
          payloadEntries={payloadEntries ?? null}
          payloadReconId={reconId ? Number(reconId) : null}
          backend={backend}
        />
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm">
      <p className="mb-4 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
        {label} — ผลลัพธ์
      </p>
      {tool === "nuclei" && (
        <NucleiOutput phase="done" logs={[]} resultFile={path} backend={backend} />
      )}
      {tool === "whatweb" && (
        <WhatWebOutput phase="done" logs={[]} resultFile={path} backend={backend} />
      )}
      {tool === "subfinder" && (
        <SubfinderOutput phase="done" logs={[]} resultFile={path} backend={backend} />
      )}
      {tool === "nmap" && (
        <NmapOutput phase="done" logs={[]} resultFile={path} backend={backend} />
      )}
    </div>
  );
}

function ViewPageInner({ targetId }: { targetId: string }) {
  const searchParams = useSearchParams();
  const tool = searchParams.get("tool");
  const path = searchParams.get("path");
  const reconId = searchParams.get("reconId");

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              {TOOL_LABEL[tool || ""] || tool || "Result"}
            </h1>
            <p className="mt-2 text-sm text-zinc-600">
              Target #{targetId}
            </p>
          </div>
          <Link
            href={`/targets/${targetId}`}
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            Back
          </Link>
        </header>

        <Suspense fallback={<p className="text-sm text-zinc-500">กำลังโหลด…</p>}>
          <ViewContent targetId={targetId} tool={tool} path={path} reconId={reconId} />
        </Suspense>
      </div>
    </div>
  );
}

export default function TargetViewPage() {
  const params = useParams();
  const targetId = typeof params?.targetId === "string" ? params.targetId : "";

  if (!targetId) return null;
  return (
    <Suspense fallback={<div className="min-h-screen bg-zinc-50" />}>
      <ViewPageInner targetId={targetId} />
    </Suspense>
  );
}
