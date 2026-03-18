import Link from "next/link";

type KatanaScanRow = {
  id: number;
  target_id: number;
  result_file: string;
  flags_json: string | null;
  scan_at: string;
};

type FfufScanRow = {
  id: number;
  target_id: number;
  result_file: string;
  wordlist_source: string | null;
  scan_at: string;
};

type ScanRow = {
  id: number;
  target_id?: number;
  result_file: string;
  scan_at: string;
};

type TargetRow = {
  target_id: number;
  target_name: string;
};

const BASE = () =>
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";

async function getTarget(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets?q=`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load targets");
  const all = (await res.json()) as TargetRow[];
  return all.find((t) => t.target_id === targetId) || null;
}

async function getKatanaScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/katana`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as KatanaScanRow[];
}

async function getFfufScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/ffuf`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as FfufScanRow[];
}

async function getPayloadReconScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/payload-recon`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as ScanRow[];
}

async function getNucleiScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/nuclei`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as ScanRow[];
}

async function getWhatwebScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/whatweb`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as ScanRow[];
}

async function getSubfinderScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/subfinder`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as ScanRow[];
}

async function getNmapScans(targetId: number) {
  const res = await fetch(`${BASE()}/api/targets/${targetId}/nmap`, {
    cache: "no-store",
  });
  if (!res.ok) return [];
  return (await res.json()) as ScanRow[];
}

function formatFlags(flagsJson: string | null) {
  if (!flagsJson) return null;
  try {
    const obj = JSON.parse(flagsJson) as {
      baseFlags?: string[];
      extraFlags?: string[];
    };
    const base = obj.baseFlags?.join(" ") || "";
    const extra = obj.extraFlags?.join(" ") || "";
    const combined = [base, extra].filter(Boolean).join(" ").trim();
    return combined || null;
  } catch {
    return null;
  }
}

function ScanTableKatana({
  title,
  scans,
  id,
  first,
}: {
  title: string;
  scans: KatanaScanRow[];
  id: number;
  first?: boolean;
}) {
  return (
    <>
      <h2 className={`mb-3 text-sm font-semibold text-zinc-900 ${first ? "" : "mt-8"}`}>{title}</h2>
      <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm">
        <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
          <div className="col-span-2">Scan</div>
          <div className="col-span-3">Scanned at</div>
          <div className="col-span-3">Flags</div>
          <div className="col-span-4">Result</div>
          <div className="col-span-2">Open</div>
        </div>
        <div className="divide-y divide-zinc-100">
          {scans.length ? (
            scans.map((s) => (
              <Link
                key={s.id}
                href={`/targets/${id}/katana/${s.id}`}
                className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
              >
                <div className="col-span-2 text-sm font-semibold text-zinc-900">
                  #{s.id}
                </div>
                <div className="col-span-3 text-sm text-zinc-700">{s.scan_at}</div>
                <div className="col-span-3 truncate text-sm text-zinc-600 font-mono text-[12px]">
                  {formatFlags(s.flags_json) || "-"}
                </div>
                <div className="col-span-4 truncate font-mono text-[12px] text-zinc-600">
                  {s.result_file}
                </div>
                <div className="col-span-2 text-sm font-medium text-sky-700">
                  Open →
                </div>
              </Link>
            ))
          ) : (
            <div className="px-4 py-10 text-sm text-zinc-600">
              ยังไม่มีประวัติ Katana
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function ScanTableFfuf({
  title,
  scans,
  id,
}: {
  title: string;
  scans: FfufScanRow[];
  id: number;
}) {
  return (
    <>
      <h2 className="mb-3 mt-8 text-sm font-semibold text-zinc-900">{title}</h2>
      <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm">
        <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
          <div className="col-span-2">Scan</div>
          <div className="col-span-3">Scanned at</div>
          <div className="col-span-3">Wordlist</div>
          <div className="col-span-4">Result</div>
          <div className="col-span-2">Open</div>
        </div>
        <div className="divide-y divide-zinc-100">
          {scans.length ? (
            scans.map((s) => (
              <Link
                key={s.id}
                href={`/targets/${id}/ffuf/${s.id}`}
                className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
              >
                <div className="col-span-2 text-sm font-semibold text-zinc-900">
                  #{s.id}
                </div>
                <div className="col-span-3 text-sm text-zinc-700">{s.scan_at}</div>
                <div className="col-span-3 text-sm text-zinc-600">
                  {s.wordlist_source || "-"}
                </div>
                <div className="col-span-4 truncate font-mono text-[12px] text-zinc-600">
                  {s.result_file}
                </div>
                <div className="col-span-2 text-sm font-medium text-sky-700">
                  Open →
                </div>
              </Link>
            ))
          ) : (
            <div className="px-4 py-10 text-sm text-zinc-600">
              ยังไม่มีประวัติ FFuf
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function ScanTableExternal({
  title,
  tool,
  scans,
  targetId,
}: {
  title: string;
  tool: "nuclei" | "whatweb" | "subfinder" | "payload_recon" | "nmap";
  scans: { id: number; result_file: string; scan_at: string }[];
  targetId: number;
}) {
  return (
    <>
      <h2 className="mb-3 mt-8 text-sm font-semibold text-zinc-900">{title}</h2>
      <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm">
        <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
          <div className="col-span-2">Scan</div>
          <div className="col-span-4">Scanned at</div>
          <div className="col-span-4">Result file</div>
          <div className="col-span-2">Open</div>
        </div>
        <div className="divide-y divide-zinc-100">
          {scans.length ? (
            scans.map((s) => {
              const viewUrl =
                tool === "payload_recon"
                  ? `/targets/${targetId}/view?tool=${tool}&path=${encodeURIComponent(s.result_file)}&reconId=${s.id}`
                  : `/targets/${targetId}/view?tool=${tool}&path=${encodeURIComponent(s.result_file)}`;
              return (
                <div
                  key={s.id}
                  className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
                >
                  <div className="col-span-2 text-sm font-semibold text-zinc-900">
                    #{s.id}
                  </div>
                  <div className="col-span-4 text-sm text-zinc-700">
                    {s.scan_at}
                  </div>
                  <div className="col-span-4 truncate font-mono text-[12px] text-zinc-600">
                    {s.result_file}
                  </div>
                  <div className="col-span-2">
                    <Link
                      href={viewUrl}
                      className="text-sm font-medium text-sky-700 hover:underline"
                    >
                      Open →
                    </Link>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="px-4 py-10 text-sm text-zinc-600">
              ยังไม่มีประวัติ
            </div>
          )}
        </div>
      </div>
    </>
  );
}

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ targetId: string }>;
}) {
  const { targetId } = await params;
  const id = Number(targetId);
  const target = Number.isFinite(id) ? await getTarget(id) : null;
  const [katanaScans, ffufScans, payloadScans, nucleiScans, whatwebScans, subfinderScans, nmapScans] =
    Number.isFinite(id)
      ? await Promise.all([
          getKatanaScans(id),
          getFfufScans(id),
          getPayloadReconScans(id),
          getNucleiScans(id),
          getWhatwebScans(id),
          getSubfinderScans(id),
          getNmapScans(id),
        ])
      : [[], [], [], [], [], [], []];

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              Target #{id}
            </h1>
            <p className="mt-2 max-w-3xl text-sm text-zinc-600">
              {target?.target_name || "Unknown target"}
            </p>
          </div>
          <Link
            href="/targets"
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            Back
          </Link>
        </header>

        <ScanTableKatana title="Katana" scans={katanaScans} id={id} first />
        <ScanTableFfuf title="FFuf Hidden Path" scans={ffufScans} id={id} />

        <ScanTableExternal title="Payload Recon" tool="payload_recon" scans={payloadScans} targetId={id} />
        <ScanTableExternal title="Nuclei" tool="nuclei" scans={nucleiScans} targetId={id} />
        <ScanTableExternal title="WhatWeb" tool="whatweb" scans={whatwebScans} targetId={id} />
        <ScanTableExternal title="Subfinder" tool="subfinder" scans={subfinderScans} targetId={id} />
        <ScanTableExternal title="Nmap" tool="nmap" scans={nmapScans} targetId={id} />
      </div>
    </div>
  );
}
