import Link from "next/link";

type KatanaScanRow = {
  id: number;
  target_id: number;
  result_file: string;
  flags_json: string | null;
  scan_at: string;
};

type TargetRow = {
  target_id: number;
  target_name: string;
};

async function getTargets(targetId: number) {
  const base = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
  const res = await fetch(`${base}/api/targets?q=`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load targets");
  const all = (await res.json()) as TargetRow[];
  return all.find((t) => t.target_id === targetId) || null;
}

async function getKatanaScans(targetId: number) {
  const base = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
  const res = await fetch(`${base}/api/targets/${targetId}/katana`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to load scans");
  return (await res.json()) as KatanaScanRow[];
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

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ targetId: string }>;
}) {
  const { targetId } = await params;
  const id = Number(targetId);
  const target = Number.isFinite(id) ? await getTargets(id) : null;
  const scans = Number.isFinite(id) ? await getKatanaScans(id) : [];

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
          <div className="flex gap-2">
            <Link
              href="/targets"
              className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
            >
              Back
            </Link>
            <Link
              href="/katana"
              className="rounded-lg bg-sky-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-sky-700"
            >
              New scan
            </Link>
          </div>
        </header>

        <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm">
          <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
            <div className="col-span-2">Scan</div>
            <div className="col-span-3">Scanned at</div>
            <div className="col-span-5">Flags</div>
            <div className="col-span-2">Result</div>
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
                  <div className="col-span-3 text-sm text-zinc-700">
                    {s.scan_at}
                  </div>
                  <div className="col-span-5 truncate text-sm text-zinc-600">
                    <span className="font-mono text-[12px]">
                      {formatFlags(s.flags_json) || "-"}
                    </span>
                  </div>
                  <div className="col-span-2 truncate text-sm font-medium text-sky-700">
                    Open →
                  </div>
                </Link>
              ))
            ) : (
              <div className="px-4 py-10 text-sm text-zinc-600">
                ยังไม่มีประวัติ scan
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

