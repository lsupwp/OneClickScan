import Link from "next/link";

type FfufScanRow = {
  id: number;
  target_id: number;
  result_file: string;
  wordlist_source: string | null;
  scan_at: string;
};

type ScoredUrl = {
  url: string;
  score: number;
  level?: string;
  reason?: string;
  status?: number | null;
};

async function getFfufScans(targetId: number) {
  const base = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
  const res = await fetch(`${base}/api/targets/${targetId}/ffuf`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to load ffuf scans");
  return (await res.json()) as FfufScanRow[];
}

async function getResult(resultFile: string) {
  const base = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
  const res = await fetch(
    `${base}/api/result?path=${encodeURIComponent(resultFile)}`,
    { cache: "no-store" },
  );
  if (!res.ok) throw new Error("Failed to load result file");
  return (await res.json()) as ScoredUrl[];
}

function scoreColor(score: number) {
  if (score >= 5) return "bg-red-600";
  if (score === 4) return "bg-orange-500";
  if (score === 3) return "bg-amber-400";
  if (score === 2) return "bg-sky-500";
  return "bg-zinc-400";
}

export default async function FfufScanDetailPage({
  params,
}: {
  params: Promise<{ targetId: string; scanId: string }>;
}) {
  const { targetId, scanId } = await params;
  const tid = Number(targetId);
  const sid = Number(scanId);

  const scans = await getFfufScans(tid);
  const scan = scans.find((s) => s.id === sid) || null;
  const results = scan ? await getResult(scan.result_file) : [];

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              FFuf result #{sid}
            </h1>
            <p className="mt-2 text-sm text-zinc-600">
              Target #{tid} • {scan?.scan_at || "-"} • wordlist:{" "}
              {scan?.wordlist_source || "-"}
            </p>
          </div>
          <Link
            href={`/targets/${tid}`}
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            Back
          </Link>
        </header>

        <div className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex items-end justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-zinc-900">Results</h2>
              <p className="mt-1 text-xs text-zinc-600">
                แสดง URL ที่ได้คะแนนจาก Gemini (ยิ่งมากยิ่งเสี่ยง)
              </p>
            </div>
            <div className="text-xs text-zinc-500">
              {results.length} rows •{" "}
              <span className="font-mono">{scan?.result_file || "-"}</span>
            </div>
          </div>

          <div className="mt-4 overflow-hidden rounded-2xl border border-zinc-200">
            <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
              <div className="col-span-1">Status</div>
              <div className="col-span-2">Score</div>
              <div className="col-span-9">URL</div>
            </div>
            <div className="divide-y divide-zinc-100">
              {results
                .slice()
                .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url))
                .map((r) => (
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
                          className={`inline-flex h-2.5 w-2.5 rounded-full ${scoreColor(
                            r.score,
                          )}`}
                        />
                        <span className="text-sm font-semibold text-zinc-900">
                          {r.score}
                        </span>
                        <span className="hidden text-[11px] text-zinc-500 sm:inline">
                          {r.level || ""}
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
        </div>
      </div>
    </div>
  );
}
