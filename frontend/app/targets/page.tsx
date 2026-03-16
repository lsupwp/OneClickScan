import Link from "next/link";

type TargetRow = {
  target_id: number;
  target_name: string;
};

async function getTargets(q: string) {
  const base = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8080";
  const res = await fetch(`${base}/api/targets?q=${encodeURIComponent(q)}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to load targets");
  return (await res.json()) as TargetRow[];
}

export default async function TargetsPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q = "" } = await searchParams;
  const targets = await getTargets(q);

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-5xl px-6 py-10">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              Targets
            </h1>
            <p className="mt-2 text-sm text-zinc-600">
              เลือก target เพื่อดูประวัติการสแกนและผลลัพธ์
            </p>
          </div>
          <Link
            href="/"
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            Back
          </Link>
        </header>

        <form className="mb-6">
          <label className="block text-xs font-semibold text-zinc-600">
            Search target
          </label>
          <input
            name="q"
            defaultValue={q}
            placeholder="http://113.45.171.231/"
            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm shadow-sm outline-none ring-sky-200 focus:ring-4"
          />
        </form>

        <div className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm">
          <div className="grid grid-cols-12 bg-zinc-50 px-4 py-2 text-[11px] font-semibold text-zinc-600">
            <div className="col-span-2">ID</div>
            <div className="col-span-10">Target</div>
          </div>
          <div className="divide-y divide-zinc-100">
            {targets.length ? (
              targets.map((t) => (
                <Link
                  key={t.target_id}
                  href={`/targets/${t.target_id}`}
                  className="grid grid-cols-12 gap-3 px-4 py-3 hover:bg-zinc-50"
                >
                  <div className="col-span-2 text-sm font-semibold text-zinc-900">
                    {t.target_id}
                  </div>
                  <div className="col-span-10 truncate text-sm font-medium text-sky-700">
                    {t.target_name}
                  </div>
                </Link>
              ))
            ) : (
              <div className="px-4 py-10 text-sm text-zinc-600">
                ไม่พบ target
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

