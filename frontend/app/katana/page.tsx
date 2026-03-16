import KatanaClient from "./ui/KatanaClient";
import Link from "next/link";

export default function KatanaPage() {
  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-6xl px-6 py-10">
        <header className="mb-8 flex items-start justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              Katana Scan
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-600">
              ใส่ URL แล้วเริ่ม crawl ด้วย Katana ระบบจะกรองเฉพาะ status 200
              และส่งให้ Gemini ให้คะแนนความเสี่ยง 1–5
            </p>
          </div>
          <Link
            href="/"
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            Back
          </Link>
        </header>

        <KatanaClient />
      </div>
    </div>
  );
}

