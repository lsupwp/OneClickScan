import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900">
      <div className="mx-auto w-full max-w-5xl px-6 py-12">
        <header className="mb-10">
          <p className="text-sm font-semibold text-zinc-500">oneclickscan</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">
            Minimal scanner UI
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-600">
            เลือก tool แล้วสั่ง scan แบบ realtime ผ่าน WebSocket
          </p>
        </header>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <Link
            href="/katana"
            className="group rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm hover:border-sky-200 hover:shadow"
          >
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-semibold tracking-tight">
                  Katana Scan
                </h2>
                <p className="mt-2 text-sm text-zinc-600">
                  Crawl path แล้วให้ Gemini ให้คะแนนความเสี่ยง 1–5
                </p>
              </div>
              <span className="rounded-full bg-sky-50 px-3 py-1 text-xs font-semibold text-sky-700">
                Ready
              </span>
            </div>
            <div className="mt-5 text-sm font-semibold text-sky-700 group-hover:underline">
              Open →
            </div>
          </Link>

          <Link
            href="/targets"
            className="group rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm hover:border-sky-200 hover:shadow"
          >
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-semibold tracking-tight">History</h2>
                <p className="mt-2 text-sm text-zinc-600">
                  ดู target ทั้งหมด แล้วเจาะเข้าไปดูผลสแกนย้อนหลัง
                </p>
              </div>
              <span className="rounded-full bg-sky-50 px-3 py-1 text-xs font-semibold text-sky-700">
                Ready
              </span>
            </div>
            <div className="mt-5 text-sm font-semibold text-sky-700 group-hover:underline">
              Open →
            </div>
          </Link>

          <div className="rounded-2xl border border-zinc-200 bg-white p-6 text-sm text-zinc-600 shadow-sm">
            Tools อื่นๆ (nmap/sqlmap/ffuf) จะเพิ่มทีหลัง
          </div>
        </div>
      </div>
    </div>
  );
}
