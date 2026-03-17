import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-zinc-100 text-zinc-900">
      <div className="mx-auto w-full max-w-2xl px-6 py-16">
        <header className="text-center mb-14">
          <p className="text-xs font-semibold uppercase tracking-widest text-amber-600">oneclickscan</p>
          <h1 className="mt-4 text-4xl font-bold tracking-tight text-zinc-900">
            สแกนหลาย tools พร้อมกัน
          </h1>
          <p className="mt-4 text-base leading-relaxed text-zinc-600">
            ใส่ URL เดียว เลือก Katana / FFuf / Payload Recon ตั้งค่าใน modal แล้วรันได้ในหน้าเดียว
          </p>
        </header>

        <div className="space-y-4">
          <Link
            href="/scan"
            className="group block rounded-3xl border-2 border-amber-200 bg-white p-8 shadow-lg shadow-amber-900/5 transition hover:border-amber-400 hover:shadow-xl hover:shadow-amber-900/10"
          >
            <div className="flex items-center gap-4">
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-amber-400 to-amber-600 text-2xl font-bold text-white shadow-lg shadow-amber-500/30">
                ▶
              </span>
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-zinc-900 group-hover:text-amber-800">
                  เริ่มสแกน
                </h2>
                <p className="mt-1 text-sm text-zinc-500">
                  เลือก tools → กด Run → ตั้งค่า flags ใน modal → ดูผลใน modal เมื่อ Done
                </p>
              </div>
              <span className="text-zinc-400 group-hover:text-amber-600 transition">→</span>
            </div>
          </Link>

          <Link
            href="/targets"
            className="group block rounded-3xl border border-zinc-200 bg-white p-6 shadow-sm transition hover:border-zinc-300 hover:shadow"
          >
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-zinc-800">History</h2>
                <p className="mt-1 text-sm text-zinc-500">ดู target และผลสแกนย้อนหลัง</p>
              </div>
              <span className="text-zinc-400 group-hover:text-zinc-600 transition">→</span>
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
}
