import Link from "next/link";
import ScanClient from "./ScanClient";

export default function ScanPage() {
  return (
    <div className="h-screen min-h-screen bg-zinc-50 text-zinc-900">
      <div className="flex h-full min-h-0 flex-col">
        <header className="flex shrink-0 items-center justify-between border-b border-zinc-200 bg-white px-6 py-4">
          <div>
            <p className="text-sm font-medium text-zinc-500">oneclickscan</p>
            <h1 className="mt-0.5 text-xl font-semibold tracking-tight">
              รันหลาย tools ในหน้าเดียว
            </h1>
            <p className="mt-1 text-sm text-zinc-600">
              ใส่ target URL แล้วเลือก tools + flags ที่ต้องการ จากนั้นกด Run
            </p>
          </div>
          <Link
            href="/"
            className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
          >
            กลับหน้าแรก
          </Link>
        </header>
        <ScanClient />
      </div>
    </div>
  );
}
