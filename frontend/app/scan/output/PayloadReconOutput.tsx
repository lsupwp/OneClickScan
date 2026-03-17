"use client";

type PayloadEntry = {
  found_in: string[];
  form_id?: string | null;
  form_name?: string | null;
  action: string;
  method: string;
  query_string: Record<string, string>;
  payload: Record<string, string>;
};

type PayloadReconOutputProps = {
  payloadEntries: PayloadEntry[] | null;
};

export default function PayloadReconOutput({ payloadEntries }: PayloadReconOutputProps) {
  if (payloadEntries === null) {
    return <p className="text-sm text-zinc-500">กำลังโหลด…</p>;
  }
  if (payloadEntries.length === 0) {
    return <p className="text-sm text-zinc-500">ไม่พบ forms / params</p>;
  }

  return (
    <div className="space-y-4">
      {payloadEntries.map((entry, idx) => (
        <div key={idx} className="rounded-2xl border border-violet-100 bg-violet-50/30 p-4">
          <div className="flex items-center gap-2">
            <span className="rounded-md bg-violet-200 px-2 py-0.5 text-xs font-semibold text-violet-800">
              {entry.method}
            </span>
            <span className="font-mono text-sm text-zinc-800 break-all">{entry.action}</span>
          </div>
          {(entry.form_id || entry.form_name) && (
            <p className="mt-1 text-[11px] text-zinc-500">
              Form:{" "}
              <span className="font-mono">
                {entry.form_id ? `#${entry.form_id}` : ""}
                {entry.form_id && entry.form_name ? " " : ""}
                {entry.form_name ? `name=\"${entry.form_name}\"` : ""}
              </span>
            </p>
          )}
          {(Object.keys(entry.query_string || {}).length > 0 || Object.keys(entry.payload || {}).length > 0) && (
            <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
              {Object.keys(entry.query_string || {}).length > 0 && (
                <div>
                  <span className="font-medium text-zinc-600">Query:</span>
                  <pre className="mt-0.5 rounded-lg bg-white p-2 font-mono text-zinc-800 overflow-x-auto">
                    {JSON.stringify(entry.query_string, null, 2)}
                  </pre>
                </div>
              )}
              {Object.keys(entry.payload || {}).length > 0 && (
                <div>
                  <span className="font-medium text-zinc-600">Payload:</span>
                  <pre className="mt-0.5 rounded-lg bg-white p-2 font-mono text-zinc-800 overflow-x-auto">
                    {JSON.stringify(entry.payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
          {entry.found_in && entry.found_in.length > 0 && (
            <p className="mt-2 text-[11px] text-zinc-500">
              Found in: {entry.found_in.slice(0, 3).join(", ")}
              {entry.found_in.length > 3 && ` +${entry.found_in.length - 3} more`}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
