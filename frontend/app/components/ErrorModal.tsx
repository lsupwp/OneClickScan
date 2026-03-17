"use client";

type ErrorModalProps = {
  open: boolean;
  onClose: () => void;
  title?: string;
  message: string;
};

export default function ErrorModal({
  open,
  onClose,
  title = "เกิดข้อผิดพลาด",
  message,
}: ErrorModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="error-modal-title"
    >
      <div className="w-full max-w-md rounded-2xl border border-red-200 bg-white p-6 shadow-xl">
        <h2
          id="error-modal-title"
          className="text-base font-semibold text-red-800"
        >
          {title}
        </h2>
        <p className="mt-2 text-sm text-zinc-700 whitespace-pre-wrap">
          {message}
        </p>
        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-700"
          >
            ปิด
          </button>
        </div>
      </div>
    </div>
  );
}
