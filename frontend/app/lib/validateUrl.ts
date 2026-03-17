/**
 * Validate URL input. Returns error message if invalid, null if valid.
 */
export function validateUrl(value: string | null | undefined): string | null {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!trimmed) {
    return "กรุณาใส่ URL";
  }
  try {
    const u = new URL(trimmed);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return "URL ต้องขึ้นต้นด้วย http:// หรือ https://";
    }
    return null;
  } catch {
    return "รูปแบบ URL ไม่ถูกต้อง (ต้องขึ้นต้นด้วย http:// หรือ https://)";
  }
}
