#!/usr/bin/env python3
"""
Executor - อ่าน triage.json จาก AI Triage / Auto Triage แล้วรันคำสั่งที่แนะนำ
- Filter: เลือกรันเฉพาะ [high] หรือทั้งหมด
- Safety: ตรวจสอบว่ามี Tool ติดตั้งก่อนรัน
- Logging: เก็บ output แยกไฟล์ใน results/ ตามชื่อ Tool และ Parameter
- CSRF: ดึง token ก่อนส่งคำสั่งให้ tool (และใช้ใน post-exploit login)
- Post-Exploit: Login ด้วย credential ที่พบ, บันทึก session, ถามรัน High-Level Scan (main.py --cookie-file)
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


def load_triage(path: str | Path) -> dict:
    """โหลด triage.json"""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Triage file not found: {p}")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


_ORDER = {"high": 3, "medium": 2, "low": 1}


def filter_targets(targets: list, min_confidence: str | None) -> list:
    """
    กรอง targets ตาม min_confidence: high = เฉพาะ high, medium = high+medium, low/None = ทั้งหมด
    """
    if not min_confidence or min_confidence.lower() == "low":
        return list(targets)
    min_level = _ORDER.get(min_confidence.lower(), 0)
    out = []
    for t in targets:
        c = (t.get("confidence") or "low").lower()
        level = _ORDER.get(c, 1)
        if level >= min_level:
            out.append(t)
    return out


def _print_post_scan_summary(project_root: Path) -> None:
    """สรุปผลหลังผู้ใช้ตอบไม่สแกนต่อ (report path, triage round2, จำนวน targets)."""
    project_root = Path(project_root)
    lines = ["\n" + "=" * 60, "สรุปผลการสแกน", "=" * 60]
    report_path = project_root / "final_report.md"
    if report_path.exists():
        lines.append(f"  รายงานรวม: {report_path}")
    triage2_path = project_root / "triage_round2.json"
    if triage2_path.exists():
        try:
            data = json.loads(triage2_path.read_text(encoding="utf-8"))
            targets = data.get("targets", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            high = sum(1 for t in targets if isinstance(t, dict) and (t.get("confidence") or "").lower() == "high")
            med = sum(1 for t in targets if isinstance(t, dict) and (t.get("confidence") or "").lower() == "medium")
            low = sum(1 for t in targets if isinstance(t, dict) and (t.get("confidence") or "").lower() == "low")
            lines.append(f"  Post-Auth Triage: {triage2_path} (high: {high}, medium: {med}, low: {low})")
        except Exception:
            lines.append(f"  Post-Auth Triage: {triage2_path}")
    lines.append(f"  ผลรันคำสั่ง: {project_root / 'results'}")
    lines.append(f"  Triage รอบแรก: {project_root / 'triage.json'}")
    lines.append("=" * 60)
    print("\n".join(lines))


def extract_tool_name(cmd: str) -> str | None:
    """ดึงชื่อคำสั่งตัวแรกจาก command string (ไม่นับ path ใน quoted URL)"""
    cmd = (cmd or "").strip()
    if not cmd:
        return None
    # แยกแบบง่าย: หา token แรกที่ไม่อยู่ใน quotes
    in_quote = None
    token = []
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if c in "\"'" and (not in_quote or in_quote == c):
            in_quote = None if in_quote else c
            i += 1
            continue
        if in_quote:
            i += 1
            continue
        if c in " \t":
            if token:
                break
            i += 1
            continue
        token.append(c)
        i += 1
    name = "".join(token)
    # ถ้าเป็น path เช่น /usr/bin/sqlmap ใช้แค่ชื่อไฟล์
    if "/" in name:
        name = name.split("/")[-1]
    return name or None


def tool_available(tool: str) -> bool:
    """ตรวจสอบว่าเครื่องมีคำสั่งนี้หรือไม่ (which)"""
    if not tool:
        return False
    return shutil.which(tool) is not None


def endpoint_to_slug(endpoint: str, max_len: int = 40) -> str:
    """แปลง endpoint เป็นชื่อไฟล์ที่ปลอดภัย (ไม่มี / : ? & =)"""
    if not endpoint:
        return "unknown"
    # เอา path จาก URL หรือใช้ทั้งก้อน
    if "://" in endpoint:
        endpoint = urlparse(endpoint).path or endpoint
    slug = re.sub(r"[^\w\-.]", "_", endpoint).strip("_")
    slug = re.sub(r"_+", "_", slug)[:max_len]
    return slug or "unknown"


def get_csrf_token(
    url: str,
    token_name: str = "user_token",
    timeout: int = 10,
    session: requests.Session | None = None,
) -> str | None:
    """
    ดึงค่า value จาก <input type="hidden" name="token_name" value="..."> ในหน้า url.
    ใช้ BeautifulSoup ก่อน แล้ว fallback เป็น regex.
    """
    try:
        if session is not None:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        else:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        html = resp.text or ""
    except Exception:
        return None
    soup = BeautifulSoup(html, "html.parser")
    inp = soup.find("input", {"type": "hidden", "name": token_name})
    if inp and inp.get("value"):
        return inp.get("value")
    # Fallback: regex หา name=token_name value="..."
    re_pattern = re.compile(
        rf'<input[^>]+name=["\']({re.escape(token_name)})["\'][^>]+value=["\']([^"\']+)["\']',
        re.I,
    )
    m = re_pattern.search(html)
    if m:
        return m.group(2)
    re_pattern2 = re.compile(
        rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']({re.escape(token_name)})["\']',
        re.I,
    )
    m2 = re_pattern2.search(html)
    if m2:
        return m2.group(1)
    return None


def _response_looks_authenticated(resp: requests.Response, login_url: str) -> bool:
    """
    เช็คว่าหน้า response ดูเหมือน login สำเร็จจริง ไม่ใช่ยังเด้งกลับหน้า login.
    """
    if resp.status_code >= 400:
        return False
    body = (resp.text or "").lower()
    final_url = (resp.url or "").lower()
    login_name = (urlparse(login_url).path.rsplit("/", 1)[-1] or "").lower()

    fail_markers = ("incorrect", "login failed", "invalid", "wrong password", "authentication failed")
    if any(marker in body for marker in fail_markers):
        return False

    success_markers = ("logout", "welcome", "dashboard", "instructions.php", "dvwa security", "php info")
    if any(marker in body for marker in success_markers):
        return True

    soup = BeautifulSoup(resp.text or "", "html.parser")
    for form in soup.find_all("form"):
        fields = {
            (inp.get("name") or "").strip().lower()
            for inp in form.find_all("input")
            if inp.get("name")
        }
        if fields and any(name in fields for name in ("username", "user", "uname")) and any(
            name in fields for name in ("password", "pass", "pwd")
        ):
            return False

    if resp.history and login_name and login_name not in final_url:
        return True

    if "login" in final_url and login_name and login_name in final_url:
        return False

    return len(resp.history) > 0


def load_cookie_header(cookie_file: str | Path) -> str | None:
    """
    อ่านไฟล์ cookie (active_session.json) แล้วคืนค่า Cookie header string.
    รองรับรูปแบบ: {"Cookie": "a=b; c=d"} หรือ {"cookies": [{"name","value"}, ...]}
    """
    p = Path(cookie_file)
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if isinstance(data, dict) and data.get("Cookie"):
        return data["Cookie"].strip()
    if isinstance(data, dict) and data.get("cookies"):
        parts = [f"{c.get('name','')}={c.get('value','')}" for c in data["cookies"] if c.get("name")]
        return "; ".join(parts) if parts else None
    return None


def _hydra_target_to_hostport(url: str) -> str:
    """แปลง URL เป็น host:port สำหรับ Hydra (target ต้องไม่มี scheme)."""
    u = urlparse(url)
    host = u.hostname or u.netloc or "127.0.0.1"
    port = u.port
    if port is not None:
        return f"{host}:{port}"
    if u.scheme == "https":
        return f"{host}:443"
    return host


def _normalize_hydra_command(cmd: str) -> str:
    """แก้ target ในคำสั่ง hydra จาก http(s)://host เป็น host:port เพื่อไม่ให้ Invalid target definition."""
    # ตรงที่อยู่ก่อน "http-post-form" คือ target; ถ้าเป็น URL ต้องแปลง
    m = re.search(r"(\s)(https?://[^/\s]+(?::\d+)?)(\s+http-post-form)", cmd)
    if m:
        prefix, url, suffix = m.group(1), m.group(2), m.group(3)
        return cmd.replace(m.group(0), prefix + _hydra_target_to_hostport(url) + suffix, 1)
    return cmd


def inject_cookie_into_command(cmd: str, tool: str, cookie_header: str) -> str:
    """
    ฉีด Cookie header เข้า command ตามรูปแบบของแต่ละ tool.
    sqlmap: --cookie="..."
    xsstrike: --headers "Cookie: ..."
    hydra: ไม่เปลี่ยน (มักใช้กับ login ก่อนมี session)
    """
    if not cookie_header or not cmd.strip():
        return cmd
    cookie_escaped = cookie_header.replace('"', '\\"')
    tool_lower = (tool or "").lower()
    if tool_lower == "sqlmap":
        if "--cookie=" in cmd or "--cookie " in cmd:
            return cmd
        return cmd.rstrip() + f' --cookie="{cookie_escaped}"'
    if tool_lower == "xsstrike":
        if "--headers" in cmd:
            return cmd
        return cmd.rstrip() + f' --headers "Cookie: {cookie_escaped}"'
    return cmd


def run_command(cmd: str, timeout: int | None = 300) -> tuple[str, str, int]:
    """รันคำสั่งด้วย subprocess.run; คืน (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Path(__file__).resolve().parent,
        )
        return (r.stdout or "", r.stderr or "", r.returncode)
    except subprocess.TimeoutExpired:
        return ("", "Command timed out.", -1)
    except Exception as e:
        return ("", str(e), -1)


# รูปแบบ output ของ Hydra เมื่อพบ password (บรรทัด [host] login: user   password: pass)
_HYDRA_LOGIN_RE = re.compile(
    r"\[\d+\]\[[\w-]+\]\s+host:\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S+)",
    re.I,
)
# รูปแบบ output ของ bruter.py
_BRUTER_CREDENTIAL_RE = re.compile(r"CREDENTIAL:\t(?P<login>[^\t]+)\t(?P<password>.+)")

# คีย์ใน form ที่นับว่าเป็น token/CSRF (ถ้ามี = ใช้ bruter แทน hydra)
_TOKEN_LIKE_KEYS = ("token", "csrf", "_sync", "_token", "authenticity_token", "sync")


def has_token_like_param(body_params: list | dict) -> tuple[bool, str | None]:
    """
    ตรวจจากรายการ parameters ว่ามีชื่อที่เหมือน token/csrf/_sync หรือค่าสุ่มหรือไม่.
    คืน (True, csrf_field_name) ถ้าพบ, (False, None) ถ้าไม่พบ.
    """
    if isinstance(body_params, dict):
        keys = list(body_params.keys())
    else:
        keys = list(body_params) if body_params else []
    for k in keys:
        k_lower = str(k).lower()
        for t in _TOKEN_LIKE_KEYS:
            if t in k_lower:
                return (True, str(k))
    return (False, None)


def parse_credentials_from_log(log_path: str | Path) -> list[tuple[str, str]]:
    """
    อ่านไฟล์ log จาก hydra / bruter แล้วคืนรายการ (username, password) ที่พบ.
    รองรับรูปแบบ hydra และ CREDENTIAL:\\tuser\\tpass จาก bruter.py
    """
    path = Path(log_path)
    if not path.exists():
        return []
    found: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    for m in _HYDRA_LOGIN_RE.finditer(text):
        login = (m.group("login") or "").strip()
        password = (m.group("password") or "").strip()
        if login and (login, password) not in found:
            found.append((login, password))
    for m in _BRUTER_CREDENTIAL_RE.finditer(text):
        login = (m.group("login") or "").strip()
        password = (m.group("password") or "").strip()
        if login and (login, password) not in found:
            found.append((login, password))
    return found


def post_exploit_login(
    login_url: str,
    username: str,
    password: str,
    form_body_params: dict[str, str] | None,
    cookie_file: str | Path,
    csrf_token_name: str = "user_token",
    timeout: int = 15,
) -> bool:
    """
    Login จริงด้วย requests.Session(); ถ้าหน้า Login มี CSRF จะดึง token มาใส่ใน payload.
    เมื่อสำเร็จบันทึก cookies ลง active_session.json (cookie_file).
    form_body_params = dict ของชื่อ field -> value; จะแทน uname/user/username ด้วย username, pass/password ด้วย password.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    })
    try:
        # ดึง CSRF ถ้ามี
        csrf_val = get_csrf_token(
            login_url,
            token_name=csrf_token_name,
            timeout=timeout,
            session=session,
        )
        body: dict[str, str] = dict(form_body_params or {})
        # แทนที่ field login
        for key in list(body.keys()):
            k_lower = key.lower()
            if k_lower in ("username", "user", "uname", "login"):
                body[key] = username
            elif k_lower in ("password", "pass", "pwd"):
                body[key] = password
        if csrf_val:
            body[csrf_token_name] = csrf_val
        resp = session.post(login_url, data=body, timeout=timeout, allow_redirects=True)
        if not _response_looks_authenticated(resp, login_url):
            return False

        parsed_login = urlparse(login_url)
        base_url = f"{parsed_login.scheme}://{parsed_login.netloc}"
        # ตรวจ login_url เองก่อน แล้ว probe root + index — ไม่ hardcode path เฉพาะ app ใด
        login_path = parsed_login.path.lstrip("/") or ""
        verify_candidates = list(dict.fromkeys([  # unique, preserve order
            base_url + "/",
            base_url + "/" + login_path if login_path else base_url + "/",
            base_url + "/index.php",
        ]))
        verified = False
        for candidate in verify_candidates:
            try:
                verify_resp = session.get(candidate, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if _response_looks_authenticated(verify_resp, login_url):
                verified = True
                break
        if not verified:
            return False

        # บันทึก session
        cookies_list = [
            {"name": c.name, "value": c.value}
            for c in session.cookies
        ]
        out = {
            "url": login_url,
            "Cookie": "; ".join(f"{c.name}={c.value}" for c in session.cookies),
            "cookies": cookies_list,
        }
        Path(cookie_file).parent.mkdir(parents=True, exist_ok=True)
        with open(cookie_file, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def _run_one(
    item: tuple[tuple[str, str, str, int, int], int, int, Path, int, str | None],
) -> tuple[int, str, str, int, bool]:
    """
    รันคำสั่งเดียวแล้วเขียน log.
    item = ((cmd, tool, slug, ti, ci), idx, total, results_dir, timeout, cookie_header)
    คืน (idx, tool, log_name, returncode, skipped)
    """
    (cmd, tool, slug, ti, ci), idx, total, results_dir, timeout, cookie_header = item
    if not tool_available(tool):
        return (idx, tool, "", -1, True)
    if (tool or "").lower() == "hydra":
        cmd = _normalize_hydra_command(cmd)
    if cookie_header:
        cmd = inject_cookie_into_command(cmd, tool, cookie_header)
    safe_tool = re.sub(r"[^\w\-]", "_", tool)
    log_name = f"{safe_tool}_{slug}_{ti}_{ci}.log"
    log_path = results_dir / log_name
    stdout, stderr, rc = run_command(cmd, timeout=timeout)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"# Command:\n{cmd}\n\n")
        f.write(f"# Return code: {rc}\n\n")
        f.write("# --- stdout ---\n")
        f.write(stdout)
        if stderr:
            f.write("\n# --- stderr ---\n")
            f.write(stderr)
    return (idx, tool, log_name, rc, False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run suggested commands from triage.json (AI/auto triage output)"
    )
    parser.add_argument(
        "triage_file",
        nargs="?",
        default="triage.json",
        help="Path to triage.json (default: triage.json)",
    )
    parser.add_argument(
        "--high-only",
        action="store_true",
        help="Run only targets with confidence 'high' (same as --min-confidence high)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["high", "medium", "low"],
        metavar="LEVEL",
        help="Minimum confidence: high=only high, medium=high+medium, low=all (default: all)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all targets (no filter)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print commands and missing tools, do not execute",
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        metavar="DIR",
        help="Directory for output logs (default: results)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SEC",
        help="Timeout per command in seconds (default: 300)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Number of commands to run in parallel (default: 4)",
    )
    parser.add_argument(
        "--cookie-file",
        default=None,
        metavar="FILE",
        help="Inject session from FILE (e.g. active_session.json) into sqlmap/xsstrike",
    )
    parser.add_argument(
        "--no-rescan-prompt",
        action="store_true",
        help="Do not prompt for High-Level Scan after run (skip Y/N)",
    )
    parser.add_argument(
        "--user-file",
        default=None,
        metavar="FILE",
        help="Username list for bruter (when form has token). Default: admin",
    )
    parser.add_argument(
        "--pass-file",
        default=None,
        metavar="FILE",
        help="Password list for bruter/hydra. Default: SecLists/.../10k-most-common.txt",
    )
    args = parser.parse_args()

    min_confidence: str | None = getattr(args, "min_confidence", None)
    if args.high_only:
        min_confidence = "high"
    if args.all:
        min_confidence = None  # all

    try:
        data = load_triage(args.triage_file)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    targets = data.get("targets") or []
    if not targets:
        print("[!] No targets in triage file.", file=sys.stderr)
        sys.exit(1)

    filtered = filter_targets(targets, min_confidence)
    if not filtered:
        print(
            "[!] No targets match filter (--min-confidence/--high-only too strict for this triage).",
            file=sys.stderr,
        )
        sys.exit(1)

    project_root = Path(__file__).resolve().parent
    pass_file_opt = getattr(args, "pass_file", None)
    default_pass_file = Path(pass_file_opt) if pass_file_opt else None
    if not default_pass_file or not default_pass_file.exists():
        default_pass_file = project_root / "SecLists" / "Passwords" / "Common-Credentials" / "10k-most-common.txt"
    if not default_pass_file.exists():
        default_pass_file = Path("/usr/share/wordlists/rockyou.txt")

    # รวบรวมคำสั่งทั้งหมด + bruter_jobs (เมื่อพบ token ใน form ให้ใช้ bruter แทน hydra)
    commands: list[tuple[str, str, str, int, int]] = []  # (cmd, tool, slug, target_idx, cmd_idx)
    bruter_jobs: list[dict] = []  # [{url, user_field, pass_field, csrf_field, extra, slug, ti, form_params}]
    for ti, t in enumerate(filtered):
        endpoint = (t.get("endpoint") or "").strip()
        slug = endpoint_to_slug(endpoint)
        body_params = t.get("body_params")
        if isinstance(body_params, list):
            param_names = [str(x) for x in body_params]
        else:
            param_names = list((body_params or {}).keys())
        has_token, csrf_field = has_token_like_param(param_names)

        for ci, cmd in enumerate(t.get("suggested_commands") or []):
            cmd = (cmd or "").strip()
            if not cmd:
                continue
            tool = extract_tool_name(cmd)
            if not tool:
                continue
            if (tool or "").lower() == "hydra" and has_token and csrf_field:
                # Override: ไม่รัน hydra ให้รัน bruter แทน
                user_field = next((p for p in param_names if str(p).lower() in ("username", "user", "uname", "login")), param_names[0] if param_names else "username")
                pass_field = next((p for p in param_names if str(p).lower() in ("password", "pass", "pwd")), "password")
                extra_parts = [f"{p}=x" for p in param_names if str(p).lower() not in (user_field.lower(), pass_field.lower(), csrf_field.lower())]
                bruter_jobs.append({
                    "url": endpoint if "://" in endpoint else "",
                    "endpoint": endpoint,
                    "user_field": user_field,
                    "pass_field": pass_field,
                    "csrf_field": csrf_field,
                    "extra": "&".join(extra_parts),
                    "slug": slug,
                    "ti": ti,
                    "form_params": {p: "" for p in param_names},
                })
                continue
            commands.append((cmd, tool, slug, ti, ci))

    # Safety: ตรวจสอบ tools ที่จะใช้
    tools_used = {t for (_, t, _, _, _) in commands}
    missing = [t for t in sorted(tools_used) if not tool_available(t)]
    if missing:
        print("[!] Missing tools (install or add to PATH):", ", ".join(missing), file=sys.stderr)
        if not args.dry_run:
            print("[?] Continue anyway? [y/N]: ", end="", file=sys.stderr)
            try:
                if input().strip().lower() != "y":
                    sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                sys.exit(1)

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Output directory: {results_dir.resolve()}")

    if min_confidence == "high":
        print("[*] Mode: min-confidence high only")
    elif min_confidence == "medium":
        print("[*] Mode: min-confidence high + medium")
    else:
        print("[*] Mode: all targets")

    cookie_header: str | None = None
    if getattr(args, "cookie_file", None):
        cookie_header = load_cookie_header(args.cookie_file)
        if cookie_header:
            print(f"[*] Cookie file loaded: {args.cookie_file}")
        else:
            cookie_header = None

    workers = max(1, args.workers)
    print(f"[*] Commands to run: {len(commands)} (workers: {workers})")
    if bruter_jobs:
        print(f"[*] Bruter jobs (form with token): {len(bruter_jobs)} (override hydra)")
    if args.dry_run:
        for cmd, tool, slug, ti, ci in commands:
            print(f"  {tool}: {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
        for job in bruter_jobs:
            print(f"  bruter: {job['url'][:60]}... (csrf={job['csrf_field']})")
        print("[*] Dry run — no execution.")
        return

    total = len(commands)
    items = [
        ((cmd, tool, slug, ti, ci), idx + 1, total, results_dir, args.timeout, cookie_header)
        for idx, (cmd, tool, slug, ti, ci) in enumerate(commands)
    ]
    print_lock = threading.Lock()

    def _log(msg: str) -> None:
        with print_lock:
            print(msg)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_run_one, it): it for it in items}
        for future in as_completed(futures):
            try:
                idx, tool, log_name, rc, skipped = future.result()
                if skipped:
                    _log(f"[!] Skip (not found): {tool}")
                else:
                    _log(f"[*] Done [{idx}/{total}] {tool} -> {log_name}" + (f" (exit {rc})" if rc != 0 else ""))
            except Exception as e:
                _log(f"[!] Error: {e}")

    # รัน bruter สำหรับ form ที่มี token (แทน hydra)
    base_url_bruter = ""
    for t in filtered:
        ep = (t.get("endpoint") or "").strip()
        if "://" in ep:
            base_url_bruter = f"{urlparse(ep).scheme}://{urlparse(ep).netloc}/"
            break
    for job in bruter_jobs:
        url = job["url"]
        if not url or "://" not in url:
            url = (base_url_bruter or "http://127.0.0.1/").rstrip("/") + "/" + (job.get("endpoint") or "").lstrip("/")
        log_name = f"bruter_{job['slug']}_{job['ti']}.log"
        log_path = results_dir / log_name
        pass_file = str(default_pass_file) if default_pass_file.exists() else "/usr/share/wordlists/rockyou.txt"
        bruter_cmd = [
            sys.executable,
            str(project_root / "bruter.py"),
            "--url", url,
            "--user-field", job["user_field"],
            "--pass-field", job["pass_field"],
            "--csrf-field", job["csrf_field"],
            "--pass-file", pass_file,
            "--failure-string", "incorrect|failed|login failed|invalid",
            "--output", str(log_path),
        ]
        if job.get("extra"):
            bruter_cmd.extend(["--extra", job["extra"]])
        if getattr(args, "user_file", None) and Path(args.user_file).exists():
            bruter_cmd.extend(["--user-file", str(args.user_file)])
        try:
            proc = subprocess.run(
                bruter_cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"# Command: {' '.join(bruter_cmd)}\n")
                f.write(f"# Return code: {proc.returncode}\n# --- stdout ---\n")
                f.write(proc.stdout or "")
                if proc.stderr:
                    f.write("\n# --- stderr ---\n" + proc.stderr)
            _log(f"[*] Bruter [{job['slug']}] -> {log_name}" + (f" (exit {proc.returncode})" if proc.returncode != 0 else ""))
        except Exception as e:
            _log(f"[!] Bruter error: {e}")

    # Post-Exploit: สแกน log หา credential (hydra + bruter) แล้ว login จริง, บันทึก session, ถามรัน High-Level Scan
    session_saved = False
    base_url_for_rescan: str | None = None
    if not args.dry_run and not getattr(args, "no_rescan_prompt", False):
        all_logs = list(Path(args.results_dir).glob("*.log"))
        credentials: list[tuple[str, str]] = []
        for log_path in all_logs:
            credentials.extend(parse_credentials_from_log(log_path))
        if credentials:
            # หา login endpoint จาก triage (target ที่มี uname/username + pass/password)
            login_target = None
            for t in filtered:
                bp = (t.get("body_params") or []) if isinstance(t.get("body_params"), list) else list((t.get("body_params") or {}).keys())
                bp_lower = [str(x).lower() for x in bp]
                if any(x in bp_lower for x in ("username", "user", "uname", "login")) and any(x in bp_lower for x in ("password", "pass", "pwd")):
                    login_target = t
                    break
            if login_target:
                endpoint = (login_target.get("endpoint") or "").strip()
                if endpoint and "://" in endpoint:
                    base_url_for_rescan = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}/"
                else:
                    base_url_for_rescan = (data.get("base_url") or "").rstrip("/") + "/"
                login_url = endpoint if (endpoint and "://" in endpoint) else (base_url_for_rescan or "").rstrip("/") + "/" + endpoint.lstrip("/")
                form_params = {}
                if isinstance(login_target.get("body_params"), list):
                    for k in login_target["body_params"]:
                        form_params[str(k)] = ""
                else:
                    form_params = dict(login_target.get("body_params") or {})
                for user, passwd in credentials[:3]:  # ลองสูงสุด 3 ชุด
                    cookie_path = Path(args.results_dir).parent / "active_session.json"
                    if post_exploit_login(
                        login_url=login_url,
                        username=user,
                        password=passwd,
                        form_body_params=form_params,
                        cookie_file=cookie_path,
                        csrf_token_name="user_token",
                    ):
                        session_saved = True
                        print(f"[*] Post-exploit login OK: {user}:**** -> {cookie_path}")
                        break
                if not session_saved and credentials:
                    print("[*] No successful login (try manual or check CSRF).")
        if session_saved and base_url_for_rescan:
            base_url_for_rescan = base_url_for_rescan.rstrip("/") + "/"
            try:
                print("\n[*] ต้องการเริ่ม High-Level Scan ในฐานะ User หรือไม่? (Y/N): ", end="")
                ans = input().strip().upper()
                if ans != "Y":
                    _print_post_scan_summary(Path(__file__).resolve().parent)
                elif ans == "Y":
                    cookie_path = (Path(args.results_dir).parent / "active_session.json").resolve()
                    cmd_main = [
                        sys.executable,
                        str(Path(__file__).resolve().parent / "main.py"),
                        "-u", base_url_for_rescan.rstrip("/"),
                        "--path-recon", "--payload-recon",
                        "--cookie-file", str(cookie_path),
                        "--post-auth",
                    ]
                    while True:
                        print(f"[*] Running: {' '.join(cmd_main)}")
                        subprocess.run(cmd_main, cwd=Path(__file__).resolve().parent)
                        try:
                            print("\n[*] ต้องการสแกนต่ออีกหรือไม่? (Y/N): ", end="")
                            if input().strip().upper() != "Y":
                                _print_post_scan_summary(Path(__file__).resolve().parent)
                                break
                            continue
                        except (EOFError, KeyboardInterrupt):
                            _print_post_scan_summary(Path(__file__).resolve().parent)
                            break
            except (EOFError, KeyboardInterrupt):
                pass

    print("[*] Done.")


if __name__ == "__main__":
    main()
