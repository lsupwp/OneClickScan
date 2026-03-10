"""
Local Triage - ไม่เรียก Gemini ใช้ logic ในโค้ดตัดจากผล recon
สร้าง suggested_commands (sqlmap, hydra, xsstrike, commix) ให้ format เดียวกับ AI triage
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

# โฟลเดอร์โปรเจกต์ (ใช้หา wordlist default)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_PASSWORD_LIST = _PROJECT_ROOT / "SecLists" / "Passwords" / "Common-Credentials" / "10k-most-common.txt"


def _is_login_form(body_params: Dict[str, str]) -> bool:
    keys = set((body_params or {}).keys())
    return ("username" in keys or "user" in keys) and ("password" in keys or "pass" in keys)


def _url_to_hydra_target(url: str) -> str:
    """แปลง URL เป็น host:port สำหรับ Hydra (ไม่ใส่ scheme เพราะ http-post-form ใช้ HTTP อยู่แล้ว)."""
    u = urlparse(url)
    host = u.hostname or u.netloc or "127.0.0.1"
    port = u.port
    if port is not None:
        return f"{host}:{port}"
    if u.scheme == "https":
        return f"{host}:443"
    return host  # http default 80


def run_local_triage(
    base_url: str,
    grouped_forms: Dict[str, Any],
    url_entry_points: Dict[str, Any],
    password_wordlist: str | Path | None = None,
) -> Dict[str, Any]:
    """
    จาก grouped_forms + url_entry_points สร้าง targets พร้อม suggested_commands
    (format เดียวกับ AI triage เพื่อใช้กับ output/print เดิมได้)
    """
    base = base_url.rstrip("/") + "/"
    if password_wordlist is None:
        password_wordlist = _DEFAULT_PASSWORD_LIST
    pw_path = str(password_wordlist) if Path(str(password_wordlist)).exists() else "/usr/share/wordlists/rockyou.txt"

    targets: List[Dict[str, Any]] = []

    # 1) Forms
    for _sig, data in grouped_forms.items():
        f = data.get("details", {})
        action = f.get("target_action") or ""
        method = (f.get("method") or "GET").upper()
        body_params = f.get("body_params") or {}
        query_params = f.get("query_params") or {}
        body_keys = list(body_params.keys())
        query_keys = list(query_params.keys())

        suspected = []
        commands: List[str] = []

        if _is_login_form(body_params):
            suspected.extend(["auth_bypass", "sql_injection"])
            # Hydra: http-post-form "path:body:F=fail_string" (path เท่านั้น ไม่ใช่ full URL)
            raw = (action or "").split("?")[0] or "/"
            path_part = urlparse(raw).path if raw.startswith(("http://", "https://")) else raw
            path_part = (path_part or "/").strip() or "/"
            if not path_part.startswith("/"):
                path_part = "/" + path_part
            form_parts = []
            for k in body_keys:
                if k in ("username", "user"):
                    form_parts.append(f"{k}=^USER^")
                elif k in ("password", "pass"):
                    form_parts.append(f"{k}=^PASS^")
                else:
                    form_parts.append(f"{k}=x")
            form_data = "&".join(form_parts)
            hydra_target = _url_to_hydra_target(base_url)
            commands.append(
                f'hydra -l admin -P {pw_path} {hydra_target} http-post-form "{path_part}:{form_data}:F=incorrect"'
            )

        # SQLMap สำหรับ form ที่มี params
        if body_keys or query_keys:
            if "sql_injection" not in suspected:
                suspected.append("sql_injection")
            full_url = urljoin(base, action) if action else base
            if method == "POST":
                commands.append(f'sqlmap -u "{full_url}" --forms --batch')
            else:
                commands.append(f'sqlmap -u "{full_url}" --batch')

        data_str = "&".join(f"{k}=test" for k in (body_keys or query_keys))
        # XSStrike สำหรับ input ที่น่าจะ reflect
        if body_keys or query_keys:
            if "xss" not in suspected:
                suspected.append("xss")
            full_for_tool = urljoin(base, action or "")
            commands.append(f'xsstrike -u "{full_for_tool}" --data "{data_str}" --skip')

        # Commix สำหรับจุดที่อาจมี command injection
        if any("cmd" in k.lower() or "command" in k.lower() or "exec" in k.lower() for k in (body_keys + query_keys)):
            suspected.append("command_injection")
            full_for_tool = urljoin(base, action or "")
            commands.append(f'commix -u "{full_for_tool}" --data "{data_str}"')

        if not suspected:
            suspected.append("other")
        targets.append({
            "endpoint": action or base,
            "method": method,
            "body_params": body_keys,
            "query_params": query_keys,
            "suspected_issue_types": suspected,
            "confidence": "medium",
            "recommended_manual_checks": [],
            "suggested_commands": commands,
        })

    # 2) Query-only endpoints (ไม่มี form)
    for _sig, data in url_entry_points.items():
        base_path = data.get("base_path") or ""
        params = data.get("params") or {}
        if not params:
            continue
        full_url = urljoin(base, base_path)
        param_str = "&".join(f"{k}=1" for k in params)
        if "?" in full_url:
            full_url += "&" + param_str
        else:
            full_url += "?" + param_str
        targets.append({
            "endpoint": base_path,
            "method": "GET",
            "body_params": [],
            "query_params": list(params.keys()),
            "suspected_issue_types": ["sql_injection", "xss"],
            "confidence": "medium",
            "recommended_manual_checks": [],
            "suggested_commands": [
                f'sqlmap -u "{full_url}" --batch',
                f'xsstrike -u "{full_url}" --skip',
            ],
        })

    return {"targets": targets}
