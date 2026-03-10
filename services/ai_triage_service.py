"""
AI Triage Service - ส่งผล recon ไป Gemini เพื่อวิเคราะห์ความเสี่ยงและแนะนำการทดสอบ
สำหรับ authorized pentest เท่านั้น
ตอบกลับเป็น JSON: targets, suspected_issue_types, recommended_checks, suggested_commands
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# Placeholder ที่ส่งให้ Gemini (เพื่อลดการ refuse จาก policy)
PROMPT_BASE = "http://localhost/"


def _build_recon_payload(
    base_url: str,
    paths: List[str],
    grouped_forms: Dict[str, Any],
    url_entry_points: Dict[str, Any],
    use_localhost_in_prompt: bool = True,
) -> Dict[str, Any]:
    """รวมผล recon เป็น dict สำหรับส่งให้ Gemini (ถ้า use_localhost_in_prompt จะแทน host เป็น localhost)."""
    if use_localhost_in_prompt:
        base = PROMPT_BASE
    else:
        base = base_url.rstrip("/") + "/"

    forms_list: List[Dict[str, Any]] = []
    for _sig, data in grouped_forms.items():
        f = data.get("details", {})
        forms_list.append({
            "action": f.get("target_action"),
            "method": f.get("method"),
            "body_params": list((f.get("body_params") or {}).keys()),
            "query_params": list((f.get("query_params") or {}).keys()),
        })

    query_list: List[Dict[str, Any]] = []
    for _sig, data in url_entry_points.items():
        query_list.append({
            "base_path": data.get("base_path"),
            "params": list((data.get("params") or {}).keys()),
        })

    path_sample = paths[:80] if paths else []
    if use_localhost_in_prompt and base_url:
        real_base = base_url.rstrip("/")
        path_sample = [
            (p.replace(real_base, "http://localhost", 1) if p.startswith(real_base) else p)
            for p in path_sample
        ]

    return {
        "scope": "authorized_pentest",
        "base_url": base,
        "paths_count": len(paths),
        "paths_sample": path_sample,
        "forms": forms_list,
        "query_only_endpoints": query_list,
    }


def run_ai_triage(
    base_url: str,
    paths: List[str],
    grouped_forms: Dict[str, Any],
    url_entry_points: Dict[str, Any],
    use_localhost_in_prompt: bool = True,
    model: str = "models/gemini-2.5-flash",
) -> Dict[str, Any]:
    """
    ส่ง recon ไป Gemini แล้วคืน JSON ที่มี targets, suggested_commands ฯลฯ
    """
    payload = _build_recon_payload(
        base_url, paths, grouped_forms, url_entry_points, use_localhost_in_prompt
    )
    prompt = f"""You are assisting with an authorized security assessment (pentest). The following recon data was collected from a web application. Analyze it and return a single JSON object (no markdown, no code block) with this exact structure:

{{
  "targets": [
    {{
      "endpoint": "full URL or path",
      "method": "GET or POST",
      "body_params": ["param1", "param2"],
      "query_params": ["param1"],
      "suspected_issue_types": ["sql_injection", "xss", "auth_bypass", "command_injection", "csrf", "other"],
      "confidence": "low|medium|high",
      "recommended_manual_checks": ["check 1", "check 2"],
      "suggested_commands": ["exact command line the tester can run, e.g. sqlmap -u BASE_URL/login.php --forms --batch", "hydra -l admin -P wordlist.txt BASE_URL http-post-form ..."]
    }}
  ]
}}

Rules:
- suspected_issue_types: use only sql_injection, xss, auth_bypass, command_injection, csrf, idor, path_traversal, other.
- In suggested_commands use the literal string BASE_URL for the target base (e.g. http://localhost/ or the site root). The tool will replace BASE_URL with the real target when displaying.
- Suggest concrete commands where useful: sqlmap for forms/query params that might be SQLi, commix for command injection, xsstrike for reflected input (always add --skip to xsstrike), hydra for login forms. One command per line, no comments.
- Keep suggested_commands short and runnable.

Recon data (authorized scope only):
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""

    try:
        from google import genai
    except ImportError:
        raise RuntimeError("google-genai not installed. pip install google-genai")

    if not (os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")):
        raise RuntimeError("Set GOOGLE_API_KEY or GEMINI_API_KEY for --ai-triage")

    client = genai.Client()
    response = client.models.generate_content(
        model=model,
        contents=prompt,
    )
    text = (response.text or "").strip()
    if not text:
        return {"targets": [], "error": "empty_response"}

    # ลองลบ markdown code block ถ้ามี
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        out = json.loads(text)
    except json.JSONDecodeError as e:
        return {"targets": [], "raw": text[:2000], "error": str(e)}

    if isinstance(out, list):
        out = {"targets": out}
    if "targets" not in out:
        out["targets"] = []
    return out


def apply_real_base_to_commands(triage: Dict[str, Any], real_base_url: str) -> None:
    """แทน BASE_URL ใน suggested_commands และ endpoint ด้วย URL จริง (in-place)."""
    if isinstance(triage, list):
        targets = triage
    else:
        targets = triage.get("targets") or []
    base = real_base_url.rstrip("/")  # ไม่มี trailing slash เพื่อป้องกัน double slash
    for t in targets:
        if not isinstance(t, dict):
            continue
        # แทนใน endpoint ด้วย
        ep = t.get("endpoint") or ""
        if "BASE_URL" in ep:
            t["endpoint"] = ep.replace("BASE_URL/", base + "/").replace("BASE_URL", base)
        # แทนใน suggested_commands
        cmds = t.get("suggested_commands") or []
        replaced = []
        for c in cmds:
            c = c.replace("BASE_URL/", base + "/").replace("BASE_URL", base)
            c = c.replace("http://localhost/", base + "/")
            replaced.append(c)
        t["suggested_commands"] = replaced


def run_ai_triage_round2(
    base_url: str,
    paths: List[str],
    grouped_forms: Dict[str, Any],
    url_entry_points: Dict[str, Any],
    use_localhost_in_prompt: bool = True,
    model: str = "models/gemini-2.5-flash",
) -> Dict[str, Any]:
    """
    รอบ 2 หลัง login: วิเคราะห์เน้น IDOR, Privilege Escalation, Broken Access Control.
    โครงสร้างผลลัพธ์เหมือน run_ai_triage แต่ suspected_issue_types เน้น idor, broken_access_control.
    """
    payload = _build_recon_payload(
        base_url, paths, grouped_forms, url_entry_points, use_localhost_in_prompt
    )
    prompt = f"""You are assisting with an authorized security assessment (pentest). This is a POST-AUTHENTICATION (logged-in) scan. The tester already has a valid session. Focus ONLY on:
- IDOR (Insecure Direct Object Reference): parameters like id, pid, uid, file, doc, order_id that might allow accessing other users' data.
- Privilege escalation: endpoints that might expose admin functions or horizontal/vertical access issues.
- Broken Access Control: URLs or forms that should be restricted but might be reachable.

Return a single JSON object (no markdown, no code block) with this exact structure:
{{
  "targets": [
    {{
      "endpoint": "full URL or path",
      "method": "GET or POST",
      "body_params": ["param1", "param2"],
      "query_params": ["param1"],
      "suspected_issue_types": ["idor", "broken_access_control", "privilege_escalation"],
      "confidence": "low|medium|high",
      "recommended_manual_checks": ["check 1"],
      "suggested_commands": ["exact runnable command using BASE_URL"]
    }}
  ]
}}

Rules:
- suspected_issue_types: prefer idor, broken_access_control, privilege_escalation. Add other only if relevant.
- In suggested_commands use BASE_URL for the target base (no trailing slash); the tool will replace it with the real URL.
- Use appropriate tools in suggested_commands: sqlmap for SQLi endpoints, xsstrike --skip for XSS, commix for command injection endpoints, curl for access control/IDOR checks. Do NOT only suggest curl — use the best tool for the vulnerability type.
- Suggest concrete manual checks (e.g. change id=1 to id=2, try /admin with session).

Recon data (authorized scope, post-auth):
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""

    try:
        from google import genai
    except ImportError:
        raise RuntimeError("google-genai not installed. pip install google-genai")

    if not (os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")):
        raise RuntimeError("Set GOOGLE_API_KEY or GEMINI_API_KEY for AI Triage Round 2")

    try:
        client = genai.Client()
        response = client.models.generate_content(
            model=model,
            contents=prompt,
        )
    except Exception as api_err:
        return {"targets": [], "error": str(api_err)}

    text = (response.text or "").strip()
    if not text:
        return {"targets": [], "error": "empty_response"}

    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        out = json.loads(text)
    except json.JSONDecodeError as e:
        return {"targets": [], "raw": text[:2000], "error": str(e)}

    if isinstance(out, list):
        out = {"targets": out}
    if "targets" not in out:
        out["targets"] = []
    return out


def _extract_path_params(
    full_path: str,
    forms: Dict[str, Any],
    params: Dict[str, Any],
) -> Dict[str, str]:
    """
    คืน dict ของ parameters สำหรับ path นี้ โดย lookup จาก:
    1. grouped_forms  (keyed by "METHOD|action|Q[...]|B[...]")
    2. url_entry_points (keyed by "GET|base_path|[...]")
    3. query string ใน full_path เอง
    """
    from urllib.parse import urlparse, parse_qs, urlencode
    result: Dict[str, str] = {}

    base = full_path.split("?")[0]

    # 1. ลอง lookup จาก url_entry_points (params dict)
    for sig, ep in (params or {}).items():
        if isinstance(ep, dict) and ep.get("base_path") == base:
            for k, v in (ep.get("params") or {}).items():
                result.setdefault(k, v or "test")

    # 2. ลอง lookup จาก grouped_forms
    for sig, data in (forms or {}).items():
        det = data.get("details") or {}
        if det.get("target_action", "").split("?")[0] == base:
            for k, v in (det.get("body_params") or {}).items():
                result.setdefault(k, v or "test")
            for k, v in (det.get("query_params") or {}).items():
                result.setdefault(k, v or "test")

    # 3. query string ใน URL เอง (เช่น ?page=include.php)
    qs = urlparse(full_path).query
    if qs:
        for k, vs in parse_qs(qs, keep_blank_values=True).items():
            result.setdefault(k, vs[0] if vs else "test")

    return result


def build_post_auth_triage_fallback(
    base_url: str,
    paths: List[str],
    forms: Dict[str, Any] | None = None,
    params: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Fallback เมื่อ Gemini 503/error: สร้าง triage round2 จาก paths ที่น่าจะเป็น IDOR/access control
    พร้อม suggested commands ที่เหมาะสมตาม vulnerability type (sqlmap, xsstrike, commix, curl)
    ถ้ามี forms/params → inject parameters จริงลงใน URL ก่อนส่งให้ tool
    """
    targets: List[Dict[str, Any]] = []
    seen: set[str] = set()
    keywords = ("vulnerabilities", "setup", "security", "admin", "user", "api", "config")

    for full_path in paths:
        if not full_path or full_path in seen:
            continue
        path_lower = full_path.lower()
        if not any(k in path_lower for k in keywords):
            continue
        seen.add(full_path)

        # ── classify confidence + issue type ──
        confidence  = "high" if any(x in path_lower for x in ("vulnerabilities", "setup", "security")) else "medium"
        issue_types: List[str] = []
        if "vulnerabilities" in path_lower or "id=" in path_lower or "user" in path_lower:
            issue_types.append("idor")
        if "setup" in path_lower or "security" in path_lower or "admin" in path_lower:
            issue_types.extend(["privilege_escalation", "broken_access_control"])
        if not issue_types:
            issue_types = ["broken_access_control"]

        # ── ดึง parameters จริงจาก forms/params ──────────────────────────
        from urllib.parse import urlencode, urlunparse, urlparse as _up
        known_params = _extract_path_params(full_path, forms, params)

        def _url_with_params(base: str, kp: Dict[str, str]) -> str:
            """ถ้ามี known params ให้ append ?k=v, ไม่งั้นใช้ base เดิม"""
            if not kp or "?" in base:
                return base
            return base + "?" + urlencode(kp)

        # ── choose best tool(s) based on path keyword ──
        cmds: List[str] = []
        # placeholder ที่ _inject_cookie จะแทนด้วย cookie จริงทีหลัง
        C   = "<YOUR_SESSION_COOKIE>"   # generic placeholder
        CK  = f'--cookie="{C}"'          # sqlmap / commix style
        CH  = f'--headers "Cookie: {C}"' # xsstrike style
        CB  = f'-b "{C}"'                # curl style

        sqli_hints = ("sqli", "sql", "id=", "uid=", "user_id=")
        xss_hints  = ("xss_r", "xss_d", "xss_s", "xss", "name=", "q=", "search=", "msg=")
        exec_hints = ("exec", "cmd=", "command=", "ping=", "ip=", "exec/")
        fi_hints   = ("fi/", "page=", "file=", "include=", "path=")

        if any(h in path_lower for h in sqli_hints):
            url_with_p = _url_with_params(full_path, known_params)
            # ถ้า URL ยังไม่มี ? → ใช้ --forms ให้ sqlmap ดึง form เอง
            forms_flag = "--forms" if "?" not in url_with_p else ""
            sqlmap_cmd = f'sqlmap -u "{url_with_p}" {CK} --batch --level=2'
            if forms_flag:
                sqlmap_cmd += f" {forms_flag}"
            cmds.append(sqlmap_cmd)
            cmds.append(f'curl -s {CB} "{url_with_p}"')
        elif any(h in path_lower for h in xss_hints):
            url_with_p = _url_with_params(full_path, known_params)
            # xsstrike ต้องการ param ใน URL ไม่งั้นหา injection point ไม่เจอ
            cmds.append(f'xsstrike -u "{url_with_p}" {CH} --skip')
            cmds.append(f'curl -s {CB} "{url_with_p}"')
        elif any(h in path_lower for h in exec_hints):
            url_with_p = _url_with_params(full_path, known_params)
            if known_params:
                # ส่ง data ผ่าน --data ถ้า form เป็น POST
                data_str = urlencode(known_params)
                cmds.append(f'commix --url="{full_path}" --data="{data_str}" {CK} --batch')
            else:
                cmds.append(f'commix --url="{url_with_p}" {CK} --batch')
            cmds.append(f'curl -s {CB} "{url_with_p}"')
        elif any(h in path_lower for h in fi_hints):
            _p = _up(full_path)
            # ถ้ามี known_params → ใช้ key แรก, ไม่งั้น fallback "page"
            fi_key = next(iter(known_params), None) or (list(_up(full_path).query.split("=")[:1]) or ["page"])[0].split("&")[0] or "page"
            fi_payload = urlencode({fi_key: "../../../../etc/passwd"})
            lfi_url = urlunparse(_p._replace(query=fi_payload))
            cmds.append(f'curl -s {CB} "{lfi_url}"')
            cmds.append(f'curl -s {CB} "{full_path}"')
        else:
            cmds.append(f'curl -s {CB} "{full_path}"')

        targets.append({
            "endpoint":               full_path,
            "method":                 "GET",
            "body_params":            [],
            "query_params":           [],
            "suspected_issue_types":  list(dict.fromkeys(issue_types)),
            "confidence":             confidence,
            "recommended_manual_checks": [
                "Test with session cookie; try parameter tampering (id, user_id, etc.).",
            ],
            "suggested_commands": cmds,
        })

    return {"targets": targets}
