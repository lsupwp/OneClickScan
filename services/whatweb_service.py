"""
WhatWeb Service - fingerprint tech stack จากเว็บ และดึง version ไปทำลิงก์เช็ค CVE/Exploit
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class WhatWebFinding:
    plugin: str
    value: str
    product: str
    version: Optional[str]
    query: str


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def run_whatweb(target_url: str, timeout: int = 120) -> str:
    """
    รัน whatweb แล้วคืน stdout (raw).
    """
    cmd = ["whatweb", target_url]
    try:
        return subprocess.check_output(cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise RuntimeError("whatweb not found. Install whatweb (apt install whatweb).")
    except subprocess.TimeoutExpired:
        raise RuntimeError("whatweb timed out.")
    except subprocess.CalledProcessError as e:
        # whatweb ชอบพิมพ์ error ลง stdout/stderr; คืน output เพื่อ debug ได้
        raise RuntimeError(f"whatweb failed: {e.output.strip()}") from e


_BRACKET_TOKEN = re.compile(r"(?P<plugin>[A-Za-z0-9_-]+)\[(?P<value>[^\]]+)\]")
_SEMVER_RE = re.compile(r"(?P<ver>\d+(?:\.\d+){1,3})")
_PROD_VER_RE = re.compile(r"(?P<prod>[A-Za-z][A-Za-z0-9._+-]*)/(?P<ver>\d+(?:\.\d+){1,3})")


def _normalize_product_version(plugin: str, value: str) -> tuple[str, Optional[str]]:
    """
    Normalize finding ให้เหลือ product + version ที่เหมาะกับการ search CVE/Exploit:
    - PHP[5.6.40-38+ubuntu...] -> (PHP, 5.6.40)
    - X-Powered-By[PHP/5.6.40-...] -> (PHP, 5.6.40)
    - HTTPServer[nginx/1.19.0] -> (nginx, 1.19.0)
    """
    plugin = plugin.strip()
    value = value.strip()

    # กรณี value เป็น "product/version..."
    m = _PROD_VER_RE.search(value)
    if m:
        return (m.group("prod"), m.group("ver"))

    # กรณี plugin เป็น header-ish แต่ value บอก product/version
    if plugin in {"HTTPServer", "X-Powered-By"}:
        m2 = _PROD_VER_RE.search(value)
        if m2:
            return (m2.group("prod"), m2.group("ver"))

    # กรณี plugin คือ product และ value เริ่มด้วยเวอร์ชัน + suffix
    m3 = _SEMVER_RE.search(value)
    if m3:
        return (plugin, m3.group("ver"))

    return (plugin, None)


def parse_whatweb_output(raw_output: str) -> List[WhatWebFinding]:
    """
    Parse output บรรทัดเดียวของ whatweb:
    http://x [200 OK] HTTPServer[nginx/1.19.0], PHP[5.6.40], ...
    """
    findings: list[WhatWebFinding] = []
    cleaned = strip_ansi(raw_output)
    for m in _BRACKET_TOKEN.finditer(cleaned):
        plugin = (m.group("plugin") or "").strip()
        value = (m.group("value") or "").strip()
        if not plugin or not value:
            continue

        product, version = _normalize_product_version(plugin, value)
        query = f"{product} {version}".strip() if version else product

        findings.append(
            WhatWebFinding(plugin=plugin, value=value, product=product, version=version, query=query)
        )
    return findings


def exploit_db_search_link(query: str) -> str:
    """
    ทำลิงก์ค้นหา Exploit-DB (ใช้เป็น starting point แทน CVE API).
    """
    # Exploit-DB รับ ident แบบ space เป็น +
    ident = query.replace(" ", "+")
    return f"https://www.exploit-db.com/search?ident={ident}"


def filter_versioned_findings(findings: Iterable[WhatWebFinding]) -> List[WhatWebFinding]:
    """
    เก็บเฉพาะ finding ที่ "น่าจะมีเวอร์ชัน" เพื่อไปเช็ค CVE ง่ายขึ้น
    heuristics: มีเลขอย่างน้อย 1 ตัว หรือมี slash (nginx/1.2.3)
    """
    blacklist_plugins = {
        "Country",
        "IP",
        "Email",
        "Title",
        "Script",
        "ActiveX",
        "Object",
    }
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    out: list[WhatWebFinding] = []
    for f in findings:
        if f.plugin in blacklist_plugins:
            continue
        if "@" in f.value:
            continue
        if ip_re.match(f.value):
            continue
        # ต้องมีตัวอักษรด้วย ไม่งั้นจะเป็นแต่เลขเวอร์ชันล้วนๆ
        if not re.search(r"[A-Za-z]", f.query):
            continue
        if f.version and re.search(r"\d", f.version):
            out.append(f)
    return out

