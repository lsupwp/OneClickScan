"""
Httpx Service - probe URLs/hosts แล้วคืนเฉพาะอันที่ alive (เข้าได้)
"""
from __future__ import annotations

import subprocess
from typing import List


def run_httpx(
    urls: List[str],
    silent: bool = True,
    timeout_seconds: int = 120,
) -> List[str]:
    """
    ส่ง list ของ URL หรือ host เข้า stdin ของ httpx
    คืนเฉพาะ URL ที่ alive (มี response)
    """
    if not urls:
        return []
    lines = [u.strip() for u in urls if u and u.strip()]
    if not lines:
        return []
    input_text = "\n".join(lines) + "\n"
    cmd = ["httpx", "-silent"] if silent else ["httpx"]
    try:
        out = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        # httpx พิมพ์เฉพาะ URL ที่ alive ออกมา (บรรทัดละ URL)
        result = [ln.strip() for ln in (out.stdout or "").splitlines() if ln.strip()]
        return result
    except FileNotFoundError:
        raise RuntimeError(
            "httpx not found. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("httpx timed out.")
