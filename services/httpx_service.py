"""
Httpx Service - probe URLs/hosts แล้วคืนเฉพาะอันที่ alive (เข้าได้)
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List


def _httpx_bin() -> str:
    """
    หา httpx binary ที่ถูกต้อง (Go binary ไม่ใช่ Python package)
    ลำดับ:
      1. $GOPATH/bin/httpx  หรือ  ~/go/bin/httpx
      2. shutil.which("httpx") — แต่ตรวจว่าเป็น Go binary (ไม่ใช่ Python wrapper)
    """
    candidates = []
    # GOPATH/bin
    gopath = os.environ.get("GOPATH", "")
    if gopath:
        candidates.append(str(Path(gopath) / "bin" / "httpx"))
    # ~/go/bin (default go install path)
    candidates.append(str(Path.home() / "go" / "bin" / "httpx"))

    for p in candidates:
        if Path(p).is_file() and os.access(p, os.X_OK):
            return p

    # fallback: ใช้ PATH แต่ warn ว่าอาจชนกับ Python httpx
    which = shutil.which("httpx")
    if which:
        return which

    raise RuntimeError(
        "httpx (Go binary) not found.\n"
        "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
        "Expected at: ~/go/bin/httpx"
    )


def run_httpx(
    hosts: List[str],
    silent: bool = True,
    timeout_seconds: int = 180,
) -> List[str]:
    """
    ส่ง list ของ hostname หรือ URL เข้า stdin ของ httpx
    httpx จะ probe ทั้ง HTTP และ HTTPS อัตโนมัติ
    คืน list ของ URL ที่ alive (มี response)
    """
    if not hosts:
        return []

    # strip scheme ออก → ส่ง bare hostname ให้ httpx probe ทั้ง http+https เอง
    # ถ้าส่ง http:// เดียว httpx จะไม่ลอง https → พลาด subdomains ที่ redirect HTTPS
    def _strip_scheme(u: str) -> str:
        u = u.strip()
        for pfx in ("https://", "http://"):
            if u.startswith(pfx):
                u = u[len(pfx):]
        return u.rstrip("/")

    lines = [_strip_scheme(u) for u in hosts if u and u.strip()]
    lines = [l for l in lines if l]
    if not lines:
        return []

    input_text = "\n".join(lines) + "\n"
    cmd = [
        _httpx_bin(),
        "-silent",          # ไม่แสดง banner
        "-follow-redirects", # ตาม redirect (302 → alive)
        "-threads", "50",   # probe parallely
        "-timeout", "10",   # per-host timeout (วินาที)
        "-retries", "1",
        "-no-color",
    ]
    try:
        out = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        result = [ln.strip() for ln in (out.stdout or "").splitlines() if ln.strip()]
        return result
    except (FileNotFoundError, RuntimeError) as e:
        raise RuntimeError(str(e) or
            "httpx (Go binary) not found.\n"
            "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("httpx timed out.")
