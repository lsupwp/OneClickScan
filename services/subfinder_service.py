"""
Subfinder Service - หา subdomain จาก root domain
ดึง root domain จาก URL (ตัด subdomain ออกเหลือแค่ domain + TLD) แล้วส่งให้ subfinder
"""
from __future__ import annotations

import subprocess
from urllib.parse import urlparse
from typing import List


def get_root_domain(url_or_host: str) -> str:
    """
    จาก URL หรือ hostname เช่น http://testphp.vulnweb.com/ หรือ testphp.vulnweb.com
    คืน root domain เช่น vulnweb.com (เอา index สุดท้ายก่อน TLD มาประกอบกับ TLD)
    """
    s = (url_or_host or "").strip()
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.netloc or parsed.path.split("/")[0] or s
    else:
        host = s.split("/")[0].split("?")[0]
    host = host.lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 2:
        # root = ส่วนก่อน TLD (index สุดท้ายของส่วนที่ไม่ใช่ TLD) + TLD
        # เช่น testphp.vulnweb.com -> vulnweb.com
        return ".".join(parts[-2:])
    return host


def run_subfinder(
    domain: str,
    silent: bool = True,
    timeout_seconds: int = 300,
) -> List[str]:
    """
    รัน subfinder -d <domain> คืน list ของ subdomain ที่เจอ
    """
    if not domain or not domain.strip():
        return []
    domain = domain.strip()
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    try:
        out = subprocess.check_output(
            cmd,
            text=True,
            timeout=timeout_seconds,
            stderr=subprocess.STDOUT,
        )
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return lines
    except FileNotFoundError:
        raise RuntimeError(
            "subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("subfinder timed out.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"subfinder failed: {e.output.strip()}") from e
