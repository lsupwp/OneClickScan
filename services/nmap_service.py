"""
Nmap Service - สแกนพอร์ต/บริการและหา CVE เบื้องต้น
"""
import re
import subprocess
from urllib.parse import urlparse
from typing import Optional


def get_cve_info(service_name: str, version: str) -> str:
    """สร้าง link สำหรับค้นหา CVE/Exploit (Exploit-DB)."""
    query = f"{service_name} {version}"
    return f"https://www.exploit-db.com/search?ident={service_name}+{version}"


def run_nmap_scan(target_host: str, top_ports: int = 20) -> str:
    """
    รัน nmap -sV --top-ports N กับ host
    Returns: raw output string
    """
    # ดึง hostname ถ้าได้ URL มา (ไม่มี scheme ก็ได้)
    if "://" in target_host:
        parsed = urlparse(target_host)
        target_host = parsed.netloc or parsed.path.split("/")[0]
    if not target_host:
        raise ValueError("Invalid target_host")

    cmd = ["nmap", "-sV", "-Pn", "--top-ports", str(top_ports), target_host]
    try:
        result = subprocess.check_output(cmd, text=True, timeout=300)
        return result
    except FileNotFoundError:
        raise RuntimeError("nmap not found. Install nmap.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("nmap timed out.")
    except Exception as e:
        raise RuntimeError(f"nmap failed: {e}") from e


def parse_nmap_services(nmap_output: str) -> list[tuple[str, str, str]]:
    """
    Parse nmap -sV output เป็น (port/tcp, service_name, version_info).
    """
    lines = nmap_output.split("\n")
    results = []
    for line in lines:
        if "open" not in line or "  " not in line:
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 3:
            port_service = parts[0]   # e.g. 80/tcp
            service_name = parts[2]   # e.g. http
            version_info = parts[3] if len(parts) > 3 else parts[2]
            results.append((port_service, service_name, version_info))
    return results
