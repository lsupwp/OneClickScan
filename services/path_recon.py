"""
Path Recon Service - ใช้ Katana คrawl URLs จาก target
และเสริมการหา SPA/hash routes เช่น /#/login จาก HTML/JS bundles
"""
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def discover_links_from_authenticated_page(
    page_url: str,
    extra_headers: Optional[Union[Dict[str, str], List[Tuple[str, str]]]] = None,
    timeout: int = 15,
    same_origin_only: bool = True,
) -> List[str]:
    """
    โหลดหน้า page_url ด้วย session (Cookie จาก extra_headers) แล้วดึงทุกลิงก์จาก <a href> และ <form action>
    คืนรายการ absolute URL — ใช้เมื่อมี cookie เพื่อให้ได้ path จากเมนู/sidebar จริง ไม่ต้อง hardcode
    """
    if isinstance(extra_headers, dict):
        headers = dict(extra_headers)
    elif extra_headers:
        headers = dict(extra_headers)
    else:
        headers = {}
    parsed_base = urlparse(page_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    found: List[str] = []
    seen: set[str] = set()

    try:
        resp = requests.get(page_url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        html = resp.text or ""
    except Exception:
        return []

    # ใช้ URL จริงหลัง redirect เป็นฐาน (เช่น / -> /dvwa/ แล้วลิงก์ relative จะ resolve ถูก)
    base_for_links = resp.url
    soup = BeautifulSoup(html, "html.parser")

    # ถ้าหน้ามี <base href="..."> ใช้เป็นฐานสำหรับ relative links
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_href = (base_tag.get("href") or "").strip()
        if base_href:
            base_for_links = urljoin(resp.url, base_href)

    for tag in soup.find_all("a", href=True):
        href = (tag.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        full = urljoin(base_for_links, href)
        if same_origin_only and not full.startswith(origin):
            continue
        if full not in seen:
            seen.add(full)
            found.append(full)

    for form in soup.find_all("form", action=True):
        action = (form.get("action") or "").strip()
        if not action:
            continue
        full = urljoin(base_for_links, action)
        if same_origin_only and not full.startswith(origin):
            continue
        if full not in seen:
            seen.add(full)
            found.append(full)

    return found


_HASH_ROUTE_RE = re.compile(r'(?:"|\')(?P<route>/?#/[A-Za-z0-9_\-./?=&%]+)(?:"|\')')


def discover_hash_routes(target_url: str, timeout: int = 10) -> List[str]:
    """
    หาเส้นทางแบบ SPA/hash routes เช่น http://host/#/login
    โดยอ่านจาก HTML หน้าแรกและ JS bundles ที่อ้างอิงอยู่
    """
    discovered: list[str] = []
    seen: set[str] = set()

    def _add(route: str) -> None:
        route = (route or "").strip()
        if not route:
            return
        if route.startswith("/#/"):
            full = urljoin(target_url, route)
        elif route.startswith("#/"):
            full = target_url.rstrip("/") + "/" + route
        else:
            return
        if full not in seen:
            seen.add(full)
            discovered.append(full)

    try:
        response = requests.get(target_url, timeout=timeout)
        html = response.text or ""
        for match in _HASH_ROUTE_RE.finditer(html):
            _add(match.group("route"))

        soup = BeautifulSoup(html, "html.parser")
        script_urls: list[str] = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                script_urls.append(urljoin(target_url, src))

        for script_url in script_urls:
            try:
                js_resp = requests.get(script_url, timeout=timeout)
                js_text = js_resp.text or ""
            except Exception:
                continue
            for match in _HASH_ROUTE_RE.finditer(js_text):
                _add(match.group("route"))
    except Exception:
        return []

    return discovered


def run_katana(
    target_url: str,
    silent: bool = True,
    js_crawl: bool = True,
    extra_headers: Optional[Union[Dict[str, str], List[Tuple[str, str]]]] = None,
    depth: int = 5,
) -> List[str]:
    """
    รัน Katana เพื่อ crawl paths จาก target URL
    extra_headers: Cookie, User-Agent ฯลฯ สำหรับ authenticated crawl (เช่นจาก active_session.json)
    depth: ความลึกของการ crawl (default 5)
    Returns: list ของ path strings
    """
    args = ["katana", "-u", target_url, "-d", str(depth)]
    if silent:
        args.append("-silent")
    if js_crawl:
        args.append("-jc")

    header_file_handle: Optional[tempfile.NamedTemporaryFile] = None
    if extra_headers:
        if isinstance(extra_headers, dict):
            extra_headers = list(extra_headers.items())
        # Katana รองรับ -H รับไฟล์ (header:value ต่อบรรทัด) — ใช้ไฟล์เพื่อให้ Cookie ที่มี ; ส่งได้ถูกต้อง
        lines = [f"{name}: {value}" for name, value in extra_headers if name and value]
        if lines:
            header_file_handle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="katana_headers_", delete=False, encoding="utf-8"
            )
            header_file_handle.write("\n".join(lines))
            header_file_handle.close()
            args.extend(["-H", header_file_handle.name])

    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        paths: List[str] = []
        seen: set[str] = set()
        for line in process.stdout or []:
            path = line.strip()
            if path and path not in seen:
                seen.add(path)
                paths.append(path)
        process.wait()
        # เสริม route แบบ SPA/hash เช่น /#/login สำหรับแอป frontend
        for route in discover_hash_routes(target_url):
            if route not in seen:
                seen.add(route)
                paths.append(route)
        return paths
    except FileNotFoundError:
        raise RuntimeError("Katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
    except Exception as e:
        raise RuntimeError(f"Katana failed: {e}") from e
    finally:
        if header_file_handle is not None and os.path.exists(header_file_handle.name):
            try:
                os.unlink(header_file_handle.name)
            except OSError:
                pass
