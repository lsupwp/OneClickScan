"""
DAVTest Service — ตรวจสอบว่า paths ที่ค้นพบ (จาก Katana/Gobuster)
รองรับ WebDAV PUT หรือ method upload อื่นๆ หรือไม่

Flow:
  1. โหลด path patterns จาก wordlist/path.txt
  2. filter discovered paths เฉพาะที่ตรงกับ pattern
  3. ส่ง OPTIONS → อ่าน Allow header
  4. ถ้า PUT อยู่ใน Allow → ลอง PUT ไฟล์ทดสอบ (.txt)
  5. ตรวจสอบ response → ถ้า 2xx → บันทึก finding
  6. ลบไฟล์ทดสอบ (DELETE) เพื่อ cleanup
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
_TEST_CONTENT = b"OneClickScanV2-davtest-probe"


@dataclass
class DavFinding:
    url:             str
    allowed_methods: List[str]
    put_success:     bool   = False
    put_status:      Optional[int] = None
    delete_status:   Optional[int] = None
    notes:           List[str] = field(default_factory=list)


def load_dav_patterns(wordlist_path: str) -> List[str]:
    """โหลด path patterns จากไฟล์ (หนึ่ง path ต่อบรรทัด)"""
    try:
        with open(wordlist_path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []


def filter_dav_paths(discovered: List[str], patterns: List[str]) -> List[str]:
    """
    คืน paths จาก discovered ที่ path component ตรงกับ pattern ใดๆ ใน wordlist
    เช่น pattern '/dav/' match 'http://target/dav/'
    """
    matches: List[str] = []
    seen: set[str] = set()
    for url in discovered:
        if url in seen:
            continue
        path = urlparse(url).path.lower()
        for pat in patterns:
            pat_lower = pat.lower().rstrip("/")
            if pat_lower in path:
                matches.append(url)
                seen.add(url)
                break
    return matches


def _options(url: str, headers: dict, timeout: int) -> List[str]:
    """ส่ง OPTIONS แล้วคืน list ของ methods ที่ server อนุญาต"""
    try:
        r = requests.options(url, headers=headers, timeout=timeout, verify=False)
        allow = r.headers.get("Allow", "") or r.headers.get("DAV", "")
        dav   = r.headers.get("DAV", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if dav:
            methods.append(f"DAV:{dav.strip()}")
        return methods
    except Exception:
        return []


def _put_test(url: str, headers: dict, timeout: int) -> tuple[int, str]:
    """PUT ไฟล์ทดสอบ → คืน (status_code, test_file_url)"""
    test_name = f"ocs_probe_{uuid.uuid4().hex[:8]}.txt"
    test_url  = url.rstrip("/") + "/" + test_name
    try:
        r = requests.put(test_url, data=_TEST_CONTENT, headers=headers,
                         timeout=timeout, verify=False)
        return r.status_code, test_url
    except Exception:
        return -1, test_url


def _delete_test(test_url: str, headers: dict, timeout: int) -> int:
    """DELETE ไฟล์ทดสอบเพื่อ cleanup"""
    try:
        r = requests.delete(test_url, headers=headers, timeout=timeout, verify=False)
        return r.status_code
    except Exception:
        return -1


def run_davtest(
    base_url: str,
    discovered_paths: List[str],
    wordlist_path: str,
    session_headers: Optional[dict] = None,
    timeout: int = 10,
) -> List[DavFinding]:
    """
    Main entry point.
    คืน list ของ DavFinding สำหรับทุก path ที่ตรวจแล้ว
    (รวมถึง paths ที่ OPTIONS สำเร็จแม้ PUT จะไม่ได้)
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    patterns = load_dav_patterns(wordlist_path)
    if not patterns:
        return []

    # เพิ่ม base_url เข้าไปด้วยเพื่อ cover root-level dav endpoints
    all_paths = list(dict.fromkeys(discovered_paths))

    # เพิ่ม paths จาก pattern ที่อาจไม่ถูก katana/gobuster ค้นเจอ
    base = base_url.rstrip("/")
    for pat in patterns:
        candidate = base + pat
        if candidate not in all_paths:
            all_paths.append(candidate)

    candidates = filter_dav_paths(all_paths, patterns)
    if not candidates:
        return []

    hdrs = {"User-Agent": _UA}
    if session_headers:
        hdrs.update(session_headers)

    findings: List[DavFinding] = []

    for url in candidates:
        methods = _options(url, hdrs, timeout)
        if not methods:
            # ลอง HEAD ก่อน ถ้า OPTIONS ไม่ตอบ
            try:
                r = requests.head(url, headers=hdrs, timeout=timeout, verify=False)
                if r.status_code == 404:
                    continue
            except Exception:
                continue

        finding = DavFinding(url=url, allowed_methods=methods)

        upload_methods = {"PUT", "MKCOL", "COPY", "MOVE", "PROPPATCH"}
        has_put = any(m in upload_methods for m in methods) or not methods

        if has_put or "PUT" in methods:
            status, test_url = _put_test(url, hdrs, timeout)
            finding.put_status = status
            if status in (200, 201, 204):
                finding.put_success = True
                finding.notes.append(f"PUT succeeded → {test_url}")
                del_status = _delete_test(test_url, hdrs, timeout)
                finding.delete_status = del_status
                if del_status in (200, 204):
                    finding.notes.append("DELETE cleanup OK")
                else:
                    finding.notes.append(f"DELETE cleanup failed (status {del_status}) — file may persist!")
            elif status == 401:
                finding.notes.append("PUT → 401 Unauthorized (auth required)")
            elif status == 403:
                finding.notes.append("PUT → 403 Forbidden")
            elif status == -1:
                finding.notes.append("PUT → connection error")

        if methods or finding.put_status is not None:
            findings.append(finding)

    return findings


def print_davtest_results(findings: List[DavFinding]) -> None:
    """แสดงผล findings ในรูปแบบ structured"""
    if not findings:
        print("  No DAV-like paths found or tested.")
        return

    vuln   = [f for f in findings if f.put_success]
    others = [f for f in findings if not f.put_success]

    if vuln:
        print(f"\n  [!] VULNERABLE — PUT upload allowed on {len(vuln)} path(s):")
        for f in vuln:
            print(f"  [CRITICAL] {f.url}")
            print(f"    Methods : {', '.join(f.allowed_methods) or 'unknown'}")
            print(f"    PUT     : {f.put_status}")
            for note in f.notes:
                print(f"    Note    : {note}")
    else:
        print(f"  [+] {len(findings)} DAV path(s) found — PUT not allowed (or blocked).")

    for f in others[:10]:
        methods_str = ", ".join(f.allowed_methods) if f.allowed_methods else "—"
        put_str     = str(f.put_status) if f.put_status is not None else "not tested"
        print(f"  [-] {f.url}  methods=[{methods_str}]  PUT={put_str}")
        for note in f.notes:
            print(f"      {note}")
