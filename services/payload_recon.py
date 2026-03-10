"""
Payload Recon Service - ดึง Forms และ URL params จาก URLs
ใช้ข้อมูลจาก path_recon (list ของ URLs) มาวิเคราะห์
รองรับ multithread สำหรับ map_forms หลาย URL พร้อมกัน
และรองรับหน้า SPA/hash routes ผ่าน browser-rendered DOM
"""
import re

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional


def extract_url_params(url: str) -> Optional[Dict[str, str]]:
    """ดึง Parameter จาก URL เปล่าๆ ที่ไม่มี Form (query string only)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if params:
        return {k: v[0] for k, v in params.items()}
    return None


def _infer_field_name(tag: Any, index: int) -> str:
    for attr in ("name", "formcontrolname", "id", "placeholder", "aria-label"):
        value = tag.get(attr)
        if value:
            cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value).strip()).strip("_")
            if cleaned:
                return cleaned
    return f"field_{index}"


def _extract_forms_from_html(source_url: str, html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    mapped_data: List[Dict[str, Any]] = []
    request_url = source_url.split("#", 1)[0]

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        full_url = urljoin(request_url, action)
        # strip URL fragment (#) — action="#" หรือ action="" หมายถึง current page
        full_url = full_url.split("#")[0] or request_url
        method = (form.get("method") or "get").upper()
        parsed_url = urlparse(full_url)
        query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
        body_params: Dict[str, str] = {}
        for idx, ipt in enumerate(form.find_all(["input", "textarea", "select"])):
            name = _infer_field_name(ipt, idx)
            body_params[name] = ipt.get("value") or ""
        mapped_data.append(
            {
                "target_action": full_url.split("?")[0],
                "method": method,
                "query_params": query_params,
                "body_params": body_params,
            }
        )

    if mapped_data:
        return mapped_data

    # SPA บางตัวไม่มี <form> แต่มี input/password + button อยู่ใน rendered DOM
    inputs = soup.find_all(["input", "textarea", "select"])
    password_inputs = soup.find_all("input", {"type": "password"})
    if inputs and password_inputs:
        body_params: Dict[str, str] = {}
        for idx, ipt in enumerate(inputs):
            name = _infer_field_name(ipt, idx)
            body_params[name] = ipt.get("value") or ""
        parsed_url = urlparse(request_url)
        query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
        mapped_data.append(
            {
                "target_action": source_url.split("?")[0],
                "method": "POST",
                "query_params": query_params,
                "body_params": body_params,
            }
        )
    return mapped_data


def _render_with_playwright(url: str, timeout: int = 10) -> Optional[str]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            page.wait_for_timeout(1500)
            html = page.content()
            browser.close()
            return html
    except Exception:
        return None


def map_forms(
    url: str,
    timeout: int = 5,
    extra_headers: Optional[Dict[str, str]] = None,
    session: Optional[requests.Session] = None,
) -> List[Dict[str, Any]]:
    """ดึงข้อมูลจาก <form> tags ในหน้า URL นั้น
    extra_headers: ส่ง Cookie/User-Agent เพื่อ fetch หน้า authenticated ได้ถูกต้อง
    session: shared requests.Session เพื่อ keep cookies ไว้ระหว่าง requests (ใช้ cookie jar จริงๆ)
    Returns [] ถ้า 404 หรือถ้าถูก redirect ไป login page (session expire)
    """
    try:
        target_url = url.split("#", 1)[0]
        req = session or requests
        # session มี headers แล้ว (Cookie, User-Agent) — ไม่ต้องส่ง extra_headers ซ้ำเพื่อป้องกัน dup
        hdrs = {} if (session is not None) else (extra_headers or {})
        response = req.get(target_url, timeout=timeout, headers=hdrs, allow_redirects=True)

        # ข้าม 404
        if response.status_code == 404:
            return []

        # ใช้ URL จริงหลัง redirect เป็นฐาน resolve form action
        final_url = response.url or target_url

        # ถ้า redirect ไปหน้า login → session expire → ข้ามหน้านี้
        orig_path = urlparse(target_url).path.lower().rstrip("/")
        final_path = urlparse(final_url).path.lower().rstrip("/")
        if orig_path != final_path and any(x in final_path for x in ("/login", "/signin", "/auth")):
            return []

        html = response.text or ""
        mapped_data = _extract_forms_from_html(final_url, html)
        if mapped_data:
            return mapped_data

        # ถ้าเป็น route แบบ #/login หรือหน้า JS-heavy ให้ลอง render DOM จริง
        if "#/" in url or "ng-version" in html or "<app-root" in html:
            rendered_html = _render_with_playwright(url, timeout=max(timeout, 10))
            if rendered_html:
                mapped_data = _extract_forms_from_html(final_url, rendered_html)
        return mapped_data
    except Exception:
        return []


def _process_one_path(
    path: str,
    extra_headers: Optional[Dict[str, str]] = None,
    session: Optional[requests.Session] = None,
) -> tuple[str, List[Dict[str, Any]], Optional[Dict[str, str]]]:
    """Process one URL: return (path, forms, url_params)."""
    forms = map_forms(path, extra_headers=extra_headers, session=session)
    params = extract_url_params(path)
    return (path, forms, params)


def run_payload_recon(
    paths: List[str],
    max_workers: int = 8,
    extra_headers: Optional[Dict[str, str]] = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    รับ list ของ paths (จาก Katana) แล้วจัดกลุ่มเป็น:
    - grouped_forms: HTML forms (method|action|params)
    - url_entry_points: URL ที่มี query params แต่ไม่มี form
    ใช้ multithread เรียก map_forms แยกต่อ path
    """
    grouped_forms: Dict[str, Any] = {}
    url_entry_points: Dict[str, Any] = {}
    # base_path -> merged params + example_urls
    inferred_by_base: Dict[str, Any] = {}

    # ใช้ shared session เพื่อ keep cookies ระหว่าง requests ต่างๆ — สำคัญสำหรับ authenticated crawl
    # ใช้ headers["Cookie"] โดยตรง (ไม่ใช้ cookie jar) เพราะ jar ต้องการ domain match
    shared_session = requests.Session()
    if extra_headers:
        shared_session.headers.update(extra_headers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(_process_one_path, p, extra_headers, shared_session): p for p in paths}
        for future in as_completed(future_to_path):
            try:
                path, forms_found, u_params = future.result()
            except Exception:
                continue
            # 1. HTML Forms
            for f in forms_found:
                q_keys = sorted((f.get("query_params") or {}).keys())
                b_keys = sorted((f.get("body_params") or {}).keys())
                sig = f"{f['method']}|{f['target_action']}|Q{q_keys}|B{b_keys}"
                if sig not in grouped_forms:
                    grouped_forms[sig] = {"details": f, "paths": set()}
                grouped_forms[sig]["paths"].add(path)
            # 2. URL params (inferred)
            if u_params:
                base_path = path.split("?")[0]
                if base_path not in inferred_by_base:
                    inferred_by_base[base_path] = {"params": {}, "example_urls": set()}
                # merge params (ไม่ overwrite ถ้ามี key ซ้ำ)
                for k, v in u_params.items():
                    inferred_by_base[base_path]["params"].setdefault(k, v)
                inferred_by_base[base_path]["example_urls"].add(path)

    # 3) Combine: ถ้า base_path เดียวกันมีทั้ง form และ inferred query ให้รวมเข้า form แล้วลบออกจาก query-only list
    used_bases: set[str] = set()
    for sig, data in grouped_forms.items():
        details = data["details"]
        base = details.get("target_action")
        if not base:
            continue
        inferred = inferred_by_base.get(base)
        if not inferred:
            continue
        # merge query params
        q = details.get("query_params") or {}
        for k, v in inferred["params"].items():
            q.setdefault(k, v)
        details["query_params"] = q
        # เก็บ sample URLs ไว้โชว์ได้
        details["example_urls"] = sorted(list(inferred["example_urls"]))[:5]
        used_bases.add(base)

    # 4) Build query-only entry points (เฉพาะที่ไม่มี form)
    for base_path, info in inferred_by_base.items():
        if base_path in used_bases:
            continue
        params = info["params"]
        param_sig = f"GET|{base_path}|{sorted(params.keys())}"
        url_entry_points[param_sig] = {
            "base_path": base_path,
            "params": params,
            "example_urls": info["example_urls"],
        }

    return grouped_forms, url_entry_points
