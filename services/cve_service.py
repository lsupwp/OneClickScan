"""
CVE lookup service (best-effort) by free public API.

ใช้สำหรับช่วยสรุป CVE ที่เกี่ยวกับ query (เช่น nginx/1.19.0, PHP 5.6.40)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import requests


@dataclass(frozen=True)
class CVEItem:
    cve: str
    summary: str
    url: str


def search_cves_by_query(query: str, limit: int = 5, timeout: int = 15) -> List[CVEItem]:
    """
    ค้นหา CVE ด้วย cve.circl.lu แบบ query search.
    Endpoint: /api/search/<query>
    """
    q = query.strip()
    if not q:
        return []

    url = f"https://cve.circl.lu/api/search/{q}"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results: list[CVEItem] = []
    # response shape โดยทั่วไปมี key "results": [{ "id": "CVE-....", "summary": "..."}]
    items = data.get("results") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []

    for item in items:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("id") or item.get("cve") or ""
        summary = item.get("summary") or item.get("description") or ""
        cve_id = str(cve_id).strip()
        if not cve_id.startswith("CVE-"):
            continue
        results.append(
            CVEItem(
                cve=cve_id,
                summary=str(summary).strip(),
                url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            )
        )
        if len(results) >= limit:
            break

    return results

