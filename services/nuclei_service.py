"""
Nuclei Service — รัน nuclei template scan บน target URL
รองรับ:
  - template tags (cve, exposure, misconfig, default-login, sqli, xss, ...)
  - severity filter (critical, high, medium, low, info)
  - cookie / custom headers สำหรับ authenticated scan
  - streaming output (พิมพ์ผลแบบ real-time)
  - parse ผลลัพธ์เป็น structured findings
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ─── Data types ──────────────────────────────────────────────────────────────

@dataclass
class NucleiFinding:
    template_id: str
    severity:    str
    name:        str
    url:         str
    matched:     str = ""
    extra:       str = ""

    @property
    def is_vuln(self) -> bool:
        return self.severity.lower() in ("critical", "high", "medium")


# ─── Regex สำหรับ parse nuclei output ────────────────────────────────────────
# nuclei output format จริง:
#   [template-id] [protocol] [severity] URL [extra]
# ตัวอย่าง:
#   [CVE-2017-12615] [http] [high] http://target/poc.jsp?cmd=id
#   [CVE-2000-0114] [http] [medium] http://target/_vti_bin/... ["9.85"] [path="..."]
#   [drupal-user-enum-ajax] [http] [info] http://target/... [""OmQ2""]
_LINE_RE = re.compile(
    r"^\[(?P<tid>[^\]]+)\]\s+"          # [template-id]
    r"\[(?P<proto>[^\]]+)\]\s+"         # [protocol]  ← http / dns / tcp ...
    r"\[(?P<sev>[^\]]+)\]\s+"           # [severity]  ← critical / high / ...
    r"(?P<url>https?://\S+)"            # URL
    r"(?:\s+(?P<extra>.*))?$"           # optional trailing info
)


def parse_nuclei_output(raw: str) -> List[NucleiFinding]:
    findings: List[NucleiFinding] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        # strip ANSI color codes
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        # ข้าม info/warn lines ของ nuclei เอง ([INF] [WRN] [ERR])
        if re.match(r"^\[(INF|WRN|ERR|DBG)\]", line):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        tid   = m.group("tid").strip()
        sev   = m.group("sev").strip().lower()
        url   = m.group("url").strip()
        extra = (m.group("extra") or "").strip()
        # parse matched value จาก extra เช่น ["value"] [key="value"]
        matched_m = re.search(r'\["([^"]+)"\]|(?:^|\s)\[([^\]]+=[^\]]+)\]', extra)
        matched   = matched_m.group(1) or matched_m.group(2) if matched_m else ""
        # dedup ด้วย tid+url
        key = f"{tid}|{url}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(NucleiFinding(
            template_id=tid,
            severity=sev,
            name=tid,
            url=url,
            matched=matched,
            extra=extra,
        ))
    return findings


# ─── Main runner ─────────────────────────────────────────────────────────────

def run_nuclei(
    target_url: str,
    tags:            List[str]     | None = None,
    templates:       List[str]     | None = None,
    severity:        List[str]     | None = None,
    cookie:          str           | None = None,
    extra_headers:   dict          | None = None,
    timeout_seconds: int                  = 300,
    rate_limit:      int                  = 100,
    on_output_line:  Callable[[str], None] | None = None,
) -> str:
    """
    รัน nuclei แล้วคืน raw stdout

    Parameters
    ----------
    target_url      : URL เป้าหมาย
    tags            : เช่น ["cve","misconfig","exposure"]  (ถ้าไม่ระบุ → รัน default templates)
    templates       : path to specific template/dir (override tags)
    severity        : ["critical","high","medium","low","info"]
    cookie          : "PHPSESSID=xxx; security=low"
    extra_headers   : dict ของ headers เพิ่มเติม
    on_output_line  : callback รับทีละบรรทัด (สำหรับ real-time print)
    """
    cmd: List[str] = [
        "nuclei",
        "-u", target_url,
        "-silent",          # ไม่แสดง banner
        "-no-color",
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "1",
    ]

    if templates:
        for t in templates:
            cmd += ["-t", t]
    elif tags:
        cmd += ["-tags", ",".join(tags)]
    # ถ้าไม่ระบุ templates หรือ tags → รัน ALL templates (เหมือน nuclei -target URL)

    if severity:
        cmd += ["-severity", ",".join(severity)]
    # ถ้าไม่ระบุ severity → รันทุก severity (critical → info)

    # inject cookie / headers
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    if extra_headers:
        for k, v in extra_headers.items():
            if k.lower() != "cookie":
                cmd += ["-H", f"{k}: {v}"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        lines: List[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            if on_output_line:
                on_output_line(line)
        proc.wait(timeout=timeout_seconds)
        return "".join(lines)

    except FileNotFoundError:
        raise RuntimeError(
            "nuclei not found.\n"
            "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            "Then update templates: nuclei -update-templates"
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError("nuclei timed out.")


def findings_to_dict(findings: List[NucleiFinding]) -> list:
    """แปลง findings เป็น list of dict สำหรับ JSON export"""
    return [
        {
            "template_id": f.template_id,
            "severity":    f.severity,
            "name":        f.name,
            "url":         f.url,
            "matched":     f.matched,
        }
        for f in findings
    ]


def save_nuclei_json(findings: List[NucleiFinding], output_path: str) -> None:
    """บันทึก findings เป็น JSON file"""
    import json, pathlib
    data = {
        "total": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.severity == sev])
            for sev in ("critical", "high", "medium", "low", "info")
            if any(f.severity == sev for f in findings)
        },
        "findings": findings_to_dict(findings),
    }
    pathlib.Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(output_path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def print_nuclei_results(findings: List[NucleiFinding]) -> None:
    """แสดงผล findings แบบ structured จัดกลุ่มตาม severity"""
    if not findings:
        print("  No nuclei findings.")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings  = sorted(findings, key=lambda f: sev_order.get(f.severity, 9))

    by_sev: dict[str, list[NucleiFinding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    sev_icon  = {"critical": "[CRITICAL]", "high": "[HIGH]",
                 "medium": "[MEDIUM]",   "low":  "[LOW]", "info": "[INFO]"}

    total = len(findings)
    print(f"\n  Total findings: {total}")

    for sev in ("critical", "high", "medium", "low", "info"):
        items = by_sev.get(sev)
        if not items:
            continue
        icon = sev_icon.get(sev, f"[{sev.upper()}]")
        print(f"\n  {icon} — {len(items)} finding(s)")
        for f in items:
            print(f"    {f.template_id:<45} {f.url}")
            if f.matched:
                print(f"      matched: {f.matched}")

    # รายการ severity ที่ไม่รู้จัก (กัน edge case)
    for sev, items in by_sev.items():
        if sev not in sev_order:
            print(f"\n  [{sev.upper()}] — {len(items)} finding(s)")
            for f in items:
                print(f"    {f.template_id:<45} {f.url}")
