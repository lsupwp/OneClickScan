#!/usr/bin/env python3
"""
OneClickScan V2 - Single entry point สำหรับ web pentest
ใช้ options เลือกได้ว่าให้รัน path recon (Katana), payload recon (map_forms), หรือ nmap
รันแบบ multithread และรอ task ที่ต้องใช้ข้อมูลจากเพื่อนให้เสร็จก่อน
"""
from pathlib import Path

# โหลด .env จากโฟลเดอร์โปรเจกต์ (ที่เดียวกับ main.py)
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(_env_path)
except ImportError:
    pass

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from urllib.parse import urljoin

from services.path_recon import run_katana, discover_links_from_authenticated_page
from services.payload_recon import run_payload_recon
from services.nmap_service import run_nmap_scan, parse_nmap_services, get_cve_info
from services.whatweb_service import (
    run_whatweb,
    parse_whatweb_output,
    filter_versioned_findings,
    exploit_db_search_link,
)
from services.cve_service import search_cves_by_query
from services.gobuster_service import run_gobuster_dir, parse_gobuster_output
from services.subfinder_service import get_root_domain, run_subfinder
from services.httpx_service import run_httpx
from services.ai_triage_service import (
    run_ai_triage,
    apply_real_base_to_commands,
    run_ai_triage_round2,
    build_post_auth_triage_fallback,
)
from services.local_triage_service import run_local_triage


def _load_cookie_headers(cookie_file: str | None):
    """โหลด Cookie (และถ้ามี User-Agent) จากไฟล์ active_session.json เป็น list of (name, value)."""
    if not cookie_file:
        return None
    from pathlib import Path
    p = Path(cookie_file).resolve()
    if not p.exists():
        print(f"[!] Cookie file not found: {p}", file=sys.stderr)
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load cookie file: {e}", file=sys.stderr)
        return None
    out = []
    if isinstance(data, dict) and data.get("Cookie"):
        out.append(("Cookie", data["Cookie"].strip()))
    elif isinstance(data, dict) and data.get("cookies"):
        cookie_str = "; ".join(
            f"{c.get('name','')}={c.get('value','')}" for c in data["cookies"] if c.get("name")
        )
        if cookie_str:
            out.append(("Cookie", cookie_str))
    if not out:
        print("[!] No Cookie key in session file.", file=sys.stderr)
        return None
    out.append((
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    ))
    print(f"[*] Loaded session from {p.name} for authenticated crawl ({len(out)} headers)")
    return out


def _ensure_scheme(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def _print_path_recon(paths: list[str]) -> None:
    print("\n" + "=" * 80)
    print("PATH RECON (Katana)")
    print("=" * 80)
    print(f"Total paths: {len(paths)}")
    for p in paths:
        print(f"  {p}")


def _print_payload_recon(grouped_forms: dict, url_entry_points: dict) -> None:
    print("\n" + "=" * 80)
    print("CATEGORY 1: HTML FORMS (POST/GET)")
    print("=" * 80)
    for sig, data in grouped_forms.items():
        f = data["details"]
        print(f"\nFound in Paths: {list(data['paths'])}")
        print(f"  - Action: {f['target_action']} [{f['method']}]")
        print(f"  - Parameters: {f['body_params']}")
        if f.get("query_params"):
            print(f"  - Query String: {f['query_params']}")

    print("\n" + "=" * 80)
    print("CATEGORY 2: URL QUERY PARAMETERS (Inferred Forms)")
    print("=" * 80)
    if not url_entry_points:
        print("No URL parameters discovered.")
    for sig, data in url_entry_points.items():
        print(f"\nBase Path: {data['base_path']}")
        print(f"  - Parameters: {data['params']}")
        print(f"  - Sample URLs: {list(data['example_urls'])[:3]}")


def _print_nmap(result: str, parse_services: bool = True) -> None:
    print("\n" + "=" * 80)
    print("NMAP SERVICE SCAN")
    print("=" * 80)
    print(result)
    if parse_services:
        for port_svc, svc_name, version_info in parse_nmap_services(result):
            print(f"[+] Service: {port_svc} | {version_info}")
            print(f"    [>] CVE/Exploit: {get_cve_info(svc_name, version_info)}")


def _print_whatweb(raw_output: str, lookup_cve: bool = False, cve_limit: int = 5) -> None:
    print("\n" + "=" * 80)
    print("WHATWEB FINGERPRINT")
    print("=" * 80)
    print(raw_output.strip())

    findings = parse_whatweb_output(raw_output)
    versioned = filter_versioned_findings(findings)
    if not versioned:
        return

    print("\n" + "-" * 80)
    print("WHATWEB -> Exploit/CVE lookups (heuristic)")
    print("-" * 80)
    # ลด noise: unique query
    seen = set()
    for f in versioned:
        if not f.version:
            continue
        # dedupe จาก product+version (ลดซ้ำ HTTPServer nginx vs nginx)
        key = f"{f.product.lower()} {f.version}"
        if key in seen:
            continue
        seen.add(key)
        print(f"[+] {f.product} {f.version} (from {f.plugin}[{f.value}])")
        print(f"    [>] Check Exploits: {exploit_db_search_link(f.query)}")
        if lookup_cve:
            cves = search_cves_by_query(f.query, limit=cve_limit)
            if not cves:
                print("    [CVE] not found")
            else:
                for c in cves:
                    s = c.summary
                    if len(s) > 160:
                        s = s[:157] + "..."
                    print(f"    [CVE] {c.cve} - {s}")
                    print(f"          {c.url}")


def _print_gobuster(raw_output: str, base_url: str) -> None:
    print("\n" + "=" * 80)
    print("GOBUSTER DIR (Hidden paths)")
    print("=" * 80)
    findings = parse_gobuster_output(raw_output)
    # ดึงซ้ำ path ที่ต่างกันแค่ / ท้าย เช่น cgi-bin vs cgi-bin/
    shown_set: set[str] = set()
    shown_list: list[str] = []
    base = base_url.rstrip("/") + "/"
    for f in findings:
        # normalize: ตัด / ท้าย ยกเว้น root
        norm_path = f.path.rstrip("/") or f.path
        full = urljoin(base, norm_path)
        if full in shown_set:
            continue
        shown_set.add(full)
        shown_list.append(full)
    print(f"Total findings: {len(shown_list)}")
    for u in shown_list[:100]:
        print(f"  {u}")
    if len(shown_list) > 100:
        print(f"  ... and {len(shown_list) - 100} more")


def _print_subfinder(
    subdomains: list[str],
    root_domain: str,
    scheme: str = "http",
    alive_urls: list[str] | None = None,
) -> None:
    print("\n" + "=" * 80)
    print("SUBFINDER (Subdomains)")
    print("=" * 80)
    print(f"Root domain: {root_domain}")
    if alive_urls is not None:
        print(f"Total found: {len(subdomains)}  |  Alive (httpx): {len(alive_urls)}")
        for u in alive_urls[:200]:
            print(f"  {u}")
        if len(alive_urls) > 200:
            print(f"  ... and {len(alive_urls) - 200} more")
    else:
        print(f"Total: {len(subdomains)}")
        for sub in subdomains[:200]:
            print(f"  {scheme}://{sub}")
        if len(subdomains) > 200:
            print(f"  ... and {len(subdomains) - 200} more")


def run(options: argparse.Namespace) -> None:
    url = _ensure_scheme(options.url)
    paths: list[str] = []
    gobuster_paths: list[str] = []
    cookie_headers = _load_cookie_headers(getattr(options, "cookie_file", None))

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}

        # Nmap: ไม่พึ่งใคร รันคู่กับอย่างอื่นได้
        if options.nmap:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/")[0] or url
            futures["nmap"] = executor.submit(run_nmap_scan, host, options.nmap_ports)

        # WhatWeb: ไม่พึ่งใคร รันคู่กับอย่างอื่นได้
        if getattr(options, "whatweb", False):
            futures["whatweb"] = executor.submit(run_whatweb, url)

        # Gobuster: ไม่พึ่งใคร รันคู่กับอย่างอื่นได้ (ใช้ค่า default ภายใน ไม่ต้องมี option เยอะ)
        if getattr(options, "gobuster", False):
            wordlist = "/home/lsupwp/OneClickScanV2/SecLists/Discovery/Web-Content/common.txt"
            print(f"[*] Gobuster started: url={url} threads=20 wordlist={wordlist}")

            def _live(line: str) -> None:
                s = line.strip()
                if not s or "(Status:" not in s:
                    return
                print(f"[gobuster] {s}")

            futures["gobuster"] = executor.submit(
                run_gobuster_dir,
                target_url=url,
                wordlist_path=wordlist,
                threads=20,
                timeout_seconds=10,
                status_codes="200,204,301,302,307,401,403",
                status_codes_blacklist="",
                extensions=None,
                user_agent="Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36",
                follow_redirect=False,
                insecure_tls=True,
                random_agent=False,
                retry=False,
                retry_attempts=3,
                delay="0s",
                no_error=False,
                no_progress=True,
                force=True,
                quiet=False,
                on_output_line=_live,
                extra_headers=cookie_headers,
            )

        # Subfinder: ดึง root domain จาก URL แล้วรัน subfinder
        if getattr(options, "subfinder", False):
            root_domain = get_root_domain(url)
            if root_domain:
                print(f"[*] Subfinder started: root domain {root_domain}")
                futures["subfinder"] = executor.submit(run_subfinder, root_domain)

        # Path recon (Katana): ถ้าเปิด path-recon หรือ payload-recon ต้องรันเพื่อได้ paths
        need_paths = options.path_recon or options.payload_recon
        if need_paths:
            futures["path_recon"] = executor.submit(
                run_katana, url, True, True, cookie_headers, depth=5
            )

        # รอ WhatWeb (ถ้ามี)
        if "whatweb" in futures:
            try:
                whatweb_out = futures["whatweb"].result()
                _print_whatweb(whatweb_out, lookup_cve=options.whatweb_cve, cve_limit=options.whatweb_cve_limit)
            except Exception as e:
                print(f"[!] WhatWeb error: {e}", file=sys.stderr)

        # รอ Gobuster (ถ้ามี) แล้วเก็บ path ไปใช้กับ payload recon
        if "gobuster" in futures:
            try:
                gobuster_out = futures["gobuster"].result()
                _print_gobuster(gobuster_out, url)
                # แปลงผล gobuster เป็น full URLs แล้วเก็บไว้
                from urllib.parse import urljoin

                base = url.rstrip("/") + "/"
                for f in parse_gobuster_output(gobuster_out):
                    norm_path = f.path.rstrip("/") or f.path
                    full = urljoin(base, norm_path)
                    gobuster_paths.append(full)
            except Exception as e:
                print(f"[!] Gobuster error: {e}", file=sys.stderr)

        # รอ Subfinder (ถ้ามี) แล้วกรองด้วย httpx เฉพาะอันที่เข้าได้
        if "subfinder" in futures:
            try:
                subdomains = futures["subfinder"].result()
                scheme = urlparse(url).scheme or "http"
                urls_to_probe = [f"{scheme}://{s}" for s in subdomains]
                if urls_to_probe:
                    try:
                        alive_urls = run_httpx(urls_to_probe)
                        _print_subfinder(subdomains, get_root_domain(url), scheme, alive_urls=alive_urls)
                    except Exception as e:
                        print(f"[!] Httpx probe error (showing all): {e}", file=sys.stderr)
                        _print_subfinder(subdomains, get_root_domain(url), scheme)
                else:
                    _print_subfinder(subdomains, get_root_domain(url), scheme)
            except Exception as e:
                print(f"[!] Subfinder error: {e}", file=sys.stderr)

        # รอ Nmap (ถ้ามี)
        if "nmap" in futures:
            try:
                nmap_result = futures["nmap"].result()
                _print_nmap(nmap_result)
            except Exception as e:
                print(f"[!] Nmap error: {e}", file=sys.stderr)

        # รอ Path recon ก่อน (payload_recon ต้องใช้ paths จาก katana)
        if need_paths:
            try:
                paths = list(futures["path_recon"].result())
                if cookie_headers:
                    seen = set(paths)
                    # ดึงลิงก์จากหน้า authenticated จริง (เมนู/sidebar) — ใช้แค่ base ของ target ไม่ hardcode path
                    base_normalized = url.rstrip("/") + "/"
                    try:
                        for p in discover_links_from_authenticated_page(
                            base_normalized, cookie_headers, timeout=15
                        ):
                            if p not in seen:
                                seen.add(p)
                                paths.append(p)
                    except Exception:
                        pass
                if options.path_recon:
                    _print_path_recon(paths)
            except Exception as e:
                print(f"[!] Katana/path recon error: {e}", file=sys.stderr)
                if options.payload_recon:
                    print("[!] Payload recon skipped (no paths).", file=sys.stderr)
                    return

        # Payload recon: ใช้ทั้ง paths จาก Katana + Gobuster (ทำหลัง path_recon เสร็จ)
        grouped_forms: dict = {}
        url_entry_points: dict = {}
        if options.payload_recon:
            all_paths = list({*paths, *gobuster_paths})
            if not all_paths:
                print("[!] Payload recon skipped (no paths from katana/gobuster).", file=sys.stderr)
            else:
                # แปลง cookie_headers (list of tuples) → dict สำหรับ requests
                payload_headers: dict | None = dict(cookie_headers) if cookie_headers else None

                # กรองเฉพาะ path ที่ 404 จริงๆ — ไม่กรอง login-redirect เพราะ Katana รันด้วย cookie แล้ว
                # และ session อาจหมดอายุระหว่างขั้นตอนทำให้เกิด false-positive login-redirect
                import requests as _req
                valid_paths: list[str] = []
                for _p in all_paths:
                    if not _p.startswith("http"):
                        valid_paths.append(_p)
                        continue
                    try:
                        _r = _req.get(_p, headers=payload_headers, timeout=5, allow_redirects=True)
                        if _r.status_code == 404:
                            continue
                        valid_paths.append(_p)
                    except Exception:
                        valid_paths.append(_p)
                removed = len(all_paths) - len(valid_paths)
                if removed:
                    print(f"[*] Filtered {removed} paths (404) before payload recon.")
                all_paths = valid_paths

                grouped_forms, url_entry_points = run_payload_recon(all_paths, max_workers=8, extra_headers=payload_headers)
                _print_payload_recon(grouped_forms, url_entry_points)

        # Auto Triage (ไม่ถาม Gemini): สร้าง suggested commands จาก recon เอง
        if getattr(options, "auto_triage", False):
            if not grouped_forms and not url_entry_points:
                print("[!] Auto triage skipped (no forms/params). Run --path-recon --payload-recon first.", file=sys.stderr)
            else:
                triage = run_local_triage(url, grouped_forms, url_entry_points)
                out_path = getattr(options, "ai_triage_output", "triage.json")
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(triage, f, ensure_ascii=False, indent=2)
                print("\n" + "=" * 80)
                print("AUTO TRIAGE (Local – no Gemini)")
                print("=" * 80)
                print(f"Saved: {out_path}")
                for t in triage.get("targets") or []:
                    print(f"\n  [{t.get('confidence', '')}] {t.get('endpoint')} [{t.get('method')}]")
                    print(f"    Suspected: {t.get('suspected_issue_types', [])}")
                    for cmd in t.get("suggested_commands") or []:
                        print(f"    $ {cmd}")

        # AI Triage (Gemini): วิเคราะห์ recon → JSON + suggested commands สำหรับ pentest
        if getattr(options, "ai_triage", False):
            all_paths = list({*paths, *gobuster_paths})
            if not all_paths:
                print("[!] AI triage skipped (no paths). Run --path-recon --payload-recon first.", file=sys.stderr)
            else:
                try:
                    triage = run_ai_triage(
                        url,
                        all_paths,
                        grouped_forms,
                        url_entry_points,
                        use_localhost_in_prompt=True,
                    )
                    apply_real_base_to_commands(triage, url)
                    out_path = getattr(options, "ai_triage_output", "triage.json")
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(triage, f, ensure_ascii=False, indent=2)
                    print("\n" + "=" * 80)
                    print("AI TRIAGE (Gemini)")
                    print("=" * 80)
                    print(f"Saved: {out_path}")
                    for t in triage.get("targets") or []:
                        print(f"\n  [{t.get('confidence', '')}] {t.get('endpoint')} [{t.get('method')}]")
                        print(f"    Suspected: {t.get('suspected_issue_types', [])}")
                        for cmd in t.get("suggested_commands") or []:
                            print(f"    $ {cmd}")
                except Exception as e:
                    print(f"[!] AI triage error: {e}", file=sys.stderr)

        # บันทึกสรุป pre-auth ไว้สำหรับ merge ใน final_report เมื่อรันรอบ 2 แบบ post-auth
        if not getattr(options, "post_auth", False) and (paths or grouped_forms or url_entry_points):
            try:
                pre = Path("pre_auth_summary.md")
                lines = [f"# Pre-Auth Scan\n", f"- URL: {url}\n", f"- Paths: {len(paths) + len(gobuster_paths)}\n", f"- Forms: {len(grouped_forms)}\n", f"- Query-only endpoints: {len(url_entry_points)}\n"]
                pre.write_text("".join(lines), encoding="utf-8")
            except Exception:
                pass

        # Post-Auth: AI Triage Round 2 (IDOR, Privilege Escalation, Broken Access Control) + final_report.md
        if getattr(options, "post_auth", False):
            all_paths = list({*paths, *gobuster_paths})
            if all_paths or grouped_forms or url_entry_points:
                triage2 = None
                try:
                    triage2 = run_ai_triage_round2(
                        url,
                        all_paths,
                        grouped_forms,
                        url_entry_points,
                        use_localhost_in_prompt=True,
                    )
                    if triage2.get("error"):
                        print(f"[!] AI Triage Round 2 API error: {triage2.get('error')} — using local fallback", file=sys.stderr)
                        triage2 = build_post_auth_triage_fallback(url, all_paths)
                    else:
                        apply_real_base_to_commands(triage2, url)
                except Exception as e:
                    print(f"[!] AI Triage Round 2 failed: {e} — using local fallback", file=sys.stderr)
                    triage2 = build_post_auth_triage_fallback(url, all_paths)

                if triage2:
                    triage_file = "triage.json"
                    with open(triage_file, "w", encoding="utf-8") as f:
                        json.dump(triage2, f, ensure_ascii=False, indent=2)
                    targets_r2 = triage2.get("targets", []) if isinstance(triage2, dict) else (triage2 if isinstance(triage2, list) else [])
                    print("\n" + "=" * 80)
                    print("AI TRIAGE ROUND 2 (Post-Auth: IDOR, Access Control)")
                    print("=" * 80)
                    print(f"Saved: {triage_file}")
                    for t in targets_r2:
                        if not isinstance(t, dict):
                            continue
                        print(f"\n  [{t.get('confidence', '')}] {t.get('endpoint')} [{t.get('method')}]")
                        print(f"    Suspected: {t.get('suspected_issue_types', [])}")
                        for cmd in (t.get("suggested_commands") or []):
                            print(f"    $ {cmd}")

                    report_path = Path("final_report.md")
                    pre_content = ""
                    pre_path = Path("pre_auth_summary.md")
                    if pre_path.exists():
                        pre_content = pre_path.read_text(encoding="utf-8", errors="ignore")
                    else:
                        pre_content = "See results/ and triage.json from initial (pre-auth) scan.\n"
                    post_lines = [
                        "## Post-Auth Scan",
                        f"- URL: {url}",
                        f"- Paths discovered: {len(all_paths)}",
                        "",
                        "### Triage Round 2 (IDOR / Access Control)",
                        "",
                    ]
                    for t in targets_r2:
                        if not isinstance(t, dict):
                            continue
                        post_lines.append(f"- **{t.get('endpoint')}** [{t.get('method')}]")
                        post_lines.append(f"  - Suspected: {', '.join(t.get('suspected_issue_types') or [])}")
                        for c in (t.get("suggested_commands") or []):
                            post_lines.append(f"  - `$ {c}`")
                        for c in (t.get("recommended_manual_checks") or [])[:5]:
                            post_lines.append(f"  - {c}")
                        post_lines.append("")
                    report_body = (
                        "# OneClickScan V2 – Final Report\n\n"
                        "## Pre-Auth\n\n"
                        f"{pre_content}\n\n"
                        + "\n".join(post_lines)
                    )
                    report_path.write_text(report_body, encoding="utf-8")
                    print(f"[*] Report written: {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OneClickScan V2 - Web pentest จาก URL เดียว (path recon, payload recon, nmap)"
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL (e.g. http://example.com)",
    )
    parser.add_argument(
        "-u", "--url",
        dest="url_flag",
        metavar="URL",
        help="Target URL (alternative)",
    )
    parser.add_argument(
        "--path-recon",
        action="store_true",
        help="Run path recon (Katana crawl)",
    )
    parser.add_argument(
        "--payload-recon",
        action="store_true",
        help="Run payload recon (map_forms + URL params on discovered paths)",
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Run nmap service scan on target host",
    )
    parser.add_argument(
        "--whatweb",
        action="store_true",
        help="Run whatweb fingerprint and suggest exploit/cve lookups",
    )
    parser.add_argument(
        "--whatweb-cve",
        action="store_true",
        help="When used with --whatweb, try to lookup CVEs via public API",
    )
    parser.add_argument(
        "--whatweb-cve-limit",
        type=int,
        default=5,
        metavar="N",
        help="Max CVEs per finding for --whatweb-cve (default: 5)",
    )
    parser.add_argument(
        "--gobuster",
        action="store_true",
        help="Run gobuster dir to find hidden paths",
    )
    parser.add_argument(
        "--subfinder",
        action="store_true",
        help="Find subdomains (extract root domain from URL, then run subfinder)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run path recon + payload recon + nmap + whatweb + gobuster + subfinder",
    )
    parser.add_argument(
        "--nmap-ports",
        type=int,
        default=20,
        metavar="N",
        help="Nmap top ports (default: 20)",
    )
    parser.add_argument(
        "--auto-triage",
        action="store_true",
        help="Build test commands from recon locally (no Gemini): sqlmap, hydra, xsstrike, commix",
    )
    parser.add_argument(
        "--ai-triage",
        action="store_true",
        help="Send recon to Gemini for triage and suggested test commands (authorized pentest)",
    )
    parser.add_argument(
        "--ai-triage-output",
        default="triage.json",
        metavar="FILE",
        help="Output path for triage JSON (default: triage.json)",
    )
    parser.add_argument(
        "--cookie-file",
        default=None,
        metavar="FILE",
        help="Use session cookies from FILE (e.g. active_session.json) for Katana/Gobuster",
    )
    parser.add_argument(
        "--post-auth",
        action="store_true",
        help="Post-authentication run: AI Triage Round 2 (IDOR/access control) and merge into final_report.md",
    )

    args = parser.parse_args()
    url = args.url or args.url_flag
    if not url:
        parser.error("Need URL: pass as positional or -u/--url")
    args.url = url

    if args.all:
        args.path_recon = True
        args.payload_recon = True
        args.nmap = True
        args.whatweb = True
        args.gobuster = True
        args.subfinder = True

    if getattr(args, "ai_triage", False) or getattr(args, "auto_triage", False):
        args.payload_recon = True

    if not (
        args.path_recon
        or args.payload_recon
        or args.nmap
        or args.whatweb
        or args.gobuster
        or args.subfinder
        or getattr(args, "ai_triage", False)
        or getattr(args, "auto_triage", False)
    ):
        parser.error(
            "Choose at least one: --path-recon, --payload-recon, --nmap, --whatweb, --gobuster, --subfinder, --auto-triage, --ai-triage, or --all"
        )

    run(args)


if __name__ == "__main__":
    main()
