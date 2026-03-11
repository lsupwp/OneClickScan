"""
OneClickScan V2 — FastAPI backend
WebSocket /ws/scan  →  stream scan output line by line
REST      GET /api/results/{job_id}  →  full JSON result after done
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="OneClickScan V2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ROOT   = Path(__file__).resolve().parent
PYTHON = sys.executable


def _httpx_bin() -> str | None:
    """หา Go httpx binary (ไม่ใช่ Python httpx)"""
    import os, shutil
    candidates = []
    gopath = os.environ.get("GOPATH", "")
    if gopath:
        candidates.append(str(Path(gopath) / "bin" / "httpx"))
    candidates.append(str(Path.home() / "go" / "bin" / "httpx"))
    for p in candidates:
        if Path(p).is_file() and os.access(p, os.X_OK):
            return p
    return shutil.which("httpx")


async def _probe_paths(paths: list[str], base_url: str) -> list[str]:
    """
    ส่ง paths เข้า httpx แบบ async แล้วคืนเฉพาะที่ไม่ใช่ 404
    - paths อาจเป็น full URL หรือ relative path
    - ใช้ -fc 404 เพื่อกรอง 404 ออก และ -sc เพื่อแสดง status code
    """
    if not paths:
        return paths

    bin_path = _httpx_bin()
    if not bin_path:
        return paths  # httpx ไม่มี → คืนทั้งหมด

    base = base_url.rstrip("/")
    full_urls: list[str] = []
    for p in paths:
        p = p.strip()
        if not p:
            continue
        if p.startswith("http://") or p.startswith("https://"):
            full_urls.append(p)
        else:
            full_urls.append(base + "/" + p.lstrip("/"))

    if not full_urls:
        return paths

    stdin_data = "\n".join(full_urls) + "\n"
    cmd = [
        bin_path,
        "-silent",
        "-fc", "404",           # กรอง 404 ออก
        "-mc", "200,201,204,301,302,307,308,401,403,405,500,503",
        "-follow-redirects",
        "-threads", "40",
        "-timeout", "8",
        "-retries", "1",
        "-no-color",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data.encode()), timeout=120)
        alive = [ln.strip() for ln in stdout.decode(errors="replace").splitlines() if ln.strip()]
        return alive if alive else paths
    except Exception:
        return paths  # fallback ถ้า httpx พัง

# ── active jobs (job_id → result JSON) ──────────────────────────────────────
_jobs: dict[str, Any] = {}


def _build_cmd(url: str, options: dict) -> list[str]:
    """แปลง options dict → argv list สำหรับ executor.py"""
    cmd = [PYTHON, str(ROOT / "executor.py"), "-u", url]

    flag_map = {
        "path_recon":    "--path-recon",
        "payload_recon": "--payload-recon",
        "auto_triage":   "--auto-triage",
        "ai_triage":     "--ai-triage",
        "gobuster":      "--gobuster",
        "davtest":       "--davtest",
        "nuclei":        "--nuclei",
        "nmap":          "--nmap",
        "whatweb":       "--whatweb",
        "subfinder":     "--subfinder",
        "run_exploit":   "--run-exploit",
    }
    for key, flag in flag_map.items():
        if options.get(key):
            cmd.append(flag)

    if options.get("workers"):
        cmd += ["--workers", str(options["workers"])]
    if options.get("timeout"):
        cmd += ["--timeout", str(options["timeout"])]

    # always save JSON output for result retrieval
    job_id = options.get("_job_id", "scan")
    out_path = ROOT / "results" / f"scan_{job_id}.json"
    cmd += ["--json-out", str(out_path)]

    return cmd


def _build_exec_cmd(options: dict) -> list[str]:
    """สร้าง command สำหรับ exec mode (run triage.json)"""
    workers = options.get("workers", 6)
    confidence = options.get("min_confidence", "medium")
    cmd = [PYTHON, "-u", str(ROOT / "executor.py"),
           "triage.json",
           "--workers", str(workers),
           "--min-confidence", confidence]
    return cmd


def _summarize_log(results_dir: Path, log_name: str, tool: str, exit_code: int) -> str:
    """อ่าน log แล้วคืนข้อความสั้นๆ (สำเร็จ/พบช่องโหว่/ล้มเหลว)"""
    path = results_dir / log_name
    if not path.exists():
        return "No log"
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        t = raw.lower()
    except Exception:
        return "Read error"
    if exit_code != 0 and exit_code != -1:
        return f"Exit {exit_code}"
    tool_l = tool.lower()
    if "sqlmap" in tool_l:
        if "injection" in t and ("parameter" in t or "vulnerable" in t):
            return "SQLi likely"
        if "injection" in t:
            return "SQLi possible"
        return "No SQLi"
    if "xsstrike" in tool_l:
        if "vulnerable" in t or "xss" in t and "found" in t:
            return "XSS possible"
        return "No XSS"
    if "hydra" in tool_l or "bruter" in tool_l:
        if "login:" in t or "password:" in t or "valid" in t or "success" in t:
            return "Credential?"
        return "No login"
    return "Done"


def _summarize_logs_with_gemini(results_dir: Path, results: list[dict]) -> list[str] | None:
    """
    อ่านไฟล์ log แต่ละอันแล้วส่งให้ Gemini สรุปเป็นข้อความสั้นๆ ภาษาไทย (1-2 ประโยคต่ออัน).
    คืน list ของข้อความตามลำดับ results หรือ None ถ้าไม่มี API key / error.
    """
    import os
    max_chars_per_log = 5000
    max_logs = 35
    snippets: list[str] = []
    for i, r in enumerate(results[:max_logs]):
        log_name = r.get("log") or ""
        tool = r.get("tool") or ""
        exit_code = r.get("exit_code", -1)
        path = results_dir / log_name
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
                if len(raw) > max_chars_per_log:
                    raw = raw[: max_chars_per_log] + "\n... (truncated)"
            except Exception:
                raw = "(read error)"
        else:
            raw = "(no file)"
        snippets.append(f"--- [{i+1}] {tool} -> {log_name} (exit {exit_code}) ---\n{raw}")
    if not snippets:
        return None
    prompt = f"""ด้านล่างเป็น output จากเครื่องมือสแกนความปลอดภัย (sqlmap, xsstrike, hydra ฯลฯ) จำนวน {len(snippets)} รายการ.
ให้สรุปแต่ละรายการเป็นภาษาไทย 1-2 ประโยคเท่านั้น: สถานะ (สำเร็จ/ล้มเหลว/ข้าม), พบช่องโหว่หรือไม่ (เช่น SQL injection, XSS, รหัสผ่านที่เดาได้ ฯลฯ).
ตอบเป็น JSON array ของ string เท่านั้น ตามลำดับรายการ (ไม่มี markdown ไม่มี code block): ["ข้อความที่ 1", "ข้อความที่ 2", ...]

{snippets[0]}
"""
    for s in snippets[1:]:
        prompt += "\n\n" + s
    try:
        from google import genai
    except ImportError:
        return None
    if not (os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")):
        return None
    try:
        client = genai.Client()
        response = client.models.generate_content(
            model="models/gemini-2.5-flash",
            contents=prompt,
        )
        text = (response.text or "").strip()
        if not text:
            return None
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        arr = json.loads(text)
        if isinstance(arr, list) and len(arr) >= len(snippets):
            return [str(x) for x in arr[: len(snippets)]]
        return None
    except Exception:
        return None


# ── WebSocket scan endpoint ──────────────────────────────────────────────────
@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    await ws.accept()
    try:
        raw = await ws.receive_text()
        body = json.loads(raw)
    except Exception as e:
        await ws.send_json({"type": "error", "msg": f"Bad payload: {e}"})
        await ws.close()
        return

    url       = (body.get("url") or "").strip()
    options   = body.get("options") or {}
    exec_mode = bool(body.get("exec_mode"))
    job_id    = uuid.uuid4().hex[:10]

    # debug: log run request
    print(f"[ws/scan] job_id={job_id} exec_mode={exec_mode} url={url!r} options={list(options.keys()) if options else []}")

    if exec_mode:
        cmd = _build_exec_cmd(options)
        print(f"[ws/scan] exec_cmd: {' '.join(cmd)}")
    else:
        if not url:
            await ws.send_json({"type": "error", "msg": "url is required"})
            await ws.close()
            return
        options["_job_id"] = job_id
        cmd = _build_cmd(url, options)
        print(f"[ws/scan] scan_cmd: {' '.join(cmd[2:])}")

    await ws.send_json({"type": "start", "job_id": job_id,
                        "cmd": " ".join(cmd[2:])})  # hide python path

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(ROOT),
    )

    # stream lines
    assert proc.stdout
    client_alive = True
    line_count = 0
    async for raw_line in proc.stdout:
        line = raw_line.decode("utf-8", errors="replace").rstrip()
        if not line:
            continue
        if not client_alive:
            continue  # keep draining stdout so the subprocess doesn't hang
        msg_type = "phase" if line.startswith("===") else "log"
        try:
            await ws.send_json({"type": msg_type, "text": line})
            line_count += 1
        except Exception as e:
            print(f"[ws/scan] send error after {line_count} lines: {e}")
            client_alive = False

    await proc.wait()
    exit_code = proc.returncode
    print(f"[ws/scan] job_id={job_id} done exit_code={exit_code} lines_sent={line_count}")

    # helper: send without raising if client already closed
    async def _safe_send(payload: dict) -> bool:
        try:
            await ws.send_json(payload)
            return True
        except Exception:
            return False

    # load JSON result if available
    result_path = ROOT / "results" / f"scan_{job_id}.json"
    result_data: dict[str, Any] | None = None
    if result_path.exists() and not exec_mode:
        try:
            result_data = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    results_dir = ROOT / "results"
    if exec_mode:
        summary_path = results_dir / "last_exploit_summary.json"
        if summary_path.exists():
            try:
                raw = json.loads(summary_path.read_text(encoding="utf-8"))
                total = raw.get("total", 0)
                results = raw.get("results") or []
                enriched = []
                for r in results:
                    outcome = _summarize_log(
                        results_dir,
                        r.get("log", ""),
                        r.get("tool", ""),
                        r.get("exit_code", -1),
                    )
                    cmd = _get_command_from_log(results_dir, r.get("log", "")) or r.get("command") or ""
                    enriched.append({
                        "idx": r.get("idx"),
                        "total": total,
                        "tool": r.get("tool"),
                        "log": r.get("log"),
                        "exit_code": r.get("exit_code"),
                        "skipped": r.get("skipped", False),
                        "outcome": outcome,
                        "command": cmd,
                    })
                try:
                    ai_summaries = await asyncio.to_thread(
                        _summarize_logs_with_gemini, results_dir, results
                    )
                    if ai_summaries:
                        for i, s in enumerate(ai_summaries):
                            if i < len(enriched):
                                enriched[i]["ai_summary"] = s
                except Exception:
                    pass
                result_data = {"summary": enriched, "total": total}
            except Exception:
                result_data = None

    # probe discovered paths through httpx to filter out 404s
    if result_data and result_data.get("paths") and not exec_mode:
        raw_paths = result_data["paths"]
        target_url = result_data.get("target") or url
        try:
            await _safe_send({"type": "log",
                              "text": f"[*] Probing {len(raw_paths)} paths with httpx (filtering 404s)…"})
            alive = await _probe_paths(raw_paths, target_url)
            result_data["paths"] = alive
            await _safe_send({"type": "log",
                              "text": f"[*] httpx: {len(alive)}/{len(raw_paths)} paths alive"})
            result_path.write_text(json.dumps(result_data, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        except Exception as probe_err:
            await _safe_send({"type": "log",
                              "text": f"[!] httpx probe skipped: {probe_err}"})

    if result_data:
        _jobs[job_id] = result_data

    await _safe_send({
        "type":      "done",
        "job_id":    job_id,
        "exit_code": exit_code,
        "result":    result_data,
    })

    try:
        await ws.close()
    except Exception:
        pass


def _get_command_from_log(results_dir: Path, log_name: str) -> str:
    """ดึงบรรทัดคำสั่งจากไฟล์ log (บรรทัดหลัง # Command:)"""
    if not log_name:
        return ""
    path = results_dir / log_name
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            s = line.strip()
            if s == "# Command:" and i + 1 < len(lines):
                return lines[i + 1].strip()
            if s.startswith("# Command:") and len(s) > 10:
                return s[10:].strip()
    except Exception:
        pass
    return ""


def _build_summary_from_log_dir(results_dir: Path) -> list[dict] | None:
    """
    ถ้าไม่มี last_exploit_summary.json ให้สร้างรายการจากไฟล์ *.log ใน results/
    คืน list ของ { idx, total, tool, log, exit_code, skipped } หรือ None ถ้าไม่มี log
    """
    logs = sorted(results_dir.glob("*.log"))
    # เฉพาะ log ที่เป็นผลจาก executor (sqlmap_*, xsstrike_*, hydra_*, bruter_*)
    def tool_from_name(name: str) -> str:
        if name.startswith("sqlmap_"): return "sqlmap"
        if name.startswith("xsstrike_"): return "xsstrike"
        if name.startswith("hydra_"): return "hydra"
        if name.startswith("bruter_"): return "bruter"
        return "unknown"
    out = []
    for i, p in enumerate(logs, 1):
        name = p.name
        if name.startswith(("sqlmap_", "xsstrike_", "hydra_", "bruter_")):
            out.append({
                "idx": i, "total": len(logs),
                "tool": tool_from_name(name), "log": name,
                "exit_code": -1, "skipped": False,
            })
    if not out:
        return None
    for r in out:
        r["total"] = len(out)
    return out


# ── REST: โหลดผล exploit จากรันล่าสุด (manual) ─────────────────────────────────
@app.get("/api/exploit-last-result")
async def get_exploit_last_result(gemini: bool = True):
    """
    อ่าน results/last_exploit_summary.json แล้วคืน summary พร้อม outcome (และ ai_summary ถ้า gemini=1).
    ถ้าไม่มีไฟล์ จะลองสร้างรายการจาก *.log ใน results/ แล้วคืนผลเหมือนกัน
    """
    results_dir = ROOT / "results"
    summary_path = results_dir / "last_exploit_summary.json"
    results: list[dict]
    if summary_path.exists():
        try:
            raw = json.loads(summary_path.read_text(encoding="utf-8"))
            results = raw.get("results") or []
            total = raw.get("total", len(results))
        except Exception:
            results = []
            total = 0
    else:
        results = _build_summary_from_log_dir(results_dir) or []
        total = len(results)
    if not results:
        return {"error": "not_found", "message": "ยังไม่มีผลรันล่าสุด (ไม่มี last_exploit_summary.json และไม่มีไฟล์ *.log ใน results/)"}
    try:
        enriched: list[dict[str, Any]] = []
        for r in results:
            outcome = _summarize_log(
                results_dir,
                r.get("log", ""),
                r.get("tool", ""),
                r.get("exit_code", -1),
            )
            cmd = _get_command_from_log(results_dir, r.get("log", "")) or r.get("command") or ""
            enriched.append({
                "idx": r.get("idx"),
                "total": total,
                "tool": r.get("tool"),
                "log": r.get("log"),
                "exit_code": r.get("exit_code"),
                "skipped": r.get("skipped", False),
                "outcome": outcome,
                "command": cmd,
            })
        if gemini:
            try:
                ai_summaries = await asyncio.to_thread(
                    _summarize_logs_with_gemini, results_dir, results
                )
                if ai_summaries:
                    for i, s in enumerate(ai_summaries):
                        if i < len(enriched):
                            enriched[i]["ai_summary"] = s
            except Exception:
                pass
        return {"summary": enriched, "total": total}
    except Exception as e:
        return {"error": "read_failed", "message": str(e)}


# ── REST: อ่านเนื้อหา log ของ exploit (สำหรับปุ่ม "ดูผล") ─────────────────────
@app.get("/api/exploit-log")
def get_exploit_log(name: str = ""):
    """คืนเนื้อหาไฟล์ log ใน results/ (เฉพาะ .log, ไม่ให้ path traversal)"""
    if not name or ".." in name or "/" in name or "\\" in name:
        return {"error": "invalid_name"}
    if not name.endswith(".log"):
        return {"error": "not_a_log"}
    path = ROOT / "results" / name
    if not path.exists() or not path.is_file():
        return {"error": "not_found"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"name": name, "content": text}
    except Exception as e:
        return {"error": "read_failed", "message": str(e)}


# ── REST: get stored result ──────────────────────────────────────────────────
@app.get("/api/results/{job_id}")
def get_result(job_id: str):
    if job_id not in _jobs:
        result_path = ROOT / "results" / f"scan_{job_id}.json"
        if result_path.exists():
            return json.loads(result_path.read_text(encoding="utf-8"))
        return {"error": "not found"}
    return _jobs[job_id]


# ── serve built React SPA ────────────────────────────────────────────────────
dist = ROOT / "fontend" / "dist"
if dist.exists():
    app.mount("/", StaticFiles(directory=str(dist), html=True), name="spa")
