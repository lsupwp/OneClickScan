"""
Gobuster Service - หา hidden paths (dir/file enumeration)
"""

from __future__ import annotations

import re
import subprocess
import uuid
from dataclasses import dataclass
from typing import Callable, List, Optional
from urllib.parse import urljoin

import requests


@dataclass(frozen=True)
class GobusterFinding:
    path: str
    status: Optional[int] = None
    size: Optional[int] = None
    redirect: Optional[str] = None


_LINE_RE = re.compile(
    r"^(?P<path>/?\S+)\s+\(Status:\s+(?P<status>\d+)\)\s*(?:\[Size:\s+(?P<size>\d+)\])?\s*(?:\[(?P<extra>[^\]]+)\])?\s*$"
)


def _detect_wildcard_content_length(
    target_url: str,
    timeout_seconds: int,
    user_agent: str,
    insecure_tls: bool,
) -> Optional[int]:
    """
    ยิง request ไป path มั่วที่ไม่น่ามีอยู่จริง แล้วคืนค่า content length
    เพื่อเอาไปใช้กับ --exclude-length ของ gobuster แบบ dynamic
    """
    random_path = str(uuid.uuid4())
    probe_url = urljoin(target_url.rstrip("/") + "/", random_path)
    try:
        response = requests.get(
            probe_url,
            timeout=timeout_seconds,
            allow_redirects=True,
            verify=not insecure_tls,
            headers={"User-Agent": user_agent},
        )
        header_len = response.headers.get("Content-Length")
        if header_len and header_len.isdigit():
            return int(header_len)
        return len(response.content or b"")
    except Exception:
        return None


def _build_gobuster_cmd(
    *,
    target_url: str,
    wordlist_path: str,
    threads: int,
    timeout_seconds: int,
    status_codes: str,
    status_codes_blacklist: str,
    extensions: Optional[str],
    user_agent: str,
    follow_redirect: bool,
    insecure_tls: bool,
    random_agent: bool,
    retry: bool,
    retry_attempts: int,
    delay: str,
    no_error: bool,
    no_progress: bool,
    force: bool,
    quiet: bool,
    exclude_length: Optional[int] = None,
    extra_headers: Optional[List[tuple[str, str]]] = None,
) -> list[str]:
    cmd = [
        "gobuster",
        "dir",
        "-u",
        target_url,
        "-w",
        wordlist_path,
        "-t",
        str(threads),
        "--timeout",
        f"{timeout_seconds}s",
        "--delay",
        delay,
        "-s",
        status_codes,
        "-b",
        status_codes_blacklist,
        "--no-color",
    ]
    if exclude_length is not None:
        cmd.extend(["--exclude-length", str(exclude_length)])
    if random_agent:
        cmd.append("--random-agent")
    else:
        cmd.extend(["-a", user_agent])
    if retry:
        cmd.append("--retry")
        cmd.extend(["--retry-attempts", str(retry_attempts)])
    if no_error:
        cmd.append("--no-error")
    if no_progress:
        cmd.append("--no-progress")
    if force:
        cmd.append("--force")
    if quiet:
        cmd.append("-q")
    if insecure_tls:
        cmd.append("-k")
    if follow_redirect:
        cmd.append("-r")
    if extensions:
        cmd.extend(["-x", extensions])
    for hname, hval in extra_headers or []:
        if hname and hval:
            cmd.extend(["-H", f"{hname}: {hval}"])
    return cmd


def _run_cmd_with_live_output(
    cmd: list[str],
    on_output_line: Optional[Callable[[str], None]] = None,
) -> tuple[int, str]:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output_lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        output_lines.append(line)
        if on_output_line:
            on_output_line(line.rstrip("\n"))
    rc = proc.wait(timeout=60 * 20)
    return rc, "".join(output_lines)


def run_gobuster_dir(
    target_url: str,
    wordlist_path: str,
    threads: int = 20,
    timeout_seconds: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    status_codes_blacklist: str = "",
    extensions: Optional[str] = None,
    user_agent: str = "OneClickScanV2",
    follow_redirect: bool = False,
    insecure_tls: bool = True,
    random_agent: bool = False,
    retry: bool = False,
    retry_attempts: int = 3,
    delay: str = "0s",
    no_error: bool = False,
    no_progress: bool = True,
    force: bool = True,
    quiet: bool = False,
    on_output_line: Optional[Callable[[str], None]] = None,
    extra_headers: Optional[List[tuple[str, str]]] = None,
) -> str:
    """
    รัน gobuster dir แล้วคืน stdout (raw).
    """
    try:
        cmd = _build_gobuster_cmd(
            target_url=target_url,
            wordlist_path=wordlist_path,
            threads=threads,
            timeout_seconds=timeout_seconds,
            status_codes=status_codes,
            status_codes_blacklist=status_codes_blacklist,
            extensions=extensions,
            user_agent=user_agent,
            follow_redirect=follow_redirect,
            insecure_tls=insecure_tls,
            random_agent=random_agent,
            retry=retry,
            retry_attempts=retry_attempts,
            delay=delay,
            no_error=no_error,
            no_progress=no_progress,
            force=force,
            quiet=quiet,
            extra_headers=extra_headers,
        )
        rc, out = _run_cmd_with_live_output(cmd, on_output_line)
        if rc == 0:
            return out

        # ถ้าชน wildcard precheck ให้ probe random path หา length แล้ว retry ด้วย --exclude-length
        if "the server returns a status code that matches the provided options for non existing urls" in out:
            wildcard_length = _detect_wildcard_content_length(
                target_url=target_url,
                timeout_seconds=timeout_seconds,
                user_agent=user_agent,
                insecure_tls=insecure_tls,
            )
            if wildcard_length is not None:
                if on_output_line:
                    on_output_line(
                        f"[auto] wildcard detected, retrying with --exclude-length {wildcard_length}"
                    )
                retry_cmd = _build_gobuster_cmd(
                    target_url=target_url,
                    wordlist_path=wordlist_path,
                    threads=threads,
                    timeout_seconds=timeout_seconds,
                    status_codes=status_codes,
                    status_codes_blacklist=status_codes_blacklist,
                    extensions=extensions,
                    user_agent=user_agent,
                    follow_redirect=follow_redirect,
                    insecure_tls=insecure_tls,
                    random_agent=random_agent,
                    retry=retry,
                    retry_attempts=retry_attempts,
                    delay=delay,
                    no_error=no_error,
                    no_progress=no_progress,
                    force=force,
                    quiet=quiet,
                    exclude_length=wildcard_length,
                    extra_headers=extra_headers,
                )
                rc, retry_out = _run_cmd_with_live_output(retry_cmd, on_output_line)
                if rc == 0:
                    return retry_out
                raise RuntimeError(f"gobuster failed (exit={rc}): {retry_out.strip()}")

        raise RuntimeError(f"gobuster failed (exit={rc}): {out.strip()}")
    except FileNotFoundError:
        raise RuntimeError("gobuster not found. Install gobuster.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("gobuster timed out.")


def parse_gobuster_output(raw_output: str) -> List[GobusterFinding]:
    """
    Parse output จาก gobuster ให้เป็น list findings.
    ตัวอย่าง line:
      /admin (Status: 301) [Size: 169] [--> http://example.com/admin/]
    """
    findings: list[GobusterFinding] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # สนใจเฉพาะบรรทัดผลลัพธ์ที่มี "(Status: NNN)"
        if "(Status:" not in line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            # fallback: เก็บ path อย่างเดียว
            findings.append(GobusterFinding(path=line.split()[0].lstrip("/")))
            continue
        path = (m.group("path") or "").lstrip("/")
        status = int(m.group("status")) if m.group("status") else None
        size = int(m.group("size")) if m.group("size") else None
        extra = m.group("extra") or ""
        redirect = None
        if "-->" in extra:
            redirect = extra.split("-->", 1)[-1].strip()
        findings.append(GobusterFinding(path=path, status=status, size=size, redirect=redirect))
    return findings

