#!/usr/bin/env python3
"""
OneClickScan V2 — unified scanner + executor

Modes:
  python executor.py scan  -u URL [opts]   # recon + triage  (เดิม main.py)
  python executor.py exec  [triage.json]   # run triage cmds (เดิม executor.py)
  python executor.py run   -u URL          # full pipeline   (เดิม --run-exploit)

Legacy compat (no subcommand → exec mode):
  python executor.py --min-confidence medium --workers 6
"""
from __future__ import annotations
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

import argparse, json, re, shutil, subprocess, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

# ── constants / tiny helpers ───────────────────────────────────────────
_UA       = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
_ORDER    = {"high": 3, "medium": 2, "low": 1}
_TOK_KEYS = ("token", "csrf", "_sync", "_token", "authenticity_token", "sync")
_FAIL_MK  = ("incorrect", "login failed", "invalid", "wrong password", "authentication failed")
_OK_MK    = ("logout", "welcome", "dashboard", "instructions.php", "dvwa security", "php info")
_CRED_RE  = re.compile(r"CREDENTIAL:\t(?P<u>[^\t]+)\t(?P<p>.+)")
_HYDRA_RE = re.compile(
    r"\[\d+\]\[[\w-]+\]\s+host:\s+login:\s+(?P<u>\S+)\s+password:\s+(?P<p>\S+)", re.I
)


def _scheme(u: str) -> str:
    return u if u.startswith(("http://", "https://")) else "http://" + u


def _slug(ep: str, n: int = 40) -> str:
    s = urlparse(ep).path if "://" in ep else ep
    return (re.sub(r"_+", "_", re.sub(r"[^\w\-.]", "_", s)).strip("_") or "unknown")[:n]


def _first_token(cmd: str) -> str | None:
    t = (cmd or "").strip().split()[0] if cmd.strip() else ""
    return (t.split("/")[-1] or None) if t else None


def _available(tool: str) -> bool:
    return bool(tool and shutil.which(tool))


def _has_token(params: list | dict) -> tuple[bool, str | None]:
    keys = list(params.keys() if isinstance(params, dict) else params)
    for k in keys:
        if any(t in str(k).lower() for t in _TOK_KEYS):
            return True, str(k)
    return False, None


def _filter_targets(targets: list, min_confidence: str | None) -> list:
    if not min_confidence or min_confidence == "low":
        return list(targets)
    lvl = _ORDER.get(min_confidence, 0)
    return [t for t in targets if _ORDER.get((t.get("confidence") or "low").lower(), 1) >= lvl]


def _hdr(title: str) -> None:
    print(f"\n{'='*80}\n{title}\n{'='*80}")


# ── SessionManager ─────────────────────────────────────────────────────
class SessionManager:
    """Loads, saves, refreshes session cookies; handles login + CSRF."""

    def __init__(self, root: Path, cookie_file: str | None = None):
        self.root        = root
        self.cookie_path = Path(cookie_file).resolve() if cookie_file else root / "active_session.json"
        self.cred_path   = self.cookie_path.parent / "credentials.json"

    # loaders
    def cookie_str(self) -> str | None:
        d = self._json(self.cookie_path)
        if not d: return None
        if d.get("Cookie"): return d["Cookie"].strip()
        if d.get("cookies"):
            return "; ".join(f"{c['name']}={c['value']}" for c in d["cookies"] if c.get("name")) or None
        return None

    def headers_list(self) -> list[tuple] | None:
        cs = self.cookie_str()
        if not cs: return None
        print(f"[*] Loaded session from {self.cookie_path.name} ({len(cs.split(';'))} cookies)")
        return [("Cookie", cs), ("User-Agent", _UA)]

    # login / session lifecycle
    def login(self, url: str, user: str, pwd: str, form: dict,
              csrf_field: str = "user_token", timeout: int = 15) -> bool:
        sess = requests.Session()
        sess.headers["User-Agent"] = _UA
        try:
            csrf = self._csrf(url, csrf_field, sess, timeout)
            body = dict(form)
            for k in body:
                kl = k.lower()
                if kl in ("username", "user", "uname", "login"): body[k] = user
                elif kl in ("password", "pass", "pwd"):           body[k] = pwd
            if csrf: body[csrf_field] = csrf
            r = sess.post(url, data=body, timeout=timeout, allow_redirects=True)
            if not self._looks_ok(r, url): return False
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            verified = any(
                self._looks_ok(sess.get(c, timeout=timeout, allow_redirects=True), url)
                for c in [base + "/", base + "/index.php"]
            )
            if not verified: return False
            self._save(sess, url)
            return True
        except Exception:
            return False

    def refresh(self) -> list[tuple] | None:
        cred = self._json(self.cred_path)
        if not cred or not cred.get("url") or not cred.get("username"): return None
        try:
            sess = requests.Session()
            sess.headers["User-Agent"] = _UA
            r   = sess.get(cred["url"], timeout=10, allow_redirects=True)
            cf  = cred.get("csrf_field", "user_token")
            inp = BeautifulSoup(r.text, "html.parser").find("input", {"name": cf})
            csrf = inp["value"] if inp and inp.get("value") else None
            body = dict(cred.get("form_params") or {})
            for k in body:
                kl = k.lower()
                if kl in ("username", "user", "uname", "login"): body[k] = cred["username"]
                elif kl in ("password", "pass", "pwd"):           body[k] = cred["password"]
            if csrf: body[cf] = csrf
            sess.post(cred["url"], data=body, timeout=10, allow_redirects=True)
            cs = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
            if not cs: return None
            self._save(sess, cred["url"])
            print(f"[*] Session refreshed (re-login as {cred['username']}) before payload recon.")
            return [("Cookie", cs), ("User-Agent", _UA)]
        except Exception as e:
            print(f"[!] Session refresh failed: {e}", file=sys.stderr)
            return None

    def save_creds(self, url, user, pwd, form, csrf_field) -> None:
        self.cred_path.write_text(
            json.dumps({"url": url, "username": user, "password": pwd,
                        "form_params": form, "csrf_field": csrf_field},
                       ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def parse_creds(self, log_dir: Path) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        for f in log_dir.glob("*.log"):
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                for m in [*_HYDRA_RE.finditer(txt), *_CRED_RE.finditer(txt)]:
                    c = (m.group("u").strip(), m.group("p").strip())
                    if c[0] and c not in found: found.append(c)
            except Exception:
                pass
        return found

    # ── private helpers ──
    def _csrf(self, url, field, sess, timeout=10) -> str | None:
        try:
            r   = sess.get(url, timeout=timeout, allow_redirects=True)
            inp = BeautifulSoup(r.text, "html.parser").find("input", {"type": "hidden", "name": field})
            if inp and inp.get("value"): return inp["value"]
            for pat in [
                rf'<input[^>]+name=["\']({re.escape(field)})["\'][^>]+value=["\']([^"\']+)["\']',
                rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']({re.escape(field)})["\']',
            ]:
                m = re.search(pat, r.text, re.I)
                if m: return m.group(2 if "name" in pat[:20] else 1)
        except Exception:
            pass
        return None

    def _looks_ok(self, resp, login_url) -> bool:
        if resp.status_code >= 400: return False
        body = (resp.text or "").lower()
        if any(m in body for m in _FAIL_MK): return False
        if any(m in body for m in _OK_MK):   return True
        for form in BeautifulSoup(resp.text or "", "html.parser").find_all("form"):
            fields = {(i.get("name") or "").lower() for i in form.find_all("input") if i.get("name")}
            if (any(n in fields for n in ("username","user","uname")) and
                    any(n in fields for n in ("password","pass","pwd"))):
                return False
        ln = (urlparse(login_url).path.rsplit("/", 1)[-1] or "").lower()
        fu = (resp.url or "").lower()
        if resp.history and ln and ln not in fu: return True
        if "login" in fu and ln and ln in fu:   return False
        return len(resp.history) > 0

    def _save(self, sess, url) -> None:
        cs  = [{"name": c.name, "value": c.value} for c in sess.cookies]
        data = {"url": url,
                "Cookie": "; ".join(f"{c.name}={c.value}" for c in sess.cookies),
                "cookies": cs}
        self.cookie_path.parent.mkdir(parents=True, exist_ok=True)
        self.cookie_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _json(path: Path) -> dict | None:
        try:
            return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        except Exception:
            return None


# ── ReconEngine ────────────────────────────────────────────────────────
class ReconEngine:
    """Katana path crawl + payload/form extraction."""

    def __init__(self, url: str, session: SessionManager | None = None):
        self.url     = _scheme(url)
        self.session = session
        self.paths:  list[str] = []
        self.forms:  dict      = {}
        self.params: dict      = {}

    def run_paths(self, depth: int = 5) -> list[str]:
        from services.path_recon import run_katana, discover_links_from_authenticated_page
        hdrs = self.session.headers_list() if self.session else None
        try:
            self.paths = list(run_katana(self.url, True, True, hdrs, depth=depth))
            if hdrs:
                seen = set(self.paths)
                for p in discover_links_from_authenticated_page(self.url.rstrip("/") + "/", hdrs, timeout=15):
                    if p not in seen: seen.add(p); self.paths.append(p)
        except Exception as e:
            print(f"[!] Path recon error: {e}", file=sys.stderr)
        return self.paths

    def run_payload(self, paths: list[str] | None = None, refresh: bool = True) -> tuple[dict, dict]:
        from services.payload_recon import run_payload_recon
        ps       = list(paths or self.paths)
        hdrs_list = self.session.headers_list() if self.session else None
        if hdrs_list and self.session and refresh:
            fresh = self.session.refresh()
            if fresh: hdrs_list = fresh
        hdrs = dict(hdrs_list) if hdrs_list else None
        if hdrs:
            skip = ("logout", "signout", "logoff", "/exit", "sign-out", "log-out")
            b4   = len(ps)
            ps   = [p for p in ps if not any(s in urlparse(p).path.lower() for s in skip)]
            if b4 != len(ps):
                print(f"[*] Excluded {b4-len(ps)} session-destructive paths (e.g. logout) from payload recon.")
        valid = []
        for p in ps:
            if not p.startswith("http"): valid.append(p); continue
            try:
                if requests.get(p, headers=hdrs, timeout=5, allow_redirects=True).status_code != 404:
                    valid.append(p)
            except Exception:
                valid.append(p)
        removed = len(ps) - len(valid)
        if removed: print(f"[*] Filtered {removed} paths (404) before payload recon.")
        self.forms, self.params = run_payload_recon(valid, max_workers=1, extra_headers=hdrs)
        return self.forms, self.params

    def print_paths(self) -> None:
        _hdr("PATH RECON (Katana)")
        print(f"Total paths: {len(self.paths)}")
        for p in self.paths: print(f"  {p}")

    def print_forms(self) -> None:
        _hdr("CATEGORY 1: HTML FORMS (POST/GET)")
        for _, d in self.forms.items():
            f = d["details"]
            print(f"\nFound in Paths: {list(d['paths'])}")
            print(f"  - Action: {f['target_action']} [{f['method']}]")
            print(f"  - Parameters: {f['body_params']}")
            if f.get("query_params"): print(f"  - Query String: {f['query_params']}")
        _hdr("CATEGORY 2: URL QUERY PARAMETERS (Inferred Forms)")
        if not self.params: print("No URL parameters discovered.")
        for _, d in self.params.items():
            print(f"\nBase Path: {d['base_path']}")
            print(f"  - Parameters: {d['params']}")
            print(f"  - Sample URLs: {list(d['example_urls'])[:3]}")


# ── TriageEngine ───────────────────────────────────────────────────────
class TriageEngine:
    """Local heuristic triage, Gemini AI triage, post-auth round-2."""

    def __init__(self, url: str, out_file: str = "triage.json"):
        self.url  = url
        self.file = Path(out_file)

    def local(self, forms, params) -> dict:
        from services.local_triage_service import run_local_triage
        return run_local_triage(self.url, forms, params)

    def ai(self, paths, forms, params) -> dict:
        from services.ai_triage_service import run_ai_triage, apply_real_base_to_commands
        t = run_ai_triage(self.url, paths, forms, params, use_localhost_in_prompt=True)
        apply_real_base_to_commands(t, self.url)
        return t

    def post_auth(self, paths, forms, params) -> dict:
        from services.ai_triage_service import (run_ai_triage_round2,
                                                 apply_real_base_to_commands,
                                                 build_post_auth_triage_fallback)
        try:
            t = run_ai_triage_round2(self.url, paths, forms, params, use_localhost_in_prompt=True)
            if t.get("error"):
                print(f"[!] AI Triage Round 2 API error: {t['error']} — using local fallback", file=sys.stderr)
                return build_post_auth_triage_fallback(self.url, paths, forms, params)
            apply_real_base_to_commands(t, self.url)
            return t
        except Exception as e:
            print(f"[!] AI Triage Round 2 failed: {e} — using local fallback", file=sys.stderr)
            from services.ai_triage_service import build_post_auth_triage_fallback
            return build_post_auth_triage_fallback(self.url, paths, forms, params)

    def save(self, t: dict) -> None:
        self.file.write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")

    def load(self) -> dict:
        if not self.file.exists():
            raise FileNotFoundError(f"Triage not found: {self.file}")
        return json.loads(self.file.read_text(encoding="utf-8"))

    def show(self, t: dict, label: str = "TRIAGE") -> None:
        _hdr(label)
        print(f"Saved: {self.file}")
        for item in (t.get("targets") or []):
            if not isinstance(item, dict): continue
            print(f"\n  [{item.get('confidence','')}] {item.get('endpoint')} [{item.get('method')}]")
            print(f"    Suspected: {item.get('suspected_issue_types', [])}")
            for c in (item.get("suggested_commands") or []):
                print(f"    $ {c}")


# ── CommandRunner ──────────────────────────────────────────────────────
class CommandRunner:
    """Execute suggested commands from triage; supports bruter, cookie injection."""

    _DEFAULT_PASS = "SecLists/Passwords/Common-Credentials/10k-most-common.txt"

    def __init__(self, root: Path, session: SessionManager | None = None,
                 results_dir: str = "results", timeout: int = 300):
        self.root     = root
        self.session  = session
        self.timeout  = timeout
        self.results  = root / results_dir
        self.results.mkdir(parents=True, exist_ok=True)
        self._lock    = threading.Lock()
        pf = root / self._DEFAULT_PASS
        self._pass    = pf if pf.exists() else Path("/usr/share/wordlists/rockyou.txt")

    def run(self, triage: dict, min_confidence: str | None = None,
            workers: int = 4, dry_run: bool = False, user_file: str | None = None) -> None:
        targets = _filter_targets(triage.get("targets") or [], min_confidence)
        if not targets:
            print("[!] No targets match filter.", file=sys.stderr)
            return
        cmds, bruters = self._build(targets)
        cookie = self.session.cookie_str() if self.session else None
        print(f"[*] Output directory: {self.results.resolve()}")
        lvl = "high only" if min_confidence == "high" else "high + medium" if min_confidence == "medium" else "all"
        print(f"[*] Mode: min-confidence {lvl}")
        if bruters: print(f"[*] Bruter jobs (form with token): {len(bruters)} (override hydra)")
        if dry_run:
            for cmd, t, *_ in cmds: print(f"  {t}: {cmd[:80]}")
            for j in bruters:       print(f"  bruter: {j['url'][:60]}... (csrf={j['csrf_field']})")
            print("[*] Dry run — no execution.")
            return
        total = len(cmds)
        print(f"[*] Commands to run: {total} (workers: {workers})" +
              (f" + {len(bruters)} bruter job(s) in parallel" if bruters else ""))
        items = [((c, t, s, ti, ci), i+1, total, self.results, self.timeout, cookie)
                 for i, (c, t, s, ti, ci) in enumerate(cmds)]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fs: dict = {ex.submit(self._run_cmd, it): "cmd" for it in items}
            fs |= {ex.submit(self._run_bruter, j, user_file): ("b", j["slug"]) for j in bruters}
            for f in as_completed(fs):
                tag = fs[f]
                try:
                    if tag == "cmd":
                        idx, tool, log, rc, skipped = f.result()
                        msg = (f"[!] Skip (not found): {tool}" if skipped
                               else f"[*] Done [{idx}/{total}] {tool} -> {log}" + (f" (exit {rc})" if rc != 0 else ""))
                    else:
                        log, rc = f.result()
                        msg = f"[*] Bruter [{tag[1]}] -> {log}" + (f" (exit {rc})" if rc != 0 else "")
                    with self._lock: print(msg)
                except Exception as e:
                    with self._lock: print(f"[!] Error: {e}")

    def _build(self, targets: list) -> tuple[list, list]:
        cmds, bruters = [], []
        for ti, t in enumerate(targets):
            ep     = (t.get("endpoint") or "").strip()
            slug   = _slug(ep)
            bp     = t.get("body_params") or {}
            params = list(bp.keys() if isinstance(bp, dict) else bp)
            tok, csrf_f = _has_token(params)
            for ci, cmd in enumerate(t.get("suggested_commands") or []):
                cmd  = (cmd or "").strip()
                if not cmd: continue
                tool = _first_token(cmd)
                if not tool: continue
                if tool.lower() == "hydra" and tok and csrf_f:
                    uf = next((p for p in params if p.lower() in ("username","user","uname","login")),
                               params[0] if params else "username")
                    pf = next((p for p in params if p.lower() in ("password","pass","pwd")), "password")
                    bp_d   = bp if isinstance(bp, dict) else {p: "" for p in params}
                    skip_k = {uf.lower(), pf.lower(), (csrf_f or "").lower()}
                    extra  = "&".join(
                        f"{p}={bp_d.get(p, '') or 'x'}"
                        for p in params if p.lower() not in skip_k
                    )
                    bruters.append({
                        "url": ep if "://" in ep else "", "endpoint": ep,
                        "user_field": uf, "pass_field": pf, "csrf_field": csrf_f,
                        "slug": slug, "ti": ti,
                        "extra": extra,
                        "form_params": bp_d,
                    })
                    continue
                cmds.append((cmd, tool, slug, ti, ci))
        return cmds, bruters

    def _run_cmd(self, item) -> tuple:
        (cmd, tool, slug, ti, ci), idx, total, results, timeout, cookie = item
        if not _available(tool): return (idx, tool, "", -1, True)
        if tool.lower() == "hydra":   cmd = self._fix_hydra(cmd)
        if cookie:                     cmd = self._inject_cookie(cmd, tool, cookie)
        if tool.lower() == "xsstrike" and "--skip" not in cmd: cmd += " --skip"
        safe_tool = re.sub(r"[^\w-]", "_", tool)
        log = f"{safe_tool}_{slug}_{ti}_{ci}.log"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               timeout=timeout, cwd=self.root)
            (results / log).write_text(
                f"# Command:\n{cmd}\n\n# Return code: {r.returncode}\n\n"
                f"# --- stdout ---\n{r.stdout}\n# --- stderr ---\n{r.stderr or ''}",
                encoding="utf-8")
            return (idx, tool, log, r.returncode, False)
        except subprocess.TimeoutExpired:
            return (idx, tool, log, -1, False)
        except Exception:
            return (idx, tool, log, -1, False)

    def _run_bruter(self, job: dict, user_file: str | None = None) -> tuple[str, int]:
        url = job["url"] or (_scheme("127.0.0.1").rstrip("/") + "/" + job["endpoint"].lstrip("/"))
        log = f"bruter_{job['slug']}_{job['ti']}.log"
        pf  = str(self._pass) if self._pass.exists() else "/usr/share/wordlists/rockyou.txt"
        cmd = [sys.executable, str(self.root / "modules" / "bruter.py"),
               "--url", url, "--user-field", job["user_field"],
               "--pass-field", job["pass_field"], "--csrf-field", job["csrf_field"],
               "--pass-file", pf, "--failure-string", "incorrect|failed|login failed|invalid",
               "--output", str(self.results / log)]
        if job.get("extra"):                              cmd += ["--extra", job["extra"]]
        if user_file and Path(user_file).exists():        cmd += ["--user-file", user_file]
        log_path = self.results / log
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(f"# Command: {' '.join(cmd)}\n")
                r = subprocess.run(cmd, cwd=self.root, timeout=self.timeout,
                                   stdout=lf, stderr=lf)
            return log, r.returncode
        except Exception:
            return log, -1

    @staticmethod
    def _fix_hydra(cmd: str) -> str:
        m = re.search(r"(\s)(https?://[^/\s]+(?::\d+)?)(\s+http-post-form)", cmd)
        if m:
            u  = urlparse(m.group(2))
            hp = (f"{u.hostname}:{u.port}" if u.port else
                  f"{u.hostname}:443" if u.scheme == "https" else (u.hostname or ""))
            return cmd.replace(m.group(0), m.group(1) + hp + m.group(3), 1)
        return cmd

    @staticmethod
    def _inject_cookie(cmd: str, tool: str, cookie: str) -> str:
        esc = cookie.replace('"', '\\"')
        t   = tool.lower()

        # ── Step 1: replace ALL placeholder patterns regardless of tool ─────
        # covers: <YOUR_SESSION_COOKIE>  <YOUR_SESSION_COOKIES>
        cmd = re.sub(r"<YOUR_SESSION_COOKIES?>", esc, cmd)
        # covers quoted variants: '<SESSION_COOKIE>'  "<YOUR_SESSION_COOKIE>"
        cmd = re.sub(r"""['"]\s*<[^>]*SESSION[^>]*>\s*['"]""", f'"{esc}"', cmd)

        # ── Step 2: if no cookie flag present at all, append one ────────────
        has_cookie = "--cookie" in cmd or "-b " in cmd or "--headers" in cmd
        if has_cookie:
            # sqlmap: ถ้าใช้ --forms หรือ --data ต้องบอกไม่ให้ test cookie param
            # ไม่งั้นมัน modify PHPSESSID → session ตาย → redirect login
            if t == "sqlmap" and "--level" in cmd and "--skip-waf" not in cmd:
                if "--param-exclude" not in cmd:
                    cmd = cmd.rstrip() + " --param-exclude=PHPSESSID"
            return cmd

        if t in ("sqlmap", "commix"):
            extra = " --param-exclude=PHPSESSID" if t == "sqlmap" else ""
            return cmd.rstrip() + f' --cookie="{esc}"{extra}'
        if t == "xsstrike":
            return cmd.rstrip() + f' --headers "Cookie: {esc}"'
        if t == "curl":
            return cmd.rstrip() + f' -b "{esc}"'
        return cmd


# ── ExploitPipeline ────────────────────────────────────────────────────
class ExploitPipeline:
    """5-phase full exploit: pre-auth → brute → login → post-auth → execute."""

    def __init__(self, url: str, opts: argparse.Namespace):
        self.url         = _scheme(url)
        self.opts        = opts
        self.root        = Path(__file__).resolve().parent
        self.sess        = SessionManager(self.root)
        self.runner      = CommandRunner(self.root, self.sess)
        self.triage_eng  = TriageEngine(self.url)

    def _cleanup_prev_scan(self) -> None:
        """ลบไฟล์จากการ scan ครั้งก่อน ก่อนเริ่ม scan ใหม่"""
        import shutil
        to_delete = [
            self.root / "active_session.json",
            self.root / "triage.json",
            self.root / "credentials.json",
            self.root / "pre_auth_summary.md",
            self.root / "final_report.md",
        ]
        for f in to_delete:
            if f.exists():
                f.unlink()
                print(f"[*] Cleared: {f.name}")
        results_dir = self.runner.results
        if results_dir.exists():
            shutil.rmtree(results_dir)
            results_dir.mkdir(parents=True, exist_ok=True)
            print(f"[*] Cleared: results/")

    def run(self) -> None:
        self._cleanup_prev_scan()
        self._phase("1/5  PRE-AUTH SCAN + TRIAGE", self._scan_pre)
        login = self._find_login()

        # ── ตัดสินว่าต้อง login ก่อนไหม ──────────────────────────────────
        if login:
            if self._is_site_gated():
                # เจอแต่ login / สิ่งที่ต้อง auth → login อัตโนมัติ + ใช้ session ต่อ
                print("[*] Site appears to be fully gated — proceeding with login.")
                use_session = True
            else:
                # มีหน้า public ด้วย → ถามผู้ใช้
                print("\n[?] Site has publicly accessible pages AND a login form.")
                print("    [1] Scan public pages + brute force (credentials only, no post-auth scan)")
                print("    [2] Login first, then scan authenticated pages")
                choice = input("    Choose [1/2]: ").strip()
                use_session = (choice == "2")

            # brute force เสมอ ถ้ามี login form (ทั้ง choice 1 และ 2)
            self._phase("2/5  BRUTE FORCE LOGIN", lambda: self._brute(login))
            creds = self.sess.parse_creds(self.runner.results)

            if use_session:
                if not creds:
                    print("[!] No credentials found. Stopping pipeline."); return
                self._phase("3/5  AUTHENTICATE WITH FOUND CREDENTIALS", lambda: self._auth(login, creds))
                if not self.sess.cookie_path.exists(): return
                self._phase("4/5  POST-AUTH SCAN", self._scan_post)
                self._phase("5/5  EXECUTE EXPLOITS (WITH SESSION)", self._execute)
            else:
                # choice [1]: มีรหัสแล้ว (ถ้าเจอ) แต่ scan public เท่านั้น
                if creds:
                    print(f"[*] Credentials found: {creds[0][0]}:{creds[0][1]} (saved to credentials.json)")
                else:
                    print("[*] No credentials found (brute force unsuccessful).")
                print("[*] Scanning public pages only (no post-auth scan).")
                self._phase("4/5  EXECUTE EXPLOITS (Pre-Auth)", self._execute)
        else:
            # ไม่มี login form เลย → scan ปกติ
            self._phase("4/5  EXECUTE EXPLOITS (Pre-Auth)", self._execute)

        if getattr(self.opts, "json_out", None):
            self._save_exploit_json(self.opts.json_out)
        print(f"\n{'='*60}\n[*] --run-exploit pipeline complete.")
        print(f"[*] Triage       : {self.triage_eng.file}")
        print(f"[*] Results      : {self.runner.results}/")
        print(f"[*] Final report : {self.root / 'final_report.md'}\n{'='*60}")

    def _save_exploit_json(self, output_path: str) -> None:
        """บันทึก full pipeline result เป็น JSON"""
        import json as _json
        from services.nuclei_service import findings_to_dict
        triage = {}
        try:
            triage = self.triage_eng.load()
        except Exception:
            pass
        cred_path = self.root / "credentials.json"
        creds = []
        if cred_path.exists():
            try:
                creds = _json.loads(cred_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        nuclei_findings = getattr(self, "_nuclei_findings", [])
        report = {
            "target":      self.url,
            "session":     str(self.sess.cookie_path) if self.sess.cookie_path.exists() else None,
            "credentials": creds,
            "triage":      triage,
            "nuclei":      findings_to_dict(nuclei_findings),
        }
        Path(output_path).write_text(
            _json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[*] JSON report saved: {output_path}")

    def _is_site_gated(self) -> bool:
        """คืน True ถ้า site ส่วนใหญ่ redirect ไป login (ไม่มีหน้า public จริงๆ).
        ทดสอบโดย sample paths จาก triage — ถ้า >70% redirect ไป login → gated.
        Register ไม่นับเป็น login form.
        """
        try:
            td   = self.triage_eng.load()
        except Exception:
            return False
        targets = [t.get("endpoint", "") for t in (td.get("targets") or [])
                   if not any(x in (t.get("endpoint") or "").lower()
                               for x in ("register", "signup", "newuser"))]
        if not targets:
            return False
        login_keywords = ("login", "signin", "sign-in", "auth", "session")
        login_count = 0
        for ep in targets[:10]:  # sample แค่ 10 อัน
            try:
                r = requests.get(ep, timeout=5, allow_redirects=True)
                if any(k in (r.url or "").lower() for k in login_keywords):
                    login_count += 1
            except Exception:
                pass
        ratio = login_count / min(len(targets), 10)
        return ratio >= 0.7

    def _phase(self, name, fn) -> None:
        _hdr(f"PHASE {name}"); fn()

    def _scan_pre(self) -> None:
        r = ReconEngine(self.url)
        r.run_paths()
        r.print_paths()
        # gobuster หลัง path_recon — ใช้ session เดียวกัน (re-login อัตโนมัติ)
        self._run_gobuster_into(r)
        # davtest หลัง gobuster — ตรวจ upload methods บน paths ที่เจอ
        self._run_davtest_into(r)
        # nuclei — template scan (pre-auth, no cookie)
        self._run_nuclei_into(cookie=None)
        r.run_payload(refresh=False)
        r.print_forms()
        t = self.triage_eng.local(r.forms, r.params)
        self.triage_eng.save(t); self.triage_eng.show(t, "AUTO TRIAGE (Pre-Auth)")
        Path("pre_auth_summary.md").write_text(
            f"# Pre-Auth Scan\n- URL: {self.url}\n- Paths: {len(r.paths)}\n- Forms: {len(r.forms)}\n",
            encoding="utf-8")

    def _run_gobuster_into(self, r: ReconEngine) -> None:
        """รัน gobuster หลัง path_recon แล้ว merge paths เข้า ReconEngine.
        ถ้ามี session → refresh (re-login) ก่อนส่ง cookie ไปกับ gobuster
        เพราะ Katana อาจทำให้ session หมดอายุก่อนหน้า.
        """
        from services.gobuster_service import run_gobuster_dir, parse_gobuster_output
        wl = self.root / "SecLists/Discovery/Web-Content/common.txt"
        if not wl.exists():
            print("[*] Gobuster skipped (wordlist not found)", file=sys.stderr)
            return

        # ── refresh session ก่อน (เหมือน payload_recon) ──────────────────
        hdrs: list[tuple] | None = None
        if hasattr(self, "sess") and self.sess is not None:
            fresh = self.sess.refresh()
            hdrs  = fresh if fresh else self.sess.headers_list()
            if fresh:
                print("[*] Session refreshed before gobuster.")
            else:
                print("[*] Using existing session for gobuster.")

        print(f"[*] Gobuster: {self.url}")
        try:
            out = run_gobuster_dir(
                self.url, str(wl), threads=20, timeout_seconds=10,
                status_codes="200,204,301,302,307,401,403", status_codes_blacklist="",
                extensions=None, user_agent=_UA, follow_redirect=False, insecure_tls=False,
                random_agent=False, retry=False, retry_attempts=3, delay="0s",
                no_error=False, no_progress=True, force=True, quiet=False,
                on_output_line=lambda l: print(f"[gobuster] {l.strip()}") if "(Status:" in l else None,
                extra_headers=hdrs)
            base = self.url.rstrip("/") + "/"
            seen = set(r.paths)
            added = 0
            for f in parse_gobuster_output(out):
                full = urljoin(base, f.path.rstrip("/") or f.path)
                if full not in seen:
                    seen.add(full); r.paths.append(full); added += 1
            print(f"[*] Gobuster added {added} new path(s) (total: {len(r.paths)})")
        except Exception as e:
            print(f"[!] Gobuster error: {e}", file=sys.stderr)

    def _run_nuclei_into(self, cookie: str | None = None) -> None:
        """รัน nuclei บน self.url — ไม่ block pipeline ถ้า error"""
        from services.nuclei_service import (run_nuclei, parse_nuclei_output,
                                              print_nuclei_results, save_nuclei_json)
        _hdr("NUCLEI SCAN")
        print(f"[*] Nuclei: {self.url}  severity=all")
        try:
            raw = run_nuclei(
                self.url,
                severity=None,   # all severities
                cookie=cookie,
                timeout_seconds=300,
                on_output_line=lambda l: print(f"[nuclei] {l.rstrip()}") if l.strip() else None,
            )
            findings = parse_nuclei_output(raw)
            print_nuclei_results(findings)
            # auto-save JSON
            label = "nuclei_post_auth" if cookie else "nuclei_pre_auth"
            out   = self.runner.results / f"{label}_findings.json"
            save_nuclei_json(findings, str(out))
            print(f"[*] Nuclei findings saved: {out}")
            # เก็บสำหรับ final JSON report
            self._nuclei_findings = getattr(self, "_nuclei_findings", []) + findings
        except RuntimeError as e:
            print(f"[!] Nuclei error: {e}", file=sys.stderr)

    def _run_davtest_into(self, r: ReconEngine) -> None:
        """รัน DAVTest หลัง gobuster แล้วแสดงผล (ไม่ block pipeline ถ้า error)"""
        from services.davtest_service import run_davtest, print_davtest_results
        wl = self.root / "wordlist" / "path.txt"
        if not wl.exists():
            print("[*] DAVTest skipped (wordlist/path.txt not found)", file=sys.stderr)
            return
        hdrs = None
        if hasattr(self, "sess") and self.sess is not None:
            raw = self.sess.headers_list()
            hdrs = dict(raw) if raw else None
        _hdr("DAVTEST (WebDAV / Upload Method Probe)")
        print(f"[*] DAVTest: probing {len(r.paths)} paths against wordlist/path.txt")
        try:
            results = run_davtest(self.url, r.paths, str(wl),
                                  session_headers=hdrs, timeout=10)
            print_davtest_results(results)
        except Exception as e:
            print(f"[!] DAVTest error: {e}", file=sys.stderr)

    def _find_login(self) -> dict | None:
        try:
            td = self.triage_eng.load()
        except Exception:
            print("[!] No triage.json. Aborting pipeline."); return None
        for t in (td.get("targets") or []):
            bp   = t.get("body_params") or {}
            keys = [k.lower() for k in (bp.keys() if isinstance(bp, dict) else bp)]
            if (any(k in keys for k in ("username","user","uname","login")) and
                    any(k in keys for k in ("password","pass","pwd"))):
                return t
        print("[!] No login form found in triage. Pre-auth scan complete (no login detected).")
        return None

    def _brute(self, login: dict) -> None:
        bp     = login.get("body_params") or {}
        bp_d   = bp if isinstance(bp, dict) else {k: "" for k in bp}
        keys   = list(bp_d.keys())
        uf     = next((k for k in keys if k.lower() in ("username","user","uname","login")), "username")
        pf     = next((k for k in keys if k.lower() in ("password","pass","pwd")), "password")
        cf     = next((k for k in keys if any(t in k.lower() for t in _TOK_KEYS)), None)
        # fields ที่เหลือ (เช่น Login=Login, submit button) ต้องส่งไปด้วยไม่งั้น server บางตัวไม่ process
        skip   = {(uf or "").lower(), (pf or "").lower(), (cf or "").lower()}
        extra  = "&".join(
            f"{k}={bp_d.get(k, 'x') or 'x'}"
            for k in keys if k.lower() not in skip
        )
        ep     = (login.get("endpoint") or "").strip()
        if "://" not in ep: ep = self.url.rstrip("/") + "/" + ep.lstrip("/")
        pp     = self.root / "SecLists/Passwords/Common-Credentials/10k-most-common.txt"
        log    = self.runner.results / "bruter_exploit_pipeline.log"
        cmd    = [sys.executable, str(self.root / "modules" / "bruter.py"),
                  "--url", ep, "--user-field", uf, "--pass-field", pf,
                  "--pass-file", str(pp) if pp.exists() else "/usr/share/wordlists/rockyou.txt",
                  "--failure-string", "incorrect|failed|login failed|invalid",
                  "--output", str(log)]
        if cf:    cmd += ["--csrf-field", cf]
        if extra: cmd += ["--extra", extra]
        if getattr(self.opts, "user_file", None) and Path(self.opts.user_file).exists():
            cmd += ["--user-file", self.opts.user_file]
        print(f"[*] Target  : {ep}")
        print(f"[*] Fields  : user={uf}  pass={pf}" + (f"  csrf={cf}" if cf else ""))
        if extra: print(f"[*] Extra   : {extra}")
        subprocess.run(cmd, cwd=self.root)

    def _auth(self, login: dict, creds: list) -> None:
        bp     = login.get("body_params") or {}
        bp_d   = bp if isinstance(bp, dict) else {k: "" for k in bp}
        keys   = list(bp_d.keys())
        cf     = next((k for k in keys if any(t in k.lower() for t in _TOK_KEYS)), None)
        ep     = (login.get("endpoint") or "").strip()
        if "://" not in ep: ep = self.url.rstrip("/") + "/" + ep.lstrip("/")
        for user, pwd in creds[:3]:
            if self.sess.login(ep, user, pwd, bp_d, cf or "user_token"):
                self.sess.save_creds(ep, user, pwd, bp_d, cf or "user_token")
                print(f"[*] Authenticated as {user}:****  →  active_session.json saved")
                return
        print("[!] Login failed with found credentials. Stopping pipeline.")
        # clear cookie_path so pipeline aborts
        if self.sess.cookie_path.exists():
            self.sess.cookie_path.unlink(missing_ok=True)

    def _scan_post(self) -> None:
        r = ReconEngine(self.url, self.sess)
        r.run_paths()
        r.print_paths()
        # gobuster หลัง Katana — re-login อัตโนมัติก่อนส่ง session cookie ไป
        self._run_gobuster_into(r)
        # davtest หลัง gobuster — ตรวจ upload methods (authenticated)
        self._run_davtest_into(r)
        # nuclei — template scan พร้อม session cookie
        cookie_str = self.sess.cookie_str() if self.sess else None
        self._run_nuclei_into(cookie=cookie_str)
        r.run_payload()
        r.print_forms()
        t2 = self.triage_eng.post_auth(r.paths, r.forms, r.params)
        self.triage_eng.save(t2)
        self.triage_eng.show(t2, "AI TRIAGE ROUND 2 (Post-Auth: IDOR, Access Control)")
        self._write_report(t2, r.paths)

    def _execute(self) -> None:
        try:
            triage = self.triage_eng.load()
        except Exception as e:
            print(f"[!] Cannot load triage: {e}"); return
        self.runner.session = self.sess
        self.runner.run(triage, min_confidence="medium", workers=getattr(self.opts, "workers", 4))

    def _write_report(self, triage2: dict, paths: list) -> None:
        pre_path = Path("pre_auth_summary.md")
        pre_c    = pre_path.read_text(encoding="utf-8") if pre_path.exists() else "See results/ from pre-auth scan.\n"
        targets  = triage2.get("targets") or []
        lines    = ["## Post-Auth Scan", f"- URL: {self.url}", f"- Paths discovered: {len(paths)}",
                    "", "### Triage Round 2 (IDOR / Access Control)", ""]
        for t in targets:
            if not isinstance(t, dict): continue
            lines.append(f"- **{t.get('endpoint')}** [{t.get('method')}]")
            lines.append(f"  - Suspected: {', '.join(t.get('suspected_issue_types') or [])}")
            for c in (t.get("suggested_commands") or []):    lines.append(f"  - `$ {c}`")
            for c in (t.get("recommended_manual_checks") or [])[:5]: lines.append(f"  - {c}")
            lines.append("")
        body = ("# OneClickScan V2 – Final Report\n\n## Pre-Auth\n\n"
                + pre_c + "\n\n" + "\n".join(lines))
        Path("final_report.md").write_text(body, encoding="utf-8")
        print("[*] Report written: final_report.md")


# ── ScanMode ───────────────────────────────────────────────────────────
class ScanMode:
    """Manual scan mode (recon + optional triage). Equivalent to old main.py."""

    def __init__(self, url: str, opts: argparse.Namespace):
        self.url        = _scheme(url)
        self.opts       = opts
        self.root       = Path(__file__).resolve().parent
        cf              = getattr(opts, "cookie_file", None)
        self.sess       = SessionManager(self.root, cf) if cf else None
        self.recon      = ReconEngine(self.url, self.sess)
        self.triage_eng = TriageEngine(self.url, getattr(opts, "ai_triage_output", "triage.json"))

    def run(self) -> None:
        o = self.opts
        if o.path_recon or o.payload_recon:
            self.recon.run_paths()
            if o.path_recon: self.recon.print_paths()
        if getattr(o, "gobuster",   False): self._gobuster()
        if getattr(o, "davtest",    False): self._davtest()
        if getattr(o, "nuclei",     False): self._nuclei()
        if getattr(o, "nmap",       False): self._nmap()
        if getattr(o, "whatweb",    False): self._whatweb()
        if getattr(o, "subfinder",  False): self._subfinder()
        if o.payload_recon:
            self.recon.run_payload()
            self.recon.print_forms()
        if getattr(o, "auto_triage", False):
            if self.recon.forms or self.recon.params:
                t = self.triage_eng.local(self.recon.forms, self.recon.params)
                self.triage_eng.save(t); self.triage_eng.show(t, "AUTO TRIAGE (Local – no Gemini)")
            else:
                print("[!] Auto triage skipped (no forms/params).", file=sys.stderr)
        if getattr(o, "ai_triage", False):
            if self.recon.paths:
                try:
                    t = self.triage_eng.ai(self.recon.paths, self.recon.forms, self.recon.params)
                    self.triage_eng.save(t); self.triage_eng.show(t, "AI TRIAGE (Gemini)")
                except Exception as e:
                    print(f"[!] AI triage error: {e}", file=sys.stderr)
            else:
                print("[!] AI triage skipped (no paths).", file=sys.stderr)
        if not getattr(o, "post_auth", False) and (self.recon.paths or self.recon.forms):
            Path("pre_auth_summary.md").write_text(
                f"# Pre-Auth Scan\n- URL: {self.url}\n- Paths: {len(self.recon.paths)}\n"
                f"- Forms: {len(self.recon.forms)}\n- Query-only: {len(self.recon.params)}\n",
                encoding="utf-8")
        if getattr(o, "post_auth", False):
            paths = list(set(self.recon.paths))
            if paths or self.recon.forms:
                t2 = self.triage_eng.post_auth(paths, self.recon.forms, self.recon.params)
                self.triage_eng.save(t2)
                self.triage_eng.show(t2, "AI TRIAGE ROUND 2 (Post-Auth: IDOR, Access Control)")
                ExploitPipeline(self.url, o)._write_report(t2, paths)

        # ── JSON report รวม (ถ้า --json-out) ──────────────────────────────
        if getattr(o, "json_out", None):
            self._save_json_report(o.json_out)

    def _save_json_report(self, output_path: str) -> None:
        """บันทึก full scan result เป็น JSON เดียว"""
        import json as _json
        from services.nuclei_service import findings_to_dict
        # forms: แปลง set → list
        def _serialize_forms(forms: dict) -> list:
            out = []
            for sig, data in (forms or {}).items():
                det = (data.get("details") or {}) if isinstance(data, dict) else {}
                out.append({
                    "signature": sig,
                    "method":    det.get("method", ""),
                    "action":    det.get("target_action", ""),
                    "body_params":  det.get("body_params", {}),
                    "query_params": det.get("query_params", {}),
                })
            return out
        def _serialize_params(params: dict) -> list:
            out = []
            for sig, ep in (params or {}).items():
                if isinstance(ep, dict):
                    out.append({"base_path": ep.get("base_path",""), "params": ep.get("params",{})})
            return out
        triage = {}
        try:
            triage = self.triage_eng.load()
        except Exception:
            pass
        nuclei_findings = getattr(self, "_nuclei_findings", [])
        report = {
            "target":   self.url,
            "paths":    self.recon.paths,
            "forms":    _serialize_forms(self.recon.forms),
            "params":   _serialize_params(self.recon.params),
            "triage":   triage,
            "nuclei":   findings_to_dict(nuclei_findings),
        }
        Path(output_path).write_text(
            _json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[*] JSON report saved: {output_path}")

    def _gobuster(self) -> None:
        from services.gobuster_service import run_gobuster_dir, parse_gobuster_output
        wl   = str(self.root / "SecLists/Discovery/Web-Content/common.txt")
        hdrs = self.sess.headers_list() if self.sess else None
        print(f"[*] Gobuster started: url={self.url} threads=20 wordlist={wl}")
        try:
            out = run_gobuster_dir(
                self.url, wl, threads=20, timeout_seconds=10,
                status_codes="200,204,301,302,307,401,403", status_codes_blacklist="",
                extensions=None, user_agent=_UA, follow_redirect=False, insecure_tls=False,
                random_agent=False, retry=False, retry_attempts=3, delay="0s",
                no_error=False, no_progress=True, force=True, quiet=False,
                on_output_line=lambda l: print(f"[gobuster] {l.strip()}") if "(Status:" in l else None,
                extra_headers=hdrs)
            _hdr("GOBUSTER DIR (Hidden paths)")
            findings = parse_gobuster_output(out)
            base = self.url.rstrip("/") + "/"
            seen: set[str] = set()
            shown: list[str] = []
            for f in findings:
                full = urljoin(base, f.path.rstrip("/") or f.path)
                if full not in seen: seen.add(full); shown.append(full)
            print(f"Total findings: {len(shown)}")
            for u in shown[:100]: print(f"  {u}")
            if len(shown) > 100: print(f"  ... and {len(shown)-100} more")
            self.recon.paths.extend(shown)
        except Exception as e:
            print(f"[!] Gobuster error: {e}", file=sys.stderr)

    def _nuclei(self) -> None:
        from services.nuclei_service import (run_nuclei, parse_nuclei_output,
                                              print_nuclei_results, save_nuclei_json)
        hdrs   = dict(self.sess.headers_list()) if self.sess and self.sess.headers_list() else None
        cookie = hdrs.pop("Cookie", None) if hdrs else None
        tags   = getattr(self.opts, "nuclei_tags", None)
        sev_raw = getattr(self.opts, "nuclei_severity", None)
        sev    = sev_raw.split(",") if sev_raw else None   # None = all severities
        _hdr("NUCLEI SCAN")
        print(f"[*] Nuclei: {self.url}"
              + (f"  severity={','.join(sev)}" if sev else "  severity=all")
              + (f"  tags={tags}" if tags else ""))
        try:
            raw = run_nuclei(
                self.url,
                tags=tags.split(",") if tags else None,
                severity=sev,
                cookie=cookie,
                extra_headers=hdrs,
                timeout_seconds=getattr(self.opts, "timeout", 300),
                on_output_line=lambda l: print(f"[nuclei] {l.rstrip()}") if l.strip() else None,
            )
            findings = parse_nuclei_output(raw)
            print_nuclei_results(findings)
            # auto-save JSON
            out_dir = self.root / getattr(self.opts, "results_dir", "results")
            out_dir.mkdir(parents=True, exist_ok=True)
            save_nuclei_json(findings, str(out_dir / "nuclei_findings.json"))
            print(f"[*] Nuclei findings saved: {out_dir / 'nuclei_findings.json'}")
            # เก็บไว้สำหรับ --json-out รวม
            self._nuclei_findings = findings
        except RuntimeError as e:
            print(f"[!] Nuclei error: {e}", file=sys.stderr)

    def _davtest(self) -> None:
        from services.davtest_service import run_davtest, print_davtest_results
        wl   = str(self.root / "wordlist" / "path.txt")
        hdrs = dict(self.sess.headers_list()) if self.sess and self.sess.headers_list() else None
        _hdr("DAVTEST (WebDAV / Upload Method Probe)")
        print(f"[*] DAVTest: probing {len(self.recon.paths)} paths against wordlist/path.txt")
        try:
            results = run_davtest(self.url, self.recon.paths, wl,
                                  session_headers=hdrs, timeout=10)
            print_davtest_results(results)
        except Exception as e:
            print(f"[!] DAVTest error: {e}", file=sys.stderr)

    def _nmap(self) -> None:
        from services.nmap_service import run_nmap_scan, parse_nmap_services, get_cve_info
        host = urlparse(self.url).netloc or self.url
        try:
            out = run_nmap_scan(host, getattr(self.opts, "nmap_ports", 20))
            _hdr("NMAP SERVICE SCAN"); print(out)
            for p, svc, ver in parse_nmap_services(out):
                print(f"[+] Service: {p} | {ver}")
                print(f"    [>] CVE/Exploit: {get_cve_info(svc, ver)}")
        except Exception as e:
            print(f"[!] Nmap error: {e}", file=sys.stderr)

    def _whatweb(self) -> None:
        from services.whatweb_service import (run_whatweb, parse_whatweb_output,
                                               filter_versioned_findings, exploit_db_search_link)
        from services.cve_service import search_cves_by_query
        try:
            out = run_whatweb(self.url)
            _hdr("WHATWEB FINGERPRINT"); print(out.strip())
            seen: set[str] = set()
            for f in filter_versioned_findings(parse_whatweb_output(out)):
                key = f"{f.product.lower()} {f.version}"
                if key in seen or not f.version: continue
                seen.add(key)
                print(f"[+] {f.product} {f.version} (from {f.plugin}[{f.value}])")
                print(f"    [>] Check Exploits: {exploit_db_search_link(f.query)}")
                if getattr(self.opts, "whatweb_cve", False):
                    for c in search_cves_by_query(f.query, limit=getattr(self.opts, "whatweb_cve_limit", 5)):
                        print(f"    [CVE] {c.cve} - {c.summary[:120]}")
        except Exception as e:
            print(f"[!] WhatWeb error: {e}", file=sys.stderr)

    def _subfinder(self) -> None:
        from services.subfinder_service import get_root_domain, run_subfinder
        from services.httpx_service import run_httpx
        root = get_root_domain(self.url)
        if not root: return
        scheme = urlparse(self.url).scheme or "http"
        try:
            subs  = run_subfinder(root)
            # ส่ง bare hostname — httpx probe ทั้ง http+https เอง
            alive = run_httpx(subs) if subs else []
            _hdr("SUBFINDER (Subdomains)")
            print(f"Root domain: {root}")
            print(f"Total found: {len(subs)}  |  Alive (httpx): {len(alive)}")
            for u in alive[:200]: print(f"  {u}")
            if len(alive) > 200: print(f"  ... and {len(alive)-200} more")
        except Exception as e:
            print(f"[!] Subfinder error: {e}", file=sys.stderr)


# ── ExecMode ───────────────────────────────────────────────────────────
class ExecMode:
    """Run commands from existing triage.json + optional post-exploit loop."""

    def __init__(self, triage_file: str, opts: argparse.Namespace):
        self.root        = Path(__file__).resolve().parent
        self.triage_file = triage_file
        self.opts        = opts
        cf               = getattr(opts, "cookie_file", None)
        self.sess        = SessionManager(self.root, cf) if cf else None
        self.runner      = CommandRunner(
            self.root, self.sess,
            results_dir=getattr(opts, "results_dir", "results"),
            timeout=getattr(opts, "timeout", 300))

    def run(self) -> None:
        try:
            triage = TriageEngine("", self.triage_file).load()
        except FileNotFoundError as e:
            print(f"[!] {e}", file=sys.stderr); sys.exit(1)
        mc = (getattr(self.opts, "min_confidence", None)
              or ("high" if getattr(self.opts, "high_only", False) else None))
        self.runner.run(triage, min_confidence=mc,
                        workers=max(1, getattr(self.opts, "workers", 4)),
                        dry_run=getattr(self.opts, "dry_run", False),
                        user_file=getattr(self.opts, "user_file", None))
        if not getattr(self.opts, "dry_run", False) and not getattr(self.opts, "no_rescan_prompt", False):
            self._post_exploit(triage)
        print("[*] Done.")

    def _post_exploit(self, triage: dict) -> None:
        sess  = self.sess or SessionManager(self.root)
        creds = sess.parse_creds(self.runner.results)
        if not creds: return
        lt = next((t for t in (triage.get("targets") or [])
                   if any(k in [str(x).lower() for x in (t.get("body_params") or {}).keys()]
                          for k in ("username","user","uname","login"))
                   and any(k in [str(x).lower() for x in (t.get("body_params") or {}).keys()]
                           for k in ("password","pass","pwd"))), None)
        if not lt: return
        ep   = (lt.get("endpoint") or "").strip()
        bp   = lt.get("body_params") or {}
        bp_d = bp if isinstance(bp, dict) else {k: "" for k in bp}
        keys = list(bp_d.keys())
        cf   = next((k for k in keys if any(t in k.lower() for t in _TOK_KEYS)), "user_token")
        base = (f"{urlparse(ep).scheme}://{urlparse(ep).netloc}/" if "://" in ep
                else (triage.get("base_url") or "").rstrip("/") + "/")
        new_sess = SessionManager(self.root)
        logged = False
        for user, pwd in creds[:3]:
            if new_sess.login(ep, user, pwd, bp_d, cf):
                new_sess.save_creds(ep, user, pwd, bp_d, cf)
                print(f"[*] Post-exploit login OK: {user}:**** -> {new_sess.cookie_path}")
                logged = True; break
        if not logged or not new_sess.cookie_path.exists(): return
        try:
            print("\n[*] ต้องการเริ่ม High-Level Scan ในฐานะ User หรือไม่? (Y/N): ", end="")
            if input().strip().upper() != "Y": return
            cmd = [sys.executable, str(Path(__file__)), "scan",
                   "-u", base.rstrip("/"),
                   "--path-recon", "--payload-recon",
                   "--cookie-file", str(new_sess.cookie_path), "--post-auth"]
            while True:
                print(f"[*] Running: {' '.join(cmd)}")
                subprocess.run(cmd, cwd=self.root)
                print("\n[*] ต้องการสแกนต่ออีกหรือไม่? (Y/N): ", end="")
                if input().strip().upper() != "Y": break
        except (EOFError, KeyboardInterrupt):
            pass


# ── CLI ────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="executor.py",
        description="OneClickScan V2 — web pentest tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python executor.py -u http://target --path-recon --payload-recon --auto-triage\n"
            "  python executor.py -u http://target --all\n"
            "  python executor.py -u http://target --run-exploit\n"
            "  python executor.py --min-confidence medium --workers 6\n"
            "  python executor.py triage.json --min-confidence medium\n"
        ),
    )
    # ── target ──
    parser.add_argument("positional",       nargs="?", default=None,
                        metavar="URL_or_FILE",
                        help="Target URL (scan/exploit) or triage.json path (exec)")
    parser.add_argument("-u", "--url",      dest="url", metavar="URL",
                        help="Target URL (alternative to positional)")
    # ── scan flags ──
    parser.add_argument("--path-recon",     action="store_true", help="Katana path crawl")
    parser.add_argument("--payload-recon",  action="store_true", help="Form + param extraction")
    parser.add_argument("--auto-triage",    action="store_true", help="Local heuristic triage (no Gemini)")
    parser.add_argument("--ai-triage",      action="store_true", help="Gemini AI triage")
    parser.add_argument("--ai-triage-output", default="triage.json", metavar="FILE")
    parser.add_argument("--nmap",           action="store_true")
    parser.add_argument("--nmap-ports",     type=int, default=20, metavar="N")
    parser.add_argument("--whatweb",        action="store_true")
    parser.add_argument("--whatweb-cve",    action="store_true")
    parser.add_argument("--whatweb-cve-limit", type=int, default=5, metavar="N")
    parser.add_argument("--gobuster",       action="store_true")
    parser.add_argument("--davtest",        action="store_true",
                        help="Probe discovered paths for WebDAV/PUT upload methods (runs after gobuster)")
    parser.add_argument("--nuclei",         action="store_true",
                        help="Run nuclei template scan (cve, misconfig, exposure, ...)")
    parser.add_argument("--nuclei-tags",    default=None, metavar="TAGS",
                        help="Comma-separated nuclei tags, e.g. cve,sqli,xss (default: cve,misconfig,exposure,...)")
    parser.add_argument("--nuclei-severity", default=None, metavar="SEV",
                        help="Comma-separated severity filter, e.g. critical,high,medium (default: critical,high,medium)")
    parser.add_argument("--subfinder",      action="store_true")
    parser.add_argument("--all",            action="store_true",
                        help="Enable path-recon + payload-recon + nmap + whatweb + gobuster + davtest + nuclei + subfinder")
    parser.add_argument("--cookie-file",    default=None, metavar="FILE",
                        help="Session cookie file (active_session.json)")
    parser.add_argument("--post-auth",      action="store_true",
                        help="Post-auth mode: AI triage round-2 + final_report.md")
    parser.add_argument("--run-exploit",    action="store_true",
                        help="Full pipeline: scan → brute force → post-auth → exploit")
    # ── exec flags ──
    parser.add_argument("--high-only",      action="store_true")
    parser.add_argument("--min-confidence", choices=["high","medium","low"], metavar="LEVEL")
    parser.add_argument("--dry-run",        action="store_true")
    parser.add_argument("--results-dir",    default="results", metavar="DIR")
    parser.add_argument("--timeout",        type=int, default=300, metavar="SEC")
    parser.add_argument("--workers",        type=int, default=4,   metavar="N")
    parser.add_argument("--no-rescan-prompt", action="store_true")
    parser.add_argument("--json-out",        default=None, metavar="FILE",
                        help="Save full scan result as JSON (e.g. scan_result.json)")
    parser.add_argument("--user-file",      default=None, metavar="FILE")
    parser.add_argument("--pass-file",      default=None, metavar="FILE")

    args = parser.parse_args()

    # ── resolve URL vs triage file ──
    url        = args.url or (args.positional if args.positional and not args.positional.endswith(".json") else None)
    triage_file = (args.positional if args.positional and args.positional.endswith(".json")
                   else "triage.json")

    _scan_flags = (args.path_recon or args.payload_recon or args.nmap or args.whatweb
                   or args.gobuster or args.davtest or args.nuclei or args.subfinder
                   or args.auto_triage or args.ai_triage
                   or args.post_auth or args.all or args.run_exploit)

    # ── dispatch ──
    if args.run_exploit:
        if not url: parser.error("--run-exploit requires -u URL")
        ExploitPipeline(url, args).run()

    elif url and _scan_flags:
        if args.all:
            args.path_recon = args.payload_recon = True
            args.nmap = args.whatweb = args.gobuster = args.davtest = args.nuclei = args.subfinder = True
        if args.ai_triage or args.auto_triage:
            args.payload_recon = True
        ScanMode(url, args).run()

    else:
        # exec mode: run commands from triage.json
        if args.high_only:
            args.min_confidence = "high"
        if args.all:
            args.min_confidence = None
        ExecMode(triage_file, args).run()


if __name__ == "__main__":
    main()
