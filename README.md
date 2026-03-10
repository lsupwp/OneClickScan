# OneClickScan V2

ระบบ Web Penetration Testing แบบ automated ที่รันจาก URL เดียว ครอบคลุมตั้งแต่ reconnaissance จนถึง post-exploitation session capture

> **สำหรับ authorized pentest เท่านั้น** — ห้ามใช้กับเป้าหมายที่ไม่ได้รับอนุญาต

---

## สิ่งที่ต้องติดตั้ง

### Python dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # สำหรับ SPA crawling
```

### External tools (Ubuntu/Debian)
```bash
chmod +x install_tools.sh
./install_tools.sh
```

จะติดตั้ง: **katana**, **nmap**, **whatweb**, **gobuster**, **subfinder**, **httpx**, **sqlmap**, **xsstrike**, **hydra**, **commix**

- จาก apt: `nmap`, `whatweb`, `gobuster`, `hydra`
- จาก Go: `katana`, `subfinder`, `httpx` (ใน `$GOPATH/bin`)
- จาก git + symlink ใน `~/.local/bin`: `sqlmap`, `xsstrike`, `commix` (โฟลเดอร์เก็บที่ `$HOME/tools` หรือกำหนด `INSTALL_DIR=/path/to/tools ./install_tools.sh`)

หลังติดตั้ง: รัน `source ~/.bashrc` หรือเปิด terminal ใหม่

### API Key (สำหรับ --ai-triage)
```bash
echo "GOOGLE_API_KEY=your_key_here" > .env
```

ถ้าไม่มี API key ให้ใช้ `--auto-triage` แทนได้ (heuristic-based, ไม่ต้องใช้ Gemini)

---

## วิธีใช้งาน

### ขั้นตอนที่ 1: Reconnaissance + Triage
```bash
# เร็ว (ไม่ใช้ Gemini)
python main.py -u http://target.com --path-recon --payload-recon --auto-triage

# ใช้ Gemini วิเคราะห์
python main.py -u http://target.com --path-recon --payload-recon --ai-triage

# ทุกอย่างพร้อมกัน
python main.py -u http://target.com --all --auto-triage
```

output จะได้:
- `triage.json` — รายการ endpoint ที่น่าสนใจ + suggested commands

### ขั้นตอนที่ 2: Execute Commands + Brute Force
```bash
# รัน commands ทั้งหมดจาก triage.json
python executor.py

# กรองเฉพาะ confidence สูง
python executor.py --min-confidence high --workers 6

# รวม medium ด้วย
python executor.py --min-confidence medium --workers 6
```

executor จะทำ:
1. รัน sqlmap, xsstrike จาก `triage.json` (concurrent)
2. ถ้าเจอ form ที่มี CSRF token → รัน `bruter.py` แทน hydra
3. ถ้าพบ credentials → login จริงและบันทึก `active_session.json`
4. ถามว่าต้องการ High-Level Scan (authenticated) หรือไม่

### ขั้นตอนที่ 3: Authenticated Scan (Post-Exploitation)
หลังจาก executor พบ credentials ระบบจะถาม:
```
[*] ต้องการเริ่ม High-Level Scan ในฐานะ User หรือไม่? (Y/N):
```
กด `Y` เพื่อให้รัน main.py ด้วย session cookie อัตโนมัติ (ค้นหา IDOR, Access Control, Privilege Escalation)

หรือรันเองได้:
```bash
python main.py -u http://target.com --path-recon --payload-recon \
  --cookie-file active_session.json --post-auth
```

### Options ทั้งหมดของ main.py

| Option | ความหมาย |
|--------|-----------|
| `-u URL` | Target URL |
| `--path-recon` | Crawl paths ด้วย Katana (depth 5) |
| `--payload-recon` | Extract forms และ URL parameters |
| `--nmap` | Nmap service scan |
| `--whatweb` | Technology fingerprint + CVE links |
| `--whatweb-cve` | Query CVE database สำหรับ versions ที่เจอ |
| `--gobuster` | Directory brute-force |
| `--subfinder` | Subdomain enumeration |
| `--all` | รัน path-recon + payload-recon + nmap + whatweb + gobuster + subfinder |
| `--auto-triage` | Local triage ไม่ต้องใช้ Gemini |
| `--ai-triage` | Gemini AI triage |
| `--cookie-file FILE` | ใช้ session cookies จากไฟล์ (authenticated crawl) |
| `--post-auth` | Post-auth scan: IDOR, Access Control, Privilege Escalation |

### Options ของ executor.py

| Option | ความหมาย |
|--------|-----------|
| `--min-confidence high\|medium\|low` | กรอง targets ตาม confidence |
| `--high-only` | เฉพาะ high confidence |
| `--workers N` | จำนวน workers (default 4) |
| `--dry-run` | แสดง commands แต่ไม่รัน |
| `--cookie-file FILE` | inject session cookie เข้า sqlmap/xsstrike |
| `--user-file FILE` | custom username list สำหรับ bruter |
| `--pass-file FILE` | custom password list สำหรับ bruter |

---

## โครงสร้างไฟล์

```
OneClickScanV2/
├── main.py               # Entry point หลัก
├── executor.py           # รัน commands จาก triage.json + post-exploitation
├── bruter.py             # Brute force login forms ที่มี CSRF token
├── services/
│   ├── path_recon.py     # Katana crawling + authenticated link extraction
│   ├── payload_recon.py  # Form extraction + URL parameter analysis
│   ├── nmap_service.py   # Nmap integration
│   ├── whatweb_service.py    # WhatWeb fingerprinting
│   ├── cve_service.py    # CVE lookup
│   ├── gobuster_service.py   # Gobuster integration
│   ├── subfinder_service.py  # Subdomain enumeration
│   ├── httpx_service.py  # HTTP probe (alive check)
│   ├── ai_triage_service.py  # Gemini AI triage + local fallback
│   └── local_triage_service.py   # Heuristic triage (ไม่ใช้ Gemini)
├── SecLists/             # Wordlists (ต้อง clone แยก)
├── .env                  # API keys (ไม่ commit)
├── triage.json           # Output: triage results
├── active_session.json   # Output: authenticated session cookies
├── final_report.md       # Output: combined pre/post-auth report
└── results/              # Output: tool logs
```

---

## สิ่งที่ทำแล้ว

### Core Features
- **Path Recon** — Katana crawl depth 5 + SPA hash route detection
- **Payload Recon** — Form extraction จากทุก path พร้อม URL parameter grouping
- **Nmap** — Service scan + version detection + CVE links
- **WhatWeb** — Technology fingerprint + Exploit-DB links
- **Gobuster** — Directory brute-force พร้อม dynamic `--exclude-length`
- **Subfinder + Httpx** — Subdomain discovery + alive probing

### Triage
- **Auto Triage** — Heuristic-based command generation (sqlmap, hydra, xsstrike, commix) ไม่ต้อง Gemini
- **AI Triage** — ส่ง recon ให้ Gemini วิเคราะห์และ suggest commands
- **Fallback** — ถ้า Gemini 503/429 จะใช้ local fallback อัตโนมัติ

### Post-Exploitation
- **Smart CSRF Detection** — ตรวจจับ form ที่มี token (csrf, user_token) → ใช้ `bruter.py` แทน hydra
- **CSRF-Aware Bruter** — `bruter.py` ดึง token ใหม่ทุก request ด้วย shared session
- **Post-Exploit Login** — หลังพบ credentials → login จริงด้วย `requests.Session` + บันทึก cookies
- **Authenticated Crawl** — Katana + payload_recon ส่ง Cookie headers สำหรับ authenticated paths
- **Link Discovery** — `discover_links_from_authenticated_page()` ดึงลิงก์จาก HTML จริงหลัง login (ไม่ hardcode paths)
- **AI Triage Round 2** — วิเคราะห์เน้น IDOR, Privilege Escalation, Broken Access Control
- **Final Report** — รวม pre-auth + post-auth ลง `final_report.md`

---

## ปัญหาที่พบและยังไม่ได้แก้

### 1. CATEGORY 1 ไม่เห็น Forms จาก Authenticated Pages
**อาการ**: หลัง login สำเร็จและ Katana พบ vulnerability pages ครบ แต่ payload_recon กลับเห็นเฉพาะ `login.php` และ `setup.php`

**สาเหตุที่สงสัย**: PHP session ที่ใช้ใน payload_recon อาจเป็น stale session จาก run ก่อนหน้า หรือ session ถูก invalidate โดย parallel requests จาก Katana ระหว่าง crawl (PHP file-based session locking + concurrent requests)

**ทดสอบแล้ว**: ถ้า login fresh ทันทีก่อน run payload_recon จะเห็น forms ครบ (xss, sqli, exec, upload, brute ฯลฯ)

**Workaround ชั่วคราว**: รัน `--path-recon --payload-recon --cookie-file` แยกสองรอบ โดย login ใหม่ก่อนรอบ payload-recon

### 2. Gemini Free Tier Quota (20 req/day)
**อาการ**: `429 RESOURCE_EXHAUSTED` ถ้าใช้ `--ai-triage` มากกว่า 20 ครั้งต่อวัน

**Workaround**: ใช้ `--auto-triage` แทน (ไม่ต้องใช้ Gemini, heuristic-based)

### 3. Katana ช้าเมื่อใช้ depth 5 บน target ขนาดใหญ่
**อาการ**: ใช้เวลา 2-5 นาทีสำหรับ site ใหญ่

**Workaround**: ยังไม่มี option ปรับ depth จาก CLI (hardcode ที่ depth=5 ใน `path_recon.py`)

### 4. Form Action ที่เป็น `#` บนบางหน้าของ DVWA
**สถานะ**: แก้แล้ว — `_extract_forms_from_html` ทำ `full_url.split("#")[0]` เพื่อ resolve `action="#"` เป็น current page URL

### 5. `active_session.json` ไม่มี field `url` บางครั้ง
**อาการ**: `session_app_base` เป็น None ทำให้ไม่ใช้ login URL เป็น seed สำหรับ authenticated crawl

---

## ตัวอย่าง Full Pipeline

```bash
# 1. Recon + Triage (ไม่ใช้ Gemini)
python main.py -u http://localhost/dvwa --path-recon --payload-recon --auto-triage

# 2. Execute (brute force, sqlmap, xsstrike)
python executor.py --min-confidence medium --workers 6

# [executor จะถาม Y/N สำหรับ High-Level Scan]
# กด Y → จะรัน main.py ด้วย session อัตโนมัติ
# กด N → แสดงสรุปผล (triage.json, final_report.md, results/)

# หรือรัน post-auth scan เองด้วย session ที่ได้
python main.py -u http://localhost/dvwa --path-recon --payload-recon \
  --cookie-file active_session.json --post-auth
```

---

## Output Files

| File | ความหมาย |
|------|-----------|
| `triage.json` | Commands ที่แนะนำ + confidence level |
| `active_session.json` | Session cookies หลัง login สำเร็จ |
| `pre_auth_summary.md` | สรุป pre-auth recon |
| `final_report.md` | รายงานรวม pre/post-auth |
| `results/*.log` | Output ของแต่ละ tool (sqlmap, xsstrike, bruter, hydra) |
