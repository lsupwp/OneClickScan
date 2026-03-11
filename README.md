# OneClickScan V2

ระบบ Web Penetration Testing แบบ automated จาก URL เดียว ครอบคลุมตั้งแต่ reconnaissance, triage, จนถึงการรัน exploit (sqlmap, xsstrike, hydra/bruter) และมี **Web UI** สำหรับรันสแกนและดูผลแบบ real-time

> **สำหรับ authorized pentest เท่านั้น** — ห้ามใช้กับเป้าหมายที่ไม่ได้รับอนุญาต

---

## ทำอะไรได้บ้าง

- **Reconnaissance** — Crawl paths (Katana), ดึง forms และ URL parameters, สแกนพอร์ต (Nmap), fingerprint เทคโนโลยี (WhatWeb), หา subdomain (Subfinder), brute path (Gobuster), ทดสอบ WebDAV (DAVTest)
- **Triage** — วิเคราะห์ผล recon แล้วแนะนำคำสั่งทดสอบ (ใช้ Gemini AI หรือ heuristic แบบไม่ใช้ API)
- **Vulnerability Scan** — รัน Nuclei (CVE templates)
- **Run Exploits** — รันคำสั่งจาก triage (sqlmap, xsstrike, hydra) พร้อม brute login แบบ CSRF-aware; แสดงสรุปผลและดึง command จาก log มาแสดงในตาราง
- **Web UI** — ใส่ URL แล้วเลือก tools รันได้จากเบราว์เซอร์ ผล stream แบบ real-time แต่ละ tool แยกแท็บ มีปุ่มโหลดผลลัพธ์ล่าสุด (manual) และดู log แต่ละคำสั่ง

---

## การทำงาน (Flow)

1. **ใส่ URL** ใน Web UI หรือส่งผ่าน CLI
2. **เลือก Tools** ที่ต้องการ (Path Recon, Payload Recon, Gobuster, WhatWeb, Nmap, Nuclei, Subfinder, DAVTest, AI Triage)
3. **Backend** รัน `executor.py` (scan mode) ตาม flags ที่เลือก — แต่ละ phase พิมพ์ banner (เช่น `=== PATH RECON ===`) แล้ว stream stdout ไปที่ frontend ผ่าน WebSocket
4. **Frontend** แยกบรรทัดตาม section (PATH RECON, WHATWEB, …) ไปยังแท็บของ tool นั้น และถ้ามี structured data (paths, forms, nuclei findings, triage targets) จะแสดงเป็นตาราง/การ์ด
5. **AI Triage** — หลัง Payload Recon ถ้าเปิด AI Triage จะส่งผลให้ Gemini วิเคราะห์และได้ `triage.json` (targets + suggested commands)
6. **Run Exploits** — จากแท็บ AI Triage กด "Run Exploits" จะส่ง WebSocket แบบ `exec_mode: true` ให้ backend รัน `executor.py` ในโหมด exec (อ่าน `triage.json`, รัน sqlmap/xsstrike/hydra/bruter) ผลสรุปและ command แต่ละอันดึงจากไฟล์ log มาแสดง; มีปุ่ม "โหลดผลลัพธ์ล่าสุด (manual)" สำหรับกรณีรัน executor เองจากเทอร์มินัล

---

## Tech Stack

| Layer | เทคโนโลยี |
|--------|------------|
| **Backend** | Python 3.11, FastAPI, WebSocket, asyncio |
| **CLI / Worker** | `executor.py` (scan + exec mode), `main.py` (legacy entry), `modules/bruter.py` |
| **Frontend** | React 19, Vite 7, Tailwind CSS 4 |
| **AI** | Google Gemini (google-genai) สำหรับ AI Triage + สรุปผล exploit log |
| **External tools** | Katana, Nmap, WhatWeb, Gobuster, Subfinder, httpx, SQLMap, XSStrike, Hydra, Commix, Nuclei (optional) |

---

## Tools ในระบบ

| Tool | คำอธิบาย |
|------|-----------|
| **Path Recon** | Katana crawler — crawl paths ความลึก 5, ตรวจจับ SPA hash routes |
| **Payload Recon** | ดึง forms (POST/GET) และ URL parameters จากทุก path |
| **Gobuster** | Directory/path brute-force |
| **WhatWeb** | Technology fingerprinting (แสดงเป็นตาราง Plugin / Value) |
| **Nmap** | Port & service scan (แสดงเป็นตาราง Port / State / Service / Version) |
| **Nuclei** | สแกน CVE templates |
| **Subfinder** | Subdomain enumeration + httpx probe (alive) |
| **DAVTest** | ทดสอบ WebDAV upload |
| **AI Triage** | วิเคราะห์ผล recon ด้วย Gemini แล้วสร้าง targets + suggested commands (sqlmap, xsstrike, hydra ฯลฯ) |
| **Full Exploit** | Scan → brute → post-auth: รันคำสั่งจาก triage (sqlmap, xsstrike, hydra/bruter), สรุปผลและดึง command จาก log |

---

## สิ่งที่ต้องติดตั้ง

### Python
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install fastapi uvicorn   # ถ้าไม่มีใน requirements
playwright install chromium   # สำหรับ SPA crawling
```

### External tools (Ubuntu/Debian)
```bash
chmod +x install_tools.sh
./install_tools.sh
```

จะติดตั้ง: **katana**, **nmap**, **whatweb**, **gobuster**, **subfinder**, **httpx**, **sqlmap**, **xsstrike**, **hydra**, **commix** (และ nuclei ถ้ามี)

### API Key (สำหรับ AI Triage / สรุปผล exploit)
```bash
echo "GOOGLE_API_KEY=your_key_here" >> .env
# หรือ GEMINI_API_KEY
```

---

## วิธีใช้งาน

### ผ่าน Web UI
```bash
# Terminal 1: Backend
uvicorn api:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Frontend
cd fontend && npm install && npm run dev
```

เปิดเบราว์เซอร์ที่ URL ที่ Vite แสดง (เช่น `http://localhost:5173`) ใส่ target URL เลือก tools แล้วกดสแกน ผลจะ stream ไปที่แท็บของแต่ละ tool

- **โหลดผลลัพธ์ exploit ล่าสุด**: ไปที่แท็บ Full Exploit แล้วกด "โหลดผลลัพธ์ล่าสุด (manual)" ถ้ารัน executor เองจาก CLI (จะอ่าน `results/last_exploit_summary.json` หรือสร้างจาก `results/*.log`)

### ผ่าน CLI (Scan)
```bash
# รัน scan ผ่าน executor (รองรับ flags ตาม api)
python executor.py scan -u http://target.com --path-recon --payload-recon --nmap --whatweb --ai-triage
```

### ผ่าน CLI (Run Exploits จาก triage.json)
```bash
python executor.py exec triage.json --min-confidence medium --workers 6
```

ผลจะเขียนที่ `results/` และ `results/last_exploit_summary.json`; ใน Web UI กด "โหลดผลลัพธ์ล่าสุด (manual)" เพื่อดูสรุปและ command

---

## โครงสร้างโปรเจกต์

```
OneClickScanV2/
├── api.py                 # FastAPI + WebSocket, stream output, /api/exploit-last-result, /api/exploit-log
├── executor.py            # Scan + Exec mode (triage → sqlmap/xsstrike/hydra/bruter)
├── main.py                # Legacy entry (recon + triage)
├── modules/
│   └── bruter.py          # CSRF-aware login brute
├── services/
│   ├── path_recon.py      # Katana
│   ├── payload_recon.py   # Forms + URL params
│   ├── nmap_service.py
│   ├── whatweb_service.py
│   ├── nuclei_service.py
│   ├── gobuster_service.py
│   ├── subfinder_service.py
│   ├── httpx_service.py
│   ├── davtest_service.py
│   ├── ai_triage_service.py
│   ├── local_triage_service.py
│   └── cve_service.py
├── fontend/                # React + Vite + Tailwind
│   └── src/
│       ├── App.jsx
│       ├── components/     # PathList, NmapOutput, WhatWebOutput, ExploitOutput, NucleiTable, TriageTable, ...
│       └── constants.js
├── results/                # Logs, last_exploit_summary.json, scan_*.json
├── triage.json             # Output จาก AI Triage
├── requirements.txt
└── install_tools.sh
```

---

## สิ่งที่ยังไม่ทำ / ยังไม่เชื่อมกับหน้าเว็บ

- **Full Exploit (Run Exploits)** — ยังไม่ลองต่อกับหน้าเว็บแบบ end-to-end ครบ flow (กด Run Exploits จาก Web UI → รัน executor exec mode → แสดง progress และสรุปบนหน้าเว็บ) ในปัจจุบัน:
  - รัน executor แบบ manual จาก CLI ได้ และใช้ปุ่ม "โหลดผลลัพธ์ล่าสุด (manual)" ในแท็บ Full Exploit เพื่อดูสรุป + command + ดู log ได้
  - การกด "Run Exploits" จาก Web UI จะส่ง WebSocket `exec_mode: true` ให้ backend รัน executor และ stream บรรทัด progress กับส่ง summary กลับเมื่อจบ — **แต่ยังไม่ได้ทดสอบต่อกับหน้าเว็บจนมั่นใจว่าทุกขั้น (รวม post-auth / session) ทำงานครบบน UI**

---

## Output หลัก

| ไฟล์/โฟลเดอร์ | ความหมาย |
|----------------|----------|
| `triage.json` | Targets + suggested commands จาก AI Triage |
| `results/last_exploit_summary.json` | สรุปผลรัน exploit ล่าสุด (จาก executor) |
| `results/*.log` | Log แต่ละคำสั่ง (sqlmap, xsstrike, hydra, bruter) — บรรทัดแรกหลัง `# Command:` คือคำสั่งที่รัน |
| `results/scan_*.json` | ผล scan แบบมี structure (paths, nuclei, ฯลฯ) ตาม job_id |
| `active_session.json` | Session cookies หลัง login สำเร็จ (ใช้กับ post-auth scan) |

---

## หมายเหตุอื่น (ปัญหาเดิมที่อาจยังมี)

- **Gemini quota** — Free tier จำกัด request ต่อวัน; ใช้ `--auto-triage` / local triage แทนได้
- **Session / Forms หลัง login** — บาง flow ต้อง login ใหม่ก่อนรัน payload_recon เพื่อให้เห็น forms ครบ
- **Katana ช้า** — depth 5 บน site ใหญ่อาจใช้เวลานาน
