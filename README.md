# OneClickScan

Web UI สำหรับสแกนเว็บหลายเครื่องมือ “รันพร้อมกันได้” พร้อมประวัติผลสแกน, real-time log ผ่าน WebSocket, และ AI analysis (Gemini) สำหรับ Payload Recon

## ภาพรวม

- **Frontend**: Next.js (App Router) + React + Tailwind
- **Backend**: Node.js + Express + SQLite (`better-sqlite3`)
- **Realtime**: WebSocket (job subscription) สำหรับ log/progress/done/error
- **Scan Engine**: รัน tools ภายใน Docker container `kali-engine` (Kali Linux) ผ่าน `docker exec`
- **Result storage**: เก็บไฟล์ผลลัพธ์ลง `backend/result/<sanitized_target>/...` และบันทึก path ลง DB

## Tools ที่รองรับ

- **Katana**: crawl แล้วส่ง URL ไป **Gemini scoring** → เก็บเป็น `katana-<round>.json`
- **FFuf Hidden Path**: brute hidden path → ส่ง URL ไป **Gemini scoring** → `ffuf-hidden-path-<round>.json`
- **Payload Recon**: สกัด forms/params จาก URL list → `payload-recon-<round>.json`
  - **AI Analysis (Gemini)**: วิเคราะห์ endpoint แล้วแนะนำ `sqlmap|xsstrike|curl` → `payload-recon-ai-<payloadReconId>-<timestamp>.json`
  - **Run Test**: กดรันคำสั่งจาก AI ได้จริง (sqlmap/xsstrike/curl) → output `.txt` + เก็บสถานะลง DB
- **Nuclei**: `-jsonl` แล้ว filter fields → `nuclei-<round>.json`
- **WhatWeb**: fingerprint → `whatweb-<round>.json` (UI loop plugins แบบ dynamic)
- **Subfinder + httpx**: subdomain enum แล้วเช็ค alive ด้วย httpx (กรอง status 200) → `subfinder-<round>.json`

## โครงสร้างโฟลเดอร์

```
oneclickscan/
  backend/
    routes/              # Express routes (/api/...)
    services/            # tool runners + AI
    result/              # ผลลัพธ์ที่ persist (ตาม target)
    temp/wordlists/      # wordlists ที่ upload ให้ FFuf
    db.js                # schema + queries (better-sqlite3)
    server.js            # express + websocket
    websocket.js         # job subscribe + buffer
  frontend/
    app/scan/            # หน้า scan ใหม่ (รวมทุก tool)
    app/scan/output/     # UI output แยกตาม tool
```

## การรันโปรเจกต์ (Dev)

### 1) สร้าง/รัน container engine (Kali tools)

```bash
docker compose up -d --build
```

จะได้ container ชื่อ **`kali-engine`** (ดูใน `compose.yml`)

### 2) Backend

```bash
cd backend
npm install
npm run dev
```

Backend จะฟังที่ `http://127.0.0.1:8080` โดย default

### 3) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend จะฟังที่ `http://127.0.0.1:3000`

## Environment Variables

Backend อ่านจาก `backend/.env`

- **`PORT`**: default `8080`
- **`KALI_CONTAINER_NAME`**: default `kali-engine`
- **`GEMINI_API_KEY`**: (จำเป็นสำหรับ scoring + AI analysis)
- **`GEMINI_MODEL`**: default `models/gemini-2.5-flash`

Frontend:
- **`NEXT_PUBLIC_BACKEND_URL`**: default `http://127.0.0.1:8080`
- **`NEXT_PUBLIC_WS_URL`**: ถ้าไม่ตั้ง จะ derive จาก backend URL

## หน้า Scan (UX)

หน้า `/scan` ออกแบบให้:

- เลือก tool ได้หลายตัว แล้วกด **Run** เพื่อเริ่ม
- **คลิก tool card ตอน idle** → เปิด config modal ของ tool นั้น
- **ตอน running**: disable การเลือก tools เพิ่ม/แก้ config (กัน state เพี้ยน) แต่ยังเปิด output modal เพื่อดู log ได้
- **ตอน done/error**: คลิก card เปิด output modal แสดงผล
- **โหลดผลเดิม**: ปุ่ม “โหลดข้อมูลเดิม” เลือกผลจากประวัติ แล้วนำมา apply ให้ card เป็น Done
- **สแกนใหม่**: ปุ่ม rescan ต่อ tool (reset state เฉพาะ tool)

## API ที่สำคัญ

### Start scans (async)
- `POST /api/scan/katana`
- `POST /api/scan/ffuf`
- `POST /api/scan/nuclei`
- `POST /api/scan/whatweb`
- `POST /api/scan/subfinder`

ตอบกลับ `{ jobId }` แล้ว frontend จะ `ws.send({type:"subscribe", jobId})`

### List history
- `GET /api/targets?q=<url>&limit=<n>` (ค้นหา target)
- `GET /api/targets/:targetId/katana`
- `GET /api/targets/:targetId/ffuf`
- `GET /api/targets/:targetId/payload-recon`
- `GET /api/targets/:targetId/nuclei`
- `GET /api/targets/:targetId/whatweb`
- `GET /api/targets/:targetId/subfinder`

### Payload Recon + AI
- `POST /api/payload/recon` → จะ set headers:
  - `X-Payload-Recon-Id`
  - `X-Payload-Recon-Result-File`
- `POST /api/payload/analyze`
  - ส่ง `{ payload_recon_id }` เพื่อดึงผลเดิมจาก DB ถ้ามี
  - หรือ `{ payload_recon_id, entries }` เพื่อ analyze ใหม่/รีทราย

### Run Test จาก AI
- `POST /api/payload/run` body: `{ payload_recon_id, cmd }`
  - จำกัด tool: `sqlmap|xsstrike|curl` และกัน token อันตราย (`;`, `&&`, `|`, redirect ฯลฯ)
  - output เก็บเป็น `.txt` ใน `backend/result/<target>/payload-run-...txt`
- `GET /api/payload/runs?payload_recon_id=<id>` ดูประวัติการรัน

### อ่านไฟล์ผลลัพธ์ (json/txt)
- `GET /api/result?path=<relative_path_under_backend>`
  - ถ้าเป็น `.json` จะตอบ `application/json`
  - ถ้าเป็น `.txt` จะตอบ `text/plain`

## WebSocket protocol (job)

Frontend subscribe ต่อ job id:
```json
{ "type": "subscribe", "jobId": "..." }
```

Backend broadcast message รูปแบบ:
- `{ type: "status", jobId, status: "starting|processing|scoring", message }`
- `{ type: "progress", jobId, message, stream? }`
- `{ type: "done", jobId, resultFile?, outputFile?, scanAt? }`
- `{ type: "error", jobId, message, outputFile? }`

มี buffer ต่อ job (replay ข้อความล่าสุด) กัน race condition ตอน subscribe ช้า

## DB (SQLite)

ไฟล์ DB อยู่ใน `backend` (ดู path ในโค้ด `db.js`)

ตารางหลัก:
- `target`
- `katana`, `ffuf`, `nuclei`, `whatweb`, `subfinder`
- `payload_recon`
- `payload_recon_ai` (FK → `payload_recon.id`)
- `payload_tool_run` (FK → `payload_recon.id`)

## การเพิ่ม tool ใหม่ (แนวทาง)

1) **backend/services/<tool>.js**
   - `spawn('docker', ['exec', KALI_CONTAINER, ...])`
   - broadcast log ผ่าน `broadcastToJob(jobId, ...)`
   - persist result ลง `backend/result/<target>/<tool>-<round>.(json|txt)`
   - insert row ลง DB
2) **backend/db.js**
   - เพิ่ม table + insert/list + get round
3) **backend/routes/index.js**
   - เพิ่ม `POST /api/scan/<tool>` + `GET /api/targets/:id/<tool>`
4) **frontend**
   - เพิ่ม state ใน `ScanClient.tsx` (phase/status/jobId/resultFile/logs)
   - เพิ่ม config UI ใน `ConfigModal.tsx` (ถ้ามี)
   - เพิ่ม output UI ใน `frontend/app/scan/output/<Tool>Output.tsx`
   - ต่อเข้า `OutputModal.tsx`
   - เพิ่มใน `LoadPreviousModal.tsx`

## Troubleshooting

- **FFuf/Nuclei/WhatWeb stuck running**: check backend log + ดูว่า `docker exec ... cat` timeout ไหม (บางเคสไฟล์ใน container อ่านค้าง)
- **Gemini 429 / quota exceeded**: เป็น free tier limit; ระบบมี queue ฝั่ง scoring แต่ถ้า quota หมดจะ error และ tool จะจบที่ phase error
- **ตรวจ process ใน container**
  ```bash
  docker exec -it kali-engine ps aux | egrep -i 'ffuf|katana|nuclei|subfinder|whatweb|httpx|sqlmap|xsstrike' | grep -v grep
  ```

