### CideCode 2K26 · CCITR Tech Hackathon · Team Submission

---

## 🎯 What it does

DroidScan is a full-stack APK forensic analysis platform for law enforcement.
Upload an Android APK — DroidScan tells you in minutes whether it's malicious,
what C2 servers it talks to, which data it steals, and maps every behavior to
the MITRE ATT&CK for Mobile framework. All findings are packaged into a
court-ready PDF forensic report.

---

## 🏗️ Architecture

```
Investigator
    │
    ▼ upload APK
┌─────────────────────────────────────────────────┐
│              React Dashboard (:3000)            │
└──────────────────────┬──────────────────────────┘
                       │ REST API
┌──────────────────────▼──────────────────────────┐
│           FastAPI Backend (:8000)               │
│    POST /analyze → Celery task queue            │
└──────────────────────┬──────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  Module 1       Module 2       Module 3
  Static +       Dynamic        C2 Detection
  Obfuscation    Sandbox        + ML Score
  (JADX,YARA)    (Frida,mitm)   (AbuseIPDB,VT)
        │              │              │
        └──────────────┴──────────────┘
                       │
               Correlation Engine
               ties signals into named
               attack patterns
                       │
               Module 4 (FastAPI)
               assembles full report
                       │
               Module 5 (React)
               displays + PDF export
```

---

## 🚀 Quick start

### 1. Clone and configure
```bash
git clone https://github.com/aditya-amrale/droidscan
cd droidscan
cp .env.example .env
# Add your API keys to .env:
#   ABUSEIPDB_KEY=your_key
#   VIRUSTOTAL_KEY=your_key
```

### 2. Run with Docker Compose
```bash
docker-compose up --build
```

| Service      | URL                        |
|--------------|----------------------------|
| Dashboard    | http://localhost:3000      |
| API docs     | http://localhost:8000/docs |
| API health   | http://localhost:8000/health |

### 3. Run locally (without Docker)
```bash
# Install Python deps
pip install -r requirements.txt

# Start Redis (required)
redis-server &

# Start PostgreSQL and create DB
createdb droidscan

# Start API
cd backend && uvicorn main:app --reload --port 8000

# Start Celery worker (separate terminal)
cd backend && celery -A tasks worker --loglevel=info

# Start React frontend (separate terminal)
cd frontend && npm install && npm start
```

---

## 📦 Module breakdown

| # | Module | File | Owned by |
|---|--------|------|----------|
| 1 | Static analysis | `static_analysis/static_analyzer.py` | Member 1 |
| 1b | Obfuscation detection | `static_analysis/obfuscation_detector.py` | Member 1 |
| 2 | Dynamic sandbox | `dynamic_sandbox/dynamic_sandbox.py` | Member 2 |
| 3 | C2 detection + ML | `c2_detection/c2_detector.py` | Member 3 |
| 3b | Correlation engine | `c2_detection/correlation_engine.py` | Member 3 |
| 4 | FastAPI backend | `backend/main.py` | Member 3 |
| 5 | React dashboard | `frontend/src/App.js` | Member 3 |

---

## 🧩 Module 1 — Static Analysis
- Decompiles APK with JADX + Androguard
- Flags 14 dangerous permissions
- Detects 17 suspicious API call patterns
- Extracts hardcoded IPs, URLs, domains (IOCs)
- Runs 5 custom YARA rules (dropper, SMS stealer, banking trojan, etc.)
- Extracts APK signing certificate info
- Outputs: risk score 0–100 + structured JSON

## 🧩 Module 1b — Obfuscation Detection
- Class-name entropy check (ProGuard/DexGuard indicator)
- High-entropy / Base64 string scan (hidden payloads, C2 addresses)
- Reflection usage detection (hidden API calls)
- Native `.so` library inspection
- Resource/asset file-type mismatch detection
- Outputs: obfuscation score 0–100 + level (NONE/LIGHT/MODERATE/HEAVY)

## 🧩 Module 2 — Dynamic Sandbox
- Runs APK in isolated Docker + Android AVD emulator
- Frida hooks intercept: SMS send, shell exec, device ID harvest,
  file writes, DexClassLoader, crypto key generation, HTTP connections
- mitmproxy captures all network traffic (HTTP + HTTPS via SSL intercept)
- Sandbox auto-destroyed after analysis
- Outputs: Frida events, network traffic log, file mutations

## 🧩 Module 3 — C2 Detection + ML
- 5 C2 heuristics: hardcoded IP comms, non-standard ports,
  beaconing detection, large POST exfiltration, dynamic DEX load + network
- Threat intel: AbuseIPDB (IPs) + VirusTotal (domains)
- ML classifier: Random Forest on 30-feature vector (permissions + APIs + IOCs)
- MITRE ATT&CK for Mobile mapping (25 technique mappings)
- Final composite score: static (30%) + ML (40%) + threat intel (20%) + C2 (10%)

## 🧩 Module 3b — Correlation Engine
- Cross-checks static + dynamic + C2 signals together
- Confirms 8 named attack patterns (SMS stealer/OTP interceptor, banking
  trojan/overlay attack, spyware, C2 beacon/RAT, APK dropper, boot
  persistence, encrypted exfiltration, mic/camera surveillance)
- Builds a full evidence chain per pattern for investigators
- Outputs: confirmed patterns, partial matches, confidence % per pattern

## 🧩 Module 4 — FastAPI Backend
- `POST /analyze` — upload APK, returns job_id
- `GET  /status/{job_id}` — poll progress (0–100%)
- `GET  /report/{job_id}` — full JSON results
- `GET  /report/{job_id}/pdf` — download PDF forensic report
- `GET  /jobs` — list recent analyses
- Celery async workers, PostgreSQL persistence, Redis queue

## 🧩 Module 5 — React Dashboard
- Drag-and-drop APK upload
- Live progress bar with stage tracking
- Risk score radial gauge with MALICIOUS/SUSPICIOUS/BENIGN verdict
- Tabbed results: Overview · Permissions · C2 · MITRE · Network ·
  Correlation · Obfuscation
- One-click PDF forensic report download

---

## 🔐 Sample APKs for testing
Download safe malware samples from:
- https://bazaar.abuse.ch (MalwareBazaar — real Android malware)
- https://github.com/ashishb/android-malware (curated samples)

> ⚠️ Only analyze in the sandboxed environment. Never install samples on real devices.

---

## 🏆 MITRE ATT&CK techniques covered

| ID     | Technique                    | Tactic              |
|--------|------------------------------|---------------------|
| T1418  | Application Discovery        | Discovery           |
| T1430  | Location Tracking            | Collection          |
| T1412  | Capture SMS Messages         | Collection          |
| T1437  | Standard App Layer Protocol  | C2                  |
| T1407  | Download New Code at Runtime | Execution           |
| T1402  | Boot or Logon Autostart      | Persistence         |
| T1406  | Obfuscated Files             | Defense Evasion     |
| T1582  | SMS Control                  | Impact              |
| + 17 more...                                          |

---

## 👥 Team

| Member | Role |
|--------|------|
| Member 1 | APK analyst — static analysis, obfuscation detection, YARA rules |
| Member 2 | Network forensics — sandbox, Frida, C2 detection |
| Member 3 | Backend + ML + Frontend — FastAPI, classifier, correlation engine, scoring, React dashboard, PDF reports, pitch |

---

## 📄 License
MIT — built for CideCode 2K26, CCITR / PES University, Bengaluru.
