# 🛡️ EvidenceDesk: Digital Evidence Triage Workstation

> **Defensible Preliminary Forensics & Indicator Analysis Platform**  
> *Created & Maintained by **Utkarsh Gupta** (Student & Aspiring SDE • IIT (BHU) Varanasi) • [gupta.utkarsh.iitbhu@gmail.com](mailto:gupta.utkarsh.iitbhu@gmail.com)*  
> 🔗 **Live Demo:** [evidence-desk-ten.vercel.app](https://evidence-desk-ten.vercel.app/)

---


## 📌 Executive Summary

Incident responders, fraud investigators, and academic reviewers receive high volumes of unverified digital assets—spear-phishing lures, manipulated screenshots, and uniform synthetic text.

**EvidenceDesk** is an automated digital evidence triage platform that provides defensible, read-only preliminary audits across three common media vectors:
1. **Email Messages (`.eml`):** Header discrepancy analysis (From vs. Reply-To vs. Return-Path), anchor-text phishing link divergence (e.g. visible text displays trusted bank but routes to attacker IP), reported authentication flags (SPF/DKIM/DMARC), server relay hops, and an **Attachment Inventory with individual SHA-256 hashes**.
2. **Images (`.jpg`, `.png`, `.webp`):** Camera hardware EXIF metadata, privacy-masked GPS coordinates (no external leaks), trailing bytes past EOF (steganography indicator), and Error Level Analysis (ELA) compression variance.
3. **Documents & Text (`.pdf`, `.docx`, `.txt`):** Sentence-length burstiness, transition phrase frequency, passive voice index, and pronoun absence with **Dual Document Hashing** (file SHA-256 vs. text stream SHA-256).

---

## ⚖️ Defensibility & Trust Architecture

Unlike black-box commercial tools that claim to "prove" authenticity or output a single "AI probability," EvidenceDesk operates strictly under an **explainable triage model**:

* **Unforgeable Server-Side Reports:** PDF reports and JSON evidence manifests are generated **exclusively from server-verified analysis records** stored by UUID `scan_id`. The client cannot submit fabricated scores, findings, or hashes.
* **Session-Authorized Ownership:** Every scan is tagged with a client session token. Only the originating analyst can view, export, or explicitly purge the evidence from memory.
* **Dual Evidence Hashes for Documents:** Document uploads track both `fileSha256` (the exact uploaded file on disk) and `textSha256` (the extracted text stream).
* **Defensible Stylistic Metrics:** Text analysis measures stylistic uniformity (burstiness, transition phrases, passive voice). It is an *uncalibrated heuristic* and does **not** establish AI authorship.
* **Non-Attribution for Unverified Headers:** Authentication results (SPF/DKIM/DMARC) are clearly reported as unverified message text; the tool does not perform live cryptographic DNS validation.
* **Inconclusive Metadata Caveat:** The absence of camera EXIF tags is reported neutrally as omitted/stripped metadata, not as proof of synthetic media.
* **ELA Limitations:** Error Level Analysis visualizes pixel difference against a 95% JPEG baseline. Sharp edges and repeated saves cause natural differences that do not prove tampering.
* **Privacy by Default:** Geolocation coordinates are masked by default with a local "Copy Coordinates" action, preventing automated data leakage to third-party map providers.

---

## 🛠️ Architecture & Tech Stack

```
[ Analyst Web Browser ]
           │
           ▼
[ React 18 + Vite Frontend (Port 5173) ]
  • "Quiet Analyst Workstation" interface (charcoal/slate palette)
  • Modular architecture (Dropzone, TriageSummary, FindingsTable, EvidenceViews)
  • Staged upload workflow (file preview, clear action, explicit "Run Triage" button)
  • Tab-switching race condition prevention & image object-URL memory safety
  • Real-time backend connectivity polling & in-page error alerts
           │
           │ REST API / JSON (Multipart form uploads with X-Session-Token)
           ▼
[ Python 3 FastAPI Backend (Port 8000) ]
  • Strict 25MB streaming upload bounds (rejects before memory exhaustion)
  • Strict CORS allowlist (no wildcard '*') & security headers (nosniff, DENY, no-referrer)
  • Concurrency limiter (prevents CPU/RAM exhaustion on free cloud instances)
  • Pillow (Image ELA & EXIF), pypdf & python-docx (Document parsing)
  • In-Memory Verified Scan Store (UUID-indexed, TTL auto-wipe, session authorization)
  • ReportLab (XML-escaped, non-certifying detailed PDF Triage Reports)
```

---

## 🚀 Quick Start Guide

### Prerequisites
* **Python 3.10+**
* **Node.js 18+** & **npm**

---

### 1. Local Backend Setup (FastAPI)

```bash
# 1. Navigate to the backend folder
cd backend

# 2. Create and activate a Python virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# macOS / Linux:
source venv/bin/activate

# 3. Install pinned backend dependencies
pip install -r requirements.txt

# 4. Start the FastAPI server
python main.py
```
*API runs at http://127.0.0.1:8000 (Interactive Swagger documentation at http://127.0.0.1:8000/docs).*

---

### 2. Local Frontend Setup (React + Vite)

Open a second terminal:

```bash
# 1. Navigate to the frontend folder
cd frontend

# 2. Install Node packages
npm install

# 3. Start the Vite development server
npm run dev
```
*Dashboard runs at http://localhost:5173.*

---

## 🌐 Free Cloud Deployment (24/7 Online)

You can publish EvidenceDesk on the web for free so it stays live 24/7 with your computer off:

### Step 1: Deploy Backend to Render (Free)
1. Push your repository to GitHub.
2. Log into [Render.com](https://render.com) and create a **New Web Service**.
3. Select your GitHub repository.
4. Set:
   * **Root Directory:** `backend`
   * **Environment:** `Python 3`
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Under **Environment Variables**, add:
   * `EVIDENCE_DESK_ALLOWED_ORIGINS`: `https://your-frontend-app.vercel.app,http://localhost:5173`
6. Click **Deploy**. Render will give you a public URL (e.g., `https://evidencedesk-api.onrender.com`).

### Step 2: Deploy Frontend to Vercel (Free)
1. Log into [Vercel.com](https://vercel.com) and click **Add New Project**.
2. Select your GitHub repository.
3. Set **Root Directory** to `frontend`.
4. Under **Environment Variables**, add:
   * `VITE_API_URL`: `https://evidencedesk-api.onrender.com` (your Render backend URL from Step 1).
5. Click **Deploy**. Your analyst dashboard is now live worldwide!

---

## 🧪 Running Automated Unit & API Tests

EvidenceDesk includes an end-to-end test suite covering analyzers, stream bounds, corrupt file rejection, session authorization, and unforgeable report generation:

```bash
python -m unittest discover tests
```

Expected output:
```text
.............
----------------------------------------------------------------------
Ran 13 tests in 0.37s

OK
```

---

## 📁 Repository Structure

```text
EvidenceDesk/
├── backend/
│   ├── main.py              # FastAPI server with bounded streaming & security headers
│   ├── config.py            # Environment-driven configuration (CORS, 25MB limits)
│   ├── scan_store.py        # Thread-safe in-memory verified scan store with TTL
│   ├── models.py            # Pydantic data contracts & error schemas
│   ├── email_analyzer.py    # RFC 5322 header, auth, hops, & attachment inventory
│   ├── image_analyzer.py    # EXIF, GPS, ELA heatmap, & trailing byte checks
│   ├── text_analyzer.py     # Document text extractor & burstiness metrics
│   ├── report_generator.py  # ReportLab defensible PDF generator (XML-escaped)
│   ├── requirements.txt     # Pinned Python package dependencies
│   ├── Dockerfile           # Multi-stage production container build
│   └── .env.example         # Backend environment configuration
├── frontend/
│   ├── index.html           # HTML5 shell
│   ├── package.json         # Vite & React scripts
│   ├── vite.config.js       # Vite build configuration (local binding)
│   ├── vercel.json          # Vercel deployment routing rules
│   ├── .env.example         # Frontend API URL configuration
│   └── src/
│       ├── main.jsx         # React entry point
│       ├── App.jsx          # Workstation coordinator with purge & safe download
│       ├── index.css        # Quiet Analyst Workstation design tokens
│       ├── api/
│       │   └── client.js    # Session-authenticated API client with health check
│       └── components/
│           ├── Header.jsx             # Live health polling & status pill
│           ├── ModuleNav.jsx          # Accessible keyboard-navigable tabs
│           ├── Dropzone.jsx           # Real drag-and-drop & staged file preview
│           ├── TriageSummary.jsx      # Priority badge, hashes, & purge control
│           ├── FindingsTable.jsx      # Severity-ranked findings with caveats
│           ├── EmailEvidenceView.jsx  # Headers, auth, & attachment inventory
│           ├── ImageEvidenceView.jsx  # ELA overlay & privacy-masked GPS
│           ├── TextEvidenceView.jsx   # Stylistic metrics & flagged sentences
│           └── ErrorBanner.jsx        # Accessible in-page error alerts
├── tests/
│   ├── test_triage.py       # Unit tests for core forensic analyzers
│   └── test_api.py          # Integration tests for FastAPI endpoints
├── evidence/                # Authoritative test fixtures (.eml, .jpg)
│   ├── clean_evidence.jpg
│   ├── tampered_evidence.jpg
│   ├── suspicious_email.eml
│   └── generate_evidence.py # Relative-path fixture generator
├── render.yaml              # Render blueprint for cloud backend
├── .gitignore               # Clean git exclusion rules
└── README.md                # Comprehensive system documentation
```

---

## 👨‍💻 Author & Contact

**Utkarsh Gupta**  
* Indian Institute of Technology (BHU) Varanasi  
* **Email:** [gupta.utkarsh.iitbhu@gmail.com](mailto:gupta.utkarsh.iitbhu@gmail.com)  
* **Live Deployment:** [evidence-desk-ten.vercel.app](https://evidence-desk-ten.vercel.app/)  
* **GitHub Repository:** [EvidenceDesk](https://github.com/utkarshgupta-iitbhu/EvidenceDesk)

---

## 📄 License

Distributed under the MIT License. Built for forensic research, evidence triage education, and defensive cybersecurity analysis.
