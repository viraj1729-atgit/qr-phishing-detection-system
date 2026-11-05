# QR Phishing Detection System

## Overview

This project provides an **end‑to‑end** solution for detecting phishing attempts hidden in QR codes. It consists of three main parts:

1. **Backend (FastAPI)** – Accepts an image, decodes the QR code, extracts the URL and runs a heuristic risk‑scoring engine.
2. **QR Scanner** – Uses OpenCV and PyZbar (with a fallback to OpenCV's built‑in detector) to robustly decode QR images.
3. **Analyzer** – Extracts lexical/structural features from the URL (IP host, length, sub‑domains, `@` symbol, hyphens, known shorteners, suspicious TLDs) and aggregates them into a 0‑100 risk score with three risk levels.
4. **Frontend (Streamlit)** – Interactive dashboard where users can upload a QR image and instantly see the decoded URL, risk score, a visual gauge and a table of triggered heuristics.

The codebase is intentionally lightweight so it can be extended with real threat‑intelligence APIs (VirusTotal, Google Safe Browsing, etc.) later.

---

## Project Structure

```
qr-phishing-detection-system/
├─ backend/                # FastAPI server and core logic
│   ├─ __init__.py
│   ├─ app.py              # API entry point
│   ├─ scanner.py          # QR decoding utilities
│   ├─ analyzer.py         # URL feature extraction & scoring
│   └─ utils.py            # Simple logger helpers
├─ frontend/               # Streamlit UI
│   └─ app.py
├─ tests/                  # Unit tests (pytest)
│   ├─ test_analyzer.py
│   └─ test_scanner.py
├─ data/                   # Sample QR images (safe & malicious) – add your own
├─ requirements.txt        # Python dependencies
├─ .gitignore
└─ README.md               # This file
```

---

## Setup & Installation

```bash
# 1️⃣ Clone the repository (once you push it – see *Deployment* below)
# git clone <repo‑url>
# cd qr-phishing-detection-system

# 2️⃣ Create a virtual environment (optional but recommended)
python -m venv venv
source venv/Scripts/activate   # Windows PowerShell
# or: . venv/bin/activate   # Linux/macOS

# 3️⃣ Install dependencies
pip install -r requirements.txt
```

---

## Running the Backend API

```bash
uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

The API endpoint is:

```
POST /api/scan
Content‑Type: multipart/form-data

Form field "file" – image (png, jpg, jpeg, webp)
```

Response example:
```json
{
  "decoded_url": "http://example.com/login",
  "risk_level": "suspicious",
  "risk_score": 45,
  "heuristics": {
    "excessive_length": true,
    "many_subdomains": true
  }
}
```

---

## Running the Streamlit Dashboard

```bash
streamlit run frontend/app.py
```

Open the URL shown in the console (usually `http://localhost:8501`).
Upload a QR image and view the risk assessment.

---

## Testing

```bash
pip install pytest
pytest
```

The test suite checks that:
* The scanner returns a URL for a known QR image.
* The analyzer correctly flags known malicious patterns.

---

## Adding Sample Data

Place a few QR‑code images inside the `data/` folder – e.g. `safe.png`, `malicious.png`. They can be used for manual testing or by the automated test suite.

---

## Deployment & GitHub

1. **Create a repository** under your GitHub account (e.g. `viraj1729-atgit/qr-phishing-detection-system`).
2. Push the local code:
   ```bash
   git init
   git add .
   git commit -m "Initial commit – QR phishing detection system"
   git branch -M main
   git remote add origin https://github.com/viraj1729-atgit/qr-phishing-detection-system.git
   git push -u origin main
   ```
3. Enable **GitHub Actions** (optional) to run tests on each push.

---

## Extending the System

* **Threat‑Intelligence APIs** – add calls inside `analyze_url` to VirusTotal or Google Safe Browsing and combine their verdicts with the heuristic score.
* **Live Camera Scan** – integrate OpenCV video capture in the Streamlit UI.
* **Dockerization** – wrap the FastAPI backend and Streamlit UI in containers for easy deployment.

---

## License

MIT License – feel free to adapt, improve and share.
