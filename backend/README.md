# Cyber Evidence Analyzer Backend

## Overview
This repository contains the **backend** of the *Cyber Evidence Analyzer* – a simple, beginner‑friendly FastAPI service for lightweight URL/IP/domain analysis.  It stores each analysis as digital evidence in a local SQLite database and exposes a small set of REST endpoints that a future React frontend can consume.

## Project Structure
```
backend/
├── __init__.py           # Makes `backend` a Python package
├── main.py               # FastAPI app and route definitions
├── database.py           # SQLAlchemy engine & session
├── models.py             # SQLAlchemy ORM model for Evidence
├── schemas.py            # Pydantic request/response schemas
├── analyzer.py           # Very basic safe analysis logic
├── evidence.py           # Placeholder for future helper functions
├── report.py             # Stub for future PDF report generation
├── requirements.txt      # Python dependencies
├── .env                  # Environment file for future API keys
├── .gitignore            # Ignored files/folders
└── README.md             # This file
```

## Setup & Installation
1. **Navigate to the backend folder**
   ```bash
   cd "C:/Users/SUHAILA/OneDrive/Documents/Cyber-Evidence-Analyzer/backend"
   ```
2. **Create a virtual environment (optional but recommended)**
   ```bash
   python -m venv venv
   venv\Scripts\activate      # on Windows PowerShell
   # or: .\venv\Scripts\activate
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Server
```bash
uvicorn main:app --reload
```
The API will be available at `http://127.0.0.1:8000`.

* Swagger UI (interactive docs) → `http://127.0.0.1:8000/docs`
* ReDoc documentation → `http://127.0.0.1:8000/redoc`

## Available API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| **POST** | `/analyze` | Accept a URL, IP or domain, run a tiny risk analysis, store the result as evidence, and return the analysis data. |
| **GET**  | `/evidence` | Retrieve a list of all saved evidence records. |
| **GET**  | `/evidence/{evidence_id}` | Retrieve a single evidence entry by its unique `evidence_id`. |
| **DELETE**| `/evidence/{evidence_id}` | Delete a specific evidence record. |
| **POST** | `/reports` | Placeholder – returns the submitted data. Future implementation will generate a PDF incident report. |

## Testing the `/analyze` Endpoint
1. Open the Swagger UI (`/docs`).
2. Locate **POST /analyze** and click **Try it out**.
3. Provide a JSON payload, e.g.:
   ```json
   {"input": "https://example.com/login"}
   ```
4. Execute the request – you should receive a response containing:
   * `input`, `input_type` (url/ip/domain)
   * `risk_score` (0‑100) and `risk_level` (Low/Medium/High)
   * `findings`, `timestamp`, and a generated `evidence_id`
5. The record is automatically saved; you can verify it with **GET /evidence**.

## Notes & Future Work
* The analysis performed is *very* basic and **not** a comprehensive security scanner. It only demonstrates input detection, simple heuristics, and storage.
* Threat‑intelligence integrations (VirusTotal, AbuseIPDB, URLScan) are intentionally left as modular stubs in `analyzer.py` – you can add API calls later without touching the rest of the code.
* PDF report generation will be added in `report.py` when needed.
* CORS is enabled for all origins to simplify frontend integration; tighten in production.

---
*Happy hacking!*
