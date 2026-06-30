"""
DroidScan — Module 4: FastAPI Backend + Celery Task Queue
==========================================================
Provides the REST API that ties all modules together:
  POST /analyze         → upload APK, returns job_id
  GET  /status/{job_id} → poll job progress
  GET  /report/{job_id} → get full JSON results
  GET  /report/{job_id}/pdf → download PDF forensic report

Architecture:
  FastAPI (HTTP) → Celery worker (analysis) → Redis (queue/results)
  PostgreSQL stores completed reports.

Dependencies:
    pip install fastapi uvicorn celery redis sqlalchemy psycopg2-binary
                reportlab python-multipart aiofiles
    Redis server running: redis-server
    Start API:    uvicorn main:app --reload --port 8000
    Start worker: celery -A tasks worker --loglevel=info
"""

# ──────────────────────────────────────────────────────────────────────────────
# main.py  (FastAPI application)
# ──────────────────────────────────────────────────────────────────────────────

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import uuid
import shutil
import json
import os
from pathlib import Path
from datetime import datetime

# Internal modules
from tasks import run_analysis_task
from database import SessionLocal, AnalysisJob, init_db
from report_generator import generate_pdf_report

# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DroidScan API",
    description="APK Threat Analysis Platform with C2 Detection",
    version="1.0.0",
)

_cors_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()
    print("[+] DroidScan API started")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.post("/analyze", summary="Upload APK for analysis")
async def analyze(file: UploadFile = File(...)):
    """
    Upload an APK file.
    Returns a job_id to poll for progress.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted")

    job_id   = str(uuid.uuid4())
    apk_path = UPLOAD_DIR / f"{job_id}.apk"

    # Save uploaded file
    with apk_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # Create DB record
    db  = SessionLocal()
    job = AnalysisJob(
        id          = job_id,
        filename    = file.filename,
        status      = "QUEUED",
        submitted_at= datetime.utcnow(),
    )
    db.add(job)
    db.commit()
    db.close()

    # Queue Celery task
    run_analysis_task.delay(job_id, str(apk_path))

    return {
        "job_id":   job_id,
        "filename": file.filename,
        "status":   "QUEUED",
        "poll_url": f"/status/{job_id}",
    }


@app.get("/status/{job_id}", summary="Poll analysis job status")
async def get_status(job_id: str):
    """Returns job status: QUEUED | RUNNING | DONE | FAILED"""
    db  = SessionLocal()
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    db.close()

    if not job:
        raise HTTPException(404, "Job not found")

    payload = {
        "job_id":       job.id,
        "filename":     job.filename,
        "status":       job.status,
        "submitted_at": job.submitted_at,
        "completed_at": job.completed_at,
        "progress":     job.progress,
    }
    if job.status == "FAILED" and job.error_message:
        payload["error_message"] = job.error_message
    return payload


@app.get("/report/{job_id}", summary="Get full analysis results as JSON")
async def get_report(job_id: str):
    """Returns complete analysis JSON once job is DONE."""
    db  = SessionLocal()
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    db.close()

    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != "DONE":
        raise HTTPException(409, f"Job not complete yet — status: {job.status}")

    return JSONResponse(content=json.loads(job.results_json))


@app.get("/report/{job_id}/pdf", summary="Download PDF forensic report")
async def get_pdf(job_id: str):
    """Generates and returns a downloadable PDF forensic report."""
    db  = SessionLocal()
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    db.close()

    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != "DONE":
        raise HTTPException(409, "Analysis not complete yet")

    pdf_path = REPORTS_DIR / f"{job_id}.pdf"

    if not pdf_path.exists():
        results = json.loads(job.results_json)
        generate_pdf_report(results, str(pdf_path))

    return FileResponse(
        path        = str(pdf_path),
        filename    = f"DroidScan_Report_{job_id[:8]}.pdf",
        media_type  = "application/pdf",
    )


@app.get("/jobs", summary="List recent analysis jobs")
async def list_jobs(limit: int = 20):
    db   = SessionLocal()
    jobs = db.query(AnalysisJob).order_by(
        AnalysisJob.submitted_at.desc()
    ).limit(limit).all()
    db.close()
    return [
        {"job_id": j.id, "filename": j.filename,
         "status": j.status, "submitted_at": j.submitted_at}
        for j in jobs
    ]


@app.get("/health")
async def health():
    return {"status": "ok", "service": "DroidScan API"}


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
