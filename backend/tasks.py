"""
DroidScan — tasks.py
=====================
Celery worker that orchestrates all 5 modules + 2 gap-fix modules.
Run with: celery -A tasks worker --loglevel=info
"""

import json
import sys
import os
from celery import Celery
from datetime import datetime

# ── Resolve project root so all module imports work regardless of CWD ─────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database import SessionLocal, AnalysisJob
from static_analysis.static_analyzer      import StaticAnalyzer
from static_analysis.obfuscation_detector import ObfuscationDetector
from dynamic_sandbox.dynamic_sandbox       import DynamicSandbox
from c2_detection.c2_detector              import C2Detector, score_to_label
from c2_detection.correlation_engine       import CorrelationEngine

# ── Celery app ────────────────────────────────────────────────────────────────
app = Celery(
    "droidscan",
    broker  = os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    backend = os.getenv("REDIS_URL", "redis://localhost:6379/0"),
)
app.conf.task_serializer   = "json"
app.conf.result_serializer = "json"
app.conf.accept_content    = ["json"]


@app.task(bind=True, max_retries=0)
def run_analysis_task(self, job_id: str, apk_path: str):
    db  = SessionLocal()
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        db.close()
        raise ValueError(f"Job {job_id} not found in database")

    def update(status: str, progress: int, extra: dict = None):
        job.status   = status
        job.progress = progress
        if extra:
            for k, v in extra.items():
                setattr(job, k, v)
        db.commit()

    try:
        update("RUNNING", 5)

        # ── Module 1: Static analysis ─────────────────────────────────────────
        update("RUNNING", 10)
        static = StaticAnalyzer(apk_path).run()

        # ── Gap 2: Obfuscation detection ──────────────────────────────────────
        update("RUNNING", 30)
        try:
            obfuscation = ObfuscationDetector(apk_path).run()
        except Exception as e:
            obfuscation = {
                "obfuscation_score": 0,
                "obfuscation_level": "UNKNOWN",
                "error": str(e),
            }
        static["obfuscation"] = obfuscation

        # ── Module 2: Dynamic sandbox ─────────────────────────────────────────
        update("RUNNING", 40)
        skip_sandbox = os.getenv("SKIP_DYNAMIC_SANDBOX", "").lower() in ("1", "true", "yes")
        if skip_sandbox:
            dynamic = {
                "frida_events":    [],
                "network_traffic": [],
                "file_mutations":  [],
                "sandbox_errors":  ["Dynamic sandbox skipped (SKIP_DYNAMIC_SANDBOX=true)"],
                "duration_secs":   0,
                "timestamp":       datetime.utcnow().isoformat() + "Z",
            }
        else:
            timeout = int(os.getenv("SANDBOX_TIMEOUT", "60"))
            dynamic = DynamicSandbox(apk_path).run(timeout=timeout)

        # ── Module 3: C2 detection + ML ───────────────────────────────────────
        update("RUNNING", 70)
        c2 = C2Detector().run(static, dynamic)

        # ── Gap 1: Correlation engine ─────────────────────────────────────────
        update("RUNNING", 85)
        try:
            correlation = CorrelationEngine().run(static, dynamic, c2)
        except Exception as e:
            correlation = {
                "confirmed":       [],
                "partial":         [],
                "total_confirmed": 0,
                "error":           str(e),
            }

        # ── Compute final score ───────────────────────────────────────────────
        update("RUNNING", 95)
        final_score = c2["final_score"]

        # Boost for confirmed CRITICAL patterns
        critical_count = sum(
            1 for p in correlation.get("confirmed", [])
            if p.get("severity") == "CRITICAL"
        )
        final_score = min(final_score + critical_count * 3, 100)

        # Boost slightly for heavy obfuscation
        obf_score = obfuscation.get("obfuscation_score", 0)
        if obf_score >= 70:
            final_score = min(final_score + 5, 100)

        # score_to_label is the single shared threshold (see c2_detector.py),
        # so this verdict can't disagree with c2["verdict"] on what a given
        # score means — it's just evaluated on the further-boosted final_score
        # (correlation + obfuscation boosts applied above, after C2Detector ran).
        verdict = score_to_label(final_score)
        c2["verdict"] = verdict

        results = {
            "job_id":      job_id,
            "filename":    job.filename,
            "static":      static,
            "dynamic":     dynamic,
            "c2":          c2,
            "correlation": correlation,
            "verdict":     verdict,
            "final_score": final_score,
        }

        update("DONE", 100, {
            "results_json": json.dumps(results),
            "completed_at": datetime.utcnow(),
        })

    except Exception as e:
        update("FAILED", 0, {"error_message": str(e)})
        raise
    finally:
        db.close()
