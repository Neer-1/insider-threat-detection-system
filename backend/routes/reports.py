# NEW — company-wide weekly report. "Runs synchronously -- the admin
# waits" from the admin's own point of view (the button stays in a
# waiting state, they don't navigate away and come back), but implemented
# as start-job / poll-status / fetch-result under the hood: a single
# indivisible HTTP request/response can't report partial progress mid-
# flight, and a per-employee LLM call taking ~10-20s each, serially (one
# local model, one request at a time), realistically means minutes -- up
# to ~30 for a larger roster in the worst case (see the report accompanying
# this feature for the measured numbers this estimate is based on). A
# static spinner for that long is indistinguishable from a hang; this
# lets the frontend show real "employee N of Total" progress instead.

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response as FastAPIResponse
from sqlalchemy.orm import Session

from backend.auth.dependencies import get_current_admin
from backend.database.db import SessionLocal, get_db
from backend.models.admin import Admin
from backend.models.devices import Device
from backend.reasoning.narrative import generate_weekly_paragraph
from backend.reports.weekly_report import build_weekly_report_pdf, gather_weekly_context

router = APIRouter(prefix="/reports", tags=["reports"])

# In-memory job store, scoped to this process's lifetime -- matches the
# project's existing "one admin-installed server" deployment model (no
# persistence needed across a restart; regenerating a report is cheap
# relative to losing one in-progress job to a restart, which should be
# rare). Keyed by job_id; company_id kept on each job so status/result
# lookups stay scoped to the requesting admin's own company, same
# discipline as every other admin-facing route in this app.
_jobs: dict[str, dict] = {}


def _running_job_for_company(company_id: int) -> str | None:
    for job_id, job in _jobs.items():
        if job["company_id"] == company_id and job["status"] == "running":
            return job_id
    return None


async def _run_weekly_report(job_id: str, company_id: int, company_name: str) -> None:
    """Runs as its own asyncio task, independent of the request that
    started it -- the admin's browser polls status separately rather than
    holding one HTTP connection open for the whole (potentially 30+
    minute) duration. Opens its OWN db session (SessionLocal directly, not
    the request-scoped get_db dependency, which would already be closed
    by the time this is still running long after the starting request
    returned)."""
    job = _jobs[job_id]
    db: Session = SessionLocal()
    try:
        context = gather_weekly_context(db, company_id)
        job["total"] = len(context["employees"])

        weekly_paragraphs: dict[str, str | None] = {}
        for employee in context["employees"]:
            if employee["week_alerts"] or employee["week_decisions"]:
                # One employee's LLM call failing must not affect any
                # other's -- same per-section independence as the
                # per-employee report (backend/reasoning/narrative.py).
                weekly_paragraphs[employee["label"]] = await generate_weekly_paragraph(employee)
            job["processed"] += 1

        job["pdf_bytes"] = build_weekly_report_pdf(company_name, context, weekly_paragraphs)
        job["status"] = "done"
    except Exception as e:
        # A genuinely unexpected failure (not an LLM-call failure -- those
        # are already handled per-employee above and never raise) still
        # needs to surface as a clear job state rather than leave the
        # frontend polling a "running" job forever.
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        db.close()


@router.post("/weekly")
async def start_weekly_report(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """MUST be async def, not a plain def -- confirmed the hard way: a
    synchronous route handler runs in FastAPI's threadpool (starlette's
    run_in_threadpool), not on the main asyncio event loop uvicorn is
    actually driving. asyncio.create_task() called from that threadpool
    thread schedules the task onto a loop nothing ever advances, so the
    job silently never progresses past processed=0 -- it isn't an error,
    there's just no loop iteration left to run it. Being async def puts
    this handler (and therefore create_task) on the real event loop,
    the same one processing every other concurrent request, matching
    the pattern backend/routes/employees.py's own async report route
    already uses.

    Kicks off generation and returns immediately with a job_id.
    Reuses an already-running job for this company (rather than starting
    a second one) if called again while one is in progress -- LM Studio
    serves one request at a time regardless, so a second concurrent job
    would only double the wait for no benefit, not run any faster."""
    existing = _running_job_for_company(admin.company_id)
    if existing is not None:
        return {"job_id": existing}

    # Cheap upfront count just for the progress bar's initial "total"
    # before gather_weekly_context's own count (computed inside the task,
    # a moment later) is available.
    total = db.query(Device).filter(Device.company_id == admin.company_id, Device.approval_status == "approved").count()

    job_id = uuid.uuid4().hex
    job = {
        "company_id": admin.company_id,
        "status": "running",
        "processed": 0,
        "total": total,
        "pdf_bytes": None,
        "error": None,
        "started_at": datetime.now(timezone.utc),
    }
    _jobs[job_id] = job
    # Holding the Task object on the job dict is deliberate, not
    # decorative -- asyncio only holds a WEAK reference to a task with no
    # other referrer, which can let it be garbage-collected mid-run.
    # Keeping a strong reference here for as long as the job entry exists
    # avoids that.
    job["_task"] = asyncio.create_task(_run_weekly_report(job_id, admin.company_id, admin.company.company_name))
    return {"job_id": job_id}


def _get_job_for_admin(job_id: str, admin: Admin) -> dict:
    job = _jobs.get(job_id)
    if job is None or job["company_id"] != admin.company_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report job not found")
    return job


@router.get("/weekly/{job_id}/status")
def get_weekly_report_status(job_id: str, admin: Admin = Depends(get_current_admin)):
    job = _get_job_for_admin(job_id, admin)
    return {"status": job["status"], "processed": job["processed"], "total": job["total"], "error": job["error"]}


@router.get("/weekly/{job_id}/result.pdf")
def get_weekly_report_result(job_id: str, admin: Admin = Depends(get_current_admin)):
    job = _get_job_for_admin(job_id, admin)
    if job["status"] != "done":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Report is not ready yet (status: {job['status']})")

    return FastAPIResponse(
        content=job["pdf_bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="litds-weekly-report.pdf"'},
    )
