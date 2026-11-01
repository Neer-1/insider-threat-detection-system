# NEW — Overview page's system-health strip: three independently-checked
# real signals (LM Studio reachability, last SMTP send outcome, whether
# the detection scheduler's own loop is still alive), never a single
# combined "all systems normal" badge.

"""
Read-only, no writes anywhere in this module. LM Studio's check is the one
genuinely slow/network-dependent call here (httpx, same async client
backend/reasoning/client.py already uses for the real chat calls, short
timeout) -- the other two are just reading already-tracked state
(CompanySmtpConfig.last_send_status, backend/scheduler.py's in-memory
get_last_cycle_at). Polled from the dashboard on its own longer cadence
(dashboard/app.js's refreshOverviewExtras, ~20s), not the 5s refreshAll
loop -- a live network probe every 5s would be wasteful and adds latency
risk to a poll that's otherwise pure DB reads.
"""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.auth.dependencies import get_current_admin
from backend.core.config import LM_STUDIO_BASE_URL, SCHEDULER_STALL_THRESHOLD_SECONDS
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.company_smtp_config import CompanySmtpConfig
from backend.scheduler import get_last_cycle_at

router = APIRouter(prefix="/system", tags=["system"])

_LM_STUDIO_CHECK_TIMEOUT_SECONDS = 3.0


async def _check_lm_studio() -> dict:
    """Server-wide, not company-scoped -- one shared local LM Studio
    instance per server, same as the AI Reasoning Core itself. A plain GET
    against the OpenAI-compatible /models endpoint is enough to confirm
    "something is listening and answering," the same reachability check
    used when this integration was first built and confirmed working."""
    from backend.core.runtime import EXTERNAL_SERVICES
    if not EXTERNAL_SERVICES:
        return {"status": "disabled", "detail": "External services disabled in the release demo"}
    try:
        async with httpx.AsyncClient(timeout=_LM_STUDIO_CHECK_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{LM_STUDIO_BASE_URL}/models")
            response.raise_for_status()
        return {"status": "ok", "detail": "Reachable"}
    except httpx.HTTPError as e:
        return {"status": "failing", "detail": f"Unreachable ({type(e).__name__})"}


def _check_smtp(db: Session, company_id: int) -> dict:
    """Reuses CompanySmtpConfig.last_send_status/last_send_at/
    last_send_error exactly as already surfaced on the Company Profile
    SMTP card (routes/company.py's get_company_smtp) -- no new tracking.
    "unknown" (not "failing") when nothing's been configured or attempted
    yet -- there's no real signal to report either way, and collapsing
    that into "failing" would be a false alarm on a company that simply
    hasn't set this up."""
    config = db.query(CompanySmtpConfig).filter(CompanySmtpConfig.company_id == company_id).first()
    if config is None or config.last_send_status is None:
        return {"status": "unknown", "detail": "No send attempted yet", "last_send_at": None}
    last_send_at = config.last_send_at.isoformat() if config.last_send_at else None
    if config.last_send_status == "success":
        return {"status": "ok", "detail": "Last send succeeded", "last_send_at": last_send_at}
    return {"status": "failing", "detail": config.last_send_error or "Last send failed", "last_send_at": last_send_at}


def _check_scheduler() -> dict:
    """"Recent" is SCHEDULER_STALL_THRESHOLD_SECONDS (core/config.py) --
    3x the real cycle interval, same reasoning shape as the device-offline
    staleness check. "unknown" right after a fresh server start, before
    the first cycle has even had a chance to complete yet (ANALYSIS_
    INITIAL_DELAY_SECONDS) -- not a false "stalled" alarm for a loop that
    simply hasn't run once yet."""
    last = get_last_cycle_at()
    if last is None:
        return {"status": "unknown", "detail": "Not run yet", "last_cycle_at": None}
    age_seconds = (datetime.now(timezone.utc) - last).total_seconds()
    if age_seconds > SCHEDULER_STALL_THRESHOLD_SECONDS:
        return {"status": "failing", "detail": f"Last cycle {int(age_seconds)}s ago", "last_cycle_at": last.isoformat()}
    return {"status": "ok", "detail": "Running normally", "last_cycle_at": last.isoformat()}


@router.get("/health")
async def get_system_health(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Three independent checks, always all three, never collapsed into
    one combined badge -- each can be ok/failing/unknown on its own,
    regardless of the other two's state."""
    return {
        "lm_studio": await _check_lm_studio(),
        "smtp": _check_smtp(db, admin.company_id),
        "scheduler": _check_scheduler(),
    }
