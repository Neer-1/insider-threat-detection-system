# KEEP litds/backend/routes/logs.py — currently empty, becomes the real ingestion endpoint, scoped by company+device

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.agent_logic.significant_events import significant_log_predicate
from backend.auth.dependencies import get_current_admin
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.company import Company
from backend.models.devices import Device
from backend.models.logs import Log

router = APIRouter(prefix="/logs", tags=["logs"])


class LogEntry(BaseModel):
    event_type: str
    timestamp: datetime | None = None
    username: str | None = None
    action: str | None = None
    status: str | None = None
    process_name: str | None = None
    filepath: str | None = None
    destination_path: str | None = None
    file_size: int | None = None
    device_name: str | None = None
    domain: str | None = None
    ip_address: str | None = None
    additional_data: dict | None = None


class DeviceInfoSnapshot(BaseModel):
    hostname: str | None = None
    username: str | None = None
    os_info: str | None = None
    ip_address: str | None = None


class LogIngestRequest(BaseModel):
    device_id: str  # Device.public_id
    device_token: str  # issued at approval time — see routes/device.py
    logs: list[LogEntry]
    # Sent by the agent on every call (agent/device_info.py) regardless of
    # whether a refresh was ever requested -- cheap local lookups, no
    # reason to gate them. Only actually applied below when Device.
    # info_refresh_requested is set; otherwise ignored. Optional so older
    # agent builds without this field still ingest fine.
    device_info: DeviceInfoSnapshot | None = None


class LogIngestResponse(BaseModel):
    accepted: int


@router.post("/ingest", response_model=LogIngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_logs(payload: LogIngestRequest, db: Session = Depends(get_db)):
    """Device-facing, not admin-facing — employees never get a dashboard
    login (onboarding_flow.md). Authenticated by device_token rather than
    the company-wide code: a leaked token only ever compromises one
    device's log stream, and revoking a single device doesn't require
    rotating every other device's credential.

    Rejecting an unapproved/unrecognised/revoked device here (rather than
    silently accepting) is what makes the agent's local buffering kick in:
    the agent buffers on ANY failed send, so "not approved yet", "revoked",
    and "no internet" all look the same from its side and correctly fall
    back to local buffering + retry."""

    device = db.query(Device).filter(Device.public_id == payload.device_id).first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # Constant-time comparison — a plain == would let response timing leak
    # how many leading characters of a guessed token were correct.
    token_ok = device.device_token is not None and secrets.compare_digest(device.device_token.encode('utf-8'), payload.device_token.encode('utf-8'))
    if not token_ok or device.approval_status != "approved":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device not approved or invalid token")

    company = db.query(Company).filter(Company.company_id == device.company_id).first()
    if company is None or not company.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Company is inactive")

    now = datetime.now(timezone.utc)
    for entry in payload.logs:
        db.add(
            Log(
                company_id=device.company_id,
                device_id=device.device_id,
                timestamp=entry.timestamp or now,
                event_type=entry.event_type,
                username=entry.username,
                action=entry.action,
                status=entry.status,
                process_name=entry.process_name,
                filepath=entry.filepath,
                destination_path=entry.destination_path,
                file_size=entry.file_size,
                device_name=entry.device_name,
                domain=entry.domain,
                ip_address=entry.ip_address,
                additional_data=entry.additional_data,
                processed=False,
            )
        )

    device.last_seen = now
    device.connection_status = "online"

    # Device-info refresh request (profile page "Refresh device info"
    # button, routes/device.py's request_device_info_refresh) fulfilled
    # here, on the device's own next check-in -- there's no way to reach
    # the agent directly. Only overwrites fields the agent actually sent a
    # value for, and only when a refresh was actually pending.
    if device.info_refresh_requested and payload.device_info is not None:
        info = payload.device_info
        if info.hostname:
            device.hostname = info.hostname
        if info.username:
            device.username = info.username
        if info.os_info:
            device.os_info = info.os_info
        if info.ip_address:
            device.ip_address = info.ip_address
        device.info_refresh_requested = False

    db.commit()

    return LogIngestResponse(accepted=len(payload.logs))


@router.get("/significant")
def list_significant_logs(
    device_id: str | None = None,
    limit: int = 100,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Admin-facing, read-only DERIVED VIEW over the same Log table
    /logs/ingest writes to. Nothing here filters or deletes what's
    stored — every raw Log row stays exactly as ingested, unmodified, for
    forensics/audits/future model retraining (this project never hard-
    deletes logs anywhere else in the schema either). This just narrows
    what's worth surfacing on a log-facing UI panel to rows that match a
    significant event type or threshold — independent of whether the
    scheduler has run an analysis cycle over them yet, so it stays useful
    even for a device with no alerts.

    The predicate mirrors agent_logic/anomaly_detector.py's per-row-
    expressible checks (USB, privilege escalation, failed logins,
    sensitive filepaths, large print jobs, after-hours, downloads,
    installs). It deliberately does NOT try to reproduce window-aggregate
    checks like access_velocity or baseline_deviation — those are
    properties of a whole feature window, not any single log row, and
    approximating them here would just be a second, more fragile copy of
    feature_extractor.py's math.
    """
    query = (
        db.query(Log, Device.public_id)
        .join(Device, Device.device_id == Log.device_id)
        .filter(Log.company_id == admin.company_id)
    )
    if device_id:
        query = query.filter(Device.public_id == device_id)

    rows = (
        query.filter(significant_log_predicate())
        .order_by(Log.timestamp.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
    return [
        {
            "log_id": log.log_id,
            "device_id": public_id,  # Device.public_id, same shape as /alerts and /employees
            "timestamp": log.timestamp,
            "event_type": log.event_type,
            "action": log.action,
            "status": log.status,
            "filepath": log.filepath,
            "file_size": log.file_size,
            "device_name": log.device_name,
            "ip_address": log.ip_address,
            "username": log.username,
        }
        for log, public_id in rows
    ]


@router.get("/raw")
def list_raw_logs(
    device_id: str,
    limit: int = 50,
    offset: int = 0,
    start: datetime | None = None,
    end: datetime | None = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Admin-facing, read-only, completely UNFILTERED view over one
    device's Log rows — every column, newest first, paginated. Distinct
    from /logs/significant above: that one narrows to what's worth
    surfacing at a glance, this one is the raw forensic record underneath
    it, for when an admin needs to see everything a device actually did
    around a given time, not just what tripped a rule. Doesn't touch
    storage or analysis in any way — purely a display-side query."""
    device = (
        db.query(Device)
        .filter(Device.public_id == device_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    query = db.query(Log).filter(Log.company_id == admin.company_id, Log.device_id == device.device_id)
    if start is not None:
        query = query.filter(Log.timestamp >= start)
    if end is not None:
        query = query.filter(Log.timestamp < end)

    total = query.count()
    page_limit = min(max(limit, 1), 200)
    rows = (
        query.order_by(Log.timestamp.desc())
        .offset(max(offset, 0))
        .limit(page_limit)
        .all()
    )

    return {
        "total": total,
        "limit": page_limit,
        "offset": offset,
        "logs": [
            {
                "log_id": log.log_id,
                "device_id": device_id,
                "timestamp": log.timestamp,
                "event_type": log.event_type,
                "username": log.username,
                "action": log.action,
                "status": log.status,
                "process_name": log.process_name,
                "filepath": log.filepath,
                "destination_path": log.destination_path,
                "file_size": log.file_size,
                "device_name": log.device_name,
                "domain": log.domain,
                "ip_address": log.ip_address,
                "additional_data": log.additional_data,
            }
            for log in rows
        ],
    }
