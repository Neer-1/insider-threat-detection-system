# NEW — read-only observability into the learned baseline system
# (agent_logic/baseline_learning.py). Lets an admin (or this project's own
# verification work) actually see what the system currently believes is
# "normal" for a department or an individual device, rather than that
# being an invisible internal number nobody can inspect.

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.agent_logic.baseline_learning import get_effective_baseline
from backend.agent_logic.departments import baseline_floor_for, get_department
from backend.auth.dependencies import get_current_admin
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.baselines import DepartmentBaseline, DeviceBaseline
from backend.models.devices import Device, DeviceMetadata

router = APIRouter(prefix="/baselines", tags=["baselines"])


def _serialize(b) -> dict | None:
    if b is None:
        return None
    return {
        "files_accessed_mean": b.files_accessed_mean,
        "files_accessed_var": b.files_accessed_var,
        "login_hour_mean": b.login_hour_mean,
        "login_hour_var": b.login_hour_var,
        "failed_logins_mean": b.failed_logins_mean,
        "failed_logins_var": b.failed_logins_var,
        "sample_count": b.sample_count,
        "login_hour_sample_count": b.login_hour_sample_count,
        "updated_at": b.updated_at,
    }


@router.get("/device/{device_public_id}")
def get_device_baseline(
    device_public_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Returns, for one device: the static ROLE_BASELINES floor, the raw
    learned device-level and department-level numbers (each None if no
    history has accumulated yet), and the actual effective (blended)
    values feature_extractor.py is using right now -- so the blend/trust
    ramp described when this feature was proposed is something that can be
    checked, not just trusted."""
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    # Genuinely None when unset -- not the old "engineering" fallback name.
    # agent_logic/departments.py's baseline_floor_for already treats None
    # exactly like an unrecognized department (generic floor).
    department = metadata.department if metadata and metadata.department else None

    dev_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device.device_id).first()
    dept_baseline = (
        db.query(DepartmentBaseline)
        .filter(DepartmentBaseline.department_id == metadata.department_id)
        .first()
    ) if metadata and metadata.department_id is not None else None

    return {
        "device_id": device.public_id,
        "department": department or "unassigned",
        "static_default": baseline_floor_for(db, admin.company_id, department),
        "learned_device": _serialize(dev_baseline),
        "learned_department": _serialize(dept_baseline),
        "effective": get_effective_baseline(db, device.device_id, admin.company_id, department),
    }


@router.get("/department/{department}")
def get_department_baseline(
    department: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Same idea as above, department-only -- no specific device's personal
    blend, just what this company's collective learned baseline for the
    department looks like against the static floor."""
    department_row = get_department(db, admin.company_id, department)
    dept_baseline = None
    if department_row is not None:
        dept_baseline = db.query(DepartmentBaseline).filter(
            DepartmentBaseline.department_id == department_row.id
        ).first()
    return {
        "department": department,
        "static_default": baseline_floor_for(db, admin.company_id, department),
        "learned": _serialize(dept_baseline),
    }
