"""Create a fresh synthetic demo; never collect endpoint data or load models."""
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

def seed_demo(password):
    from backend.auth.security import hash_password
    password_hash = hash_password(password)
    from backend.database.init_db import init_db, seed_default_departments
    from backend.database.db import SessionLocal
    from backend.models.company import Company
    from backend.models.admin import Admin
    from backend.models.devices import Device
    from backend.models.logs import Log
    from backend.agent_logic.analyzer import analyze_device_window
    init_db()  # refuses any existing tables
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        company = Company(company_name="Synthetic Demo Company", api_key=secrets.token_hex(16))
        db.add(company); db.flush()
        db.add(Admin(company_id=company.company_id, username="demo-owner", password_hash=password_hash, role="owner"))
        device = Device(company_id=company.company_id, hostname="synthetic-workstation", username="synthetic-user", device_fingerprint="synthetic-fixture-01", device_token=secrets.token_hex(32), approval_status="approved", connection_status="offline", label="Synthetic Employee")
        db.add(device); db.commit(); db.refresh(device)
        seed_default_departments(db, company.company_id)
        for i in range(5):
            db.add(Log(company_id=company.company_id, device_id=device.device_id, timestamp=now-timedelta(seconds=60-i), event_type="authentication", status="fail", username="synthetic-user"))
        for i in range(3):
            db.add(Log(company_id=company.company_id, device_id=device.device_id, timestamp=now-timedelta(seconds=30-i), event_type="file", action="read", filepath="/synthetic/payroll/sample-"+str(i)+".txt", file_size=1024))
        db.commit()
        # Zero ML contribution; unsupported confidence is explicitly unknown.
        result=analyze_device_window(db,company.company_id,device.device_id,now-timedelta(minutes=15),now,lambda sequence:(0.0,None))
        return {"company_id":company.company_id,"device_id":device.public_id,"ml_mode":"disabled; deterministic rules only","risk_score":result.get("risk_score")}

def main():
    from getpass import getpass
    from sqlalchemy.engine import make_url
    from backend.core import env
    url=make_url(os.environ.get("DATABASE_URL", ""))
    if url.drivername != "sqlite" or not url.database or url.database == ":memory:":
        raise SystemExit("Demo setup requires a new SQLite file under ./demo-data")
    target=Path(url.database).resolve(); allowed=(Path.cwd()/"demo-data").resolve()
    if not target.is_relative_to(allowed) or target.exists():
        raise SystemExit("Refusing existing/out-of-demo-data database; choose a new demo-data filename")
    password=getpass("Choose a synthetic demo-owner password (8-72 UTF-8 bytes): ")
    if not 8 <= len(password.encode("utf-8")) <= 72:
        raise SystemExit("Password must be 8-72 UTF-8 bytes")
    target.parent.mkdir(parents=True,exist_ok=True)
    result=seed_demo(password)
    print("Synthetic demo ready. Sign in as demo-owner with the password you chose.")
    print("ML inference disabled; rule-based demo risk:",result["risk_score"])

if __name__ == "__main__":main()
