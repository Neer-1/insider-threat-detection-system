"""Bounded release-path smoke test; no server sockets, model loads or collection."""
import os, sys, tempfile, pathlib, secrets, base64, json, re
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
work=pathlib.Path(sys.argv[1]).resolve();work.mkdir(parents=True,exist_ok=True)
folder=pathlib.Path(tempfile.mkdtemp(prefix="litds-synthetic-",dir=work));dbfile=folder/"demo.sqlite"
os.environ.update(PYTHON_DOTENV_DISABLED="1",DATABASE_URL="sqlite:///"+dbfile.as_posix(),SECRET_KEY=secrets.token_urlsafe(40),SMTP_ENCRYPTION_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),LITDS_BACKGROUND_ANALYSIS="0",LITDS_EXTERNAL_SERVICES="0")
results=[]
def check(n,v):
    results.append({"test":n,"pass":bool(v)})
    if not v:raise AssertionError(n)
engine=None
try:
    from backend.main import app
    from backend.database.db import engine,SessionLocal
    print("Import observation:", {"database_created":dbfile.exists(),"loaded_libraries":[m for m in ("torch","pandas","sklearn") if m in sys.modules]})
    check("Safe import: no database file or model libraries",not dbfile.exists() and not any(m in sys.modules for m in ("torch","pandas","sklearn")))
    from tools.demo import seed_demo
    password=secrets.token_urlsafe(18)
    seeded=seed_demo(password)
    check("Fresh synthetic initialization and full deterministic pipeline",dbfile.exists() and seeded["ml_mode"].startswith("disabled"))
    from backend.database.init_db import init_db
    try:init_db();check("Existing database refused",False)
    except RuntimeError:check("Existing database refused",True)
    from backend.models.company import Company
    from backend.models.devices import Device
    from backend.models.logs import Log
    from backend.models.responses import Response
    from backend.agent_logic.feature_extractor import extract_features
    from backend.agent_logic.risk_scorer import score_risk
    from sqlalchemy import text
    with SessionLocal() as db:
        device=db.query(Device).one();public_id=device.public_id;device_token=device.device_token
        f=extract_features(db,device.company_id,device.device_id,datetime.now(timezone.utc)-timedelta(minutes=15),datetime.now(timezone.utc)+timedelta(seconds=1))
        check("Feature counts from synthetic logs",f["files_accessed"]==3 and f["failed_logins"]==5 and f["sensitive_files"]==3)
        a=score_risk(f,[],{"profile_flags":[]},0.0);b=score_risk(f,[],{"profile_flags":[]},1.0)
        check("Risk bounds and 20-point ML contribution",0<=a["risk_score"]<=100 and b["risk_score"]==min(100,a["risk_score"]+20))
        check("SQLite foreign keys enabled",db.execute(text("PRAGMA foreign_keys")).scalar()==1)
        db.add(Log(company_id=9999,device_id=device.device_id,event_type="heartbeat"))
        from sqlalchemy.exc import IntegrityError
        try:db.commit();check("Invalid FK rejected",False)
        except IntegrityError:db.rollback();check("Invalid FK rejected",True)
        check("Recommendations never enforced",all(r.status=="pending" for r in db.query(Response).all()))
    from fastapi.testclient import TestClient
    with TestClient(app) as client, patch("socket.socket.connect",side_effect=AssertionError("Network access prohibited")):
        check("Startup uses initialized DB without background model load",client.get("/health").status_code==200 and "torch" not in sys.modules)
        for path in ["/device","/employees","/alerts","/company/me","/system/health"]:check("Unauthenticated "+path,client.get(path).status_code==401)
        check("Invalid JWT rejected",client.get("/employees",headers={"Authorization":"Bearer wrong"}).status_code==401)
        check("Wrong password rejected",client.post("/auth/login",json={"username":"demo-owner","password":"wrong-password"}).status_code==401)
        check("Oversized password rejected safely",client.post("/auth/login",json={"username":"demo-owner","password":"x"*73}).status_code==401)
        login=client.post("/auth/login",json={"username":"demo-owner","password":password});check("Real bcrypt login",login.status_code==200)
        headers={"Authorization":"Bearer "+login.json()["access_token"]}
        check("Employee API",client.get("/employees",headers=headers).status_code==200)
        check("Device detail API",client.get("/employees/"+public_id,headers=headers).status_code==200)
        check("Alerts API",client.get("/alerts",headers=headers).status_code==200)
        check("External health probe disabled",client.get("/system/health",headers=headers).json()["lm_studio"]["status"]=="disabled")
        other=client.post("/company/register",json={"company_name":"Synthetic Tenant Two","admin_username":"synthetic-two","admin_password":password});check("Second tenant registration",other.status_code==201)
        otherlogin=client.post("/auth/login",json={"username":"synthetic-two","password":password})
        h2={"Authorization":"Bearer "+otherlogin.json()["access_token"]}
        check("Cross-tenant detail denied",client.get("/employees/"+public_id,headers=h2).status_code==404)
        check("Cross-tenant approval denied",client.post("/device/"+public_id+"/approve",headers=h2,json={"label":"Synthetic"}).status_code==404)
        check("Cross-tenant token polling denied",client.get("/device/"+public_id+"/status",headers={"X-Company-Code":other.json()["company_code"]}).status_code==401)
        check("Wrong device credential denied",client.post("/logs/ingest",json={"device_id":public_id,"device_token":"wrong","logs":[{"event_type":"heartbeat"}]}).status_code==403)
        check("Authenticated synthetic ingestion",client.post("/logs/ingest",json={"device_id":public_id,"device_token":device_token,"logs":[{"event_type":"heartbeat"}]}).status_code==201)
        check("Wipe route absent",client.post("/dev/wipe-all-data",headers=headers).status_code==404)
        for path in ["/","/style.css","/app.js"]:check("Dashboard resource "+path,client.get(path).status_code==200)
        check("No wildcard CORS",client.get("/health",headers={"Origin":"https://example.invalid"}).headers.get("access-control-allow-origin") is None)
        with SessionLocal() as db:
            db.query(Company).filter(Company.company_id==seeded["company_id"]).one().is_active=False;db.commit()
        check("Inactive tenant login rejected",client.post("/auth/login",json={"username":"demo-owner","password":password}).status_code==401)
        check("Inactive tenant existing JWT rejected",client.get("/employees",headers=headers).status_code==401)
    check("Model libraries remain unloaded",not any(m in sys.modules for m in ("torch","pandas","sklearn")))
finally:
    if engine is not None:engine.dispose()
    for f in folder.iterdir():
        assert f.is_file() and f.name.startswith("demo.sqlite");f.unlink()
    folder.rmdir()
    (work/"release-smoke-results.json").write_text(json.dumps({"results":results,"cleanup":"disposable SQLite removed"},indent=2))
print(json.dumps({"passed":sum(r["pass"] for r in results),"checks":len(results),"cleanup":"complete"}))


