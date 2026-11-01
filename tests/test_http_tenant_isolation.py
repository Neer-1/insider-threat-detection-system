"""In-process HTTP + fresh in-memory SQLite. No production startup or model loading."""
import os
import base64
import importlib
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-only-signing-key-with-32-chars'
os.environ['SMTP_ENCRYPTION_KEY'] = base64.urlsafe_b64encode(b'0'*32).decode()

import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.database.db import Base, get_db
# Reviewed modules contain SQLAlchemy declarations, not runtime services.
for path in (Path(__file__).resolve().parents[1]/'backend/models').glob('*.py'):
    if path.stem != '__init__': importlib.import_module('backend.models.'+path.stem)
from backend.models.company import Company
from backend.models.admin import Admin
from backend.models.devices import Device
from backend.models.logs import Log
from backend.auth.security import create_access_token
from backend.routes.device import router as device_router
from backend.routes.logs import router as logs_router

class TenantHTTPTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session=sessionmaker(bind=self.engine)
        with self.Session() as db:
            db.add_all([Company(company_id=i,company_name='Synthetic '+str(i),api_key='code-'+str(i),is_active=True) for i in [1,2]])
            db.flush()
            db.add(Admin(admin_id=1,company_id=1,username='synthetic-admin',password_hash='not-a-login-hash',role='owner',is_active=True))
            for i in [1,2]:
                db.add(Device(device_id=i,company_id=i,public_id='device-'+str(i),hostname='synthetic-'+str(i),device_fingerprint='fixture-'+str(i),device_token='token-'+str(i),approval_status='approved',connection_status='online'))
            db.commit()
        app=FastAPI()
        app.include_router(device_router); app.include_router(logs_router)
        def isolated_db():
            with self.Session() as db: yield db
        app.dependency_overrides[get_db]=isolated_db
        self.client=TestClient(app)
        self.headers={'Authorization':'Bearer '+create_access_token(1)}

    def tearDown(self):
        self.client.close(); self.engine.dispose()

    def test_admin_list_is_tenant_scoped(self):
        self.assertEqual(self.client.get('/device').status_code,401)
        result=self.client.get('/device',headers=self.headers)
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual([d['device_id'] for d in result.json()],['device-1'])

    def test_other_tenant_cannot_be_approved(self):
        result=self.client.post('/device/device-2/approve',headers=self.headers,json={'label':'Synthetic'})
        self.assertEqual(result.status_code,404,result.text)
        with self.Session() as db: self.assertEqual(db.get(Device,2).device_token,'token-2')

    def test_status_requires_correct_tenant_proof(self):
        self.assertEqual(self.client.get('/device/device-1/status').status_code,422)
        self.assertEqual(self.client.get('/device/device-1/status',headers={'X-Company-Code':'code-2'}).status_code,401)
        result=self.client.get('/device/device-1/status',headers={'X-Company-Code':'code-1'})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['device_token'],'token-1')

    def test_ingestion_rejects_wrong_or_non_ascii_token(self):
        for token in ['token-2','invalid-\u00e9']:
            result=self.client.post('/logs/ingest',json={'device_id':'device-1','device_token':token,'logs':[{'event_type':'heartbeat'}]})
            self.assertEqual(result.status_code,403,result.text)
        with self.Session() as db: self.assertEqual(db.query(Log).count(),0)

    def test_valid_ingestion_stays_with_device_tenant(self):
        result=self.client.post('/logs/ingest',json={'device_id':'device-1','device_token':'token-1','logs':[{'event_type':'heartbeat'}]})
        self.assertEqual(result.status_code,201,result.text)
        with self.Session() as db:
            row=db.query(Log).one(); self.assertEqual((row.company_id,row.device_id),(1,1))

    def test_inactive_company_blocks_admin_and_device(self):
        with self.Session() as db:
            db.get(Company,1).is_active=False; db.commit()
        self.assertEqual(self.client.get('/device',headers=self.headers).status_code,401)
        self.assertEqual(self.client.get('/device/device-1/status',headers={'X-Company-Code':'code-1'}).status_code,401)
        result=self.client.post('/logs/ingest',json={'device_id':'device-1','device_token':'token-1','logs':[{'event_type':'heartbeat'}]})
        self.assertEqual(result.status_code,403,result.text)
        with self.Session() as db: self.assertEqual(db.query(Log).count(),0)

    def test_expired_missing_expiry_and_bad_signature_rejected(self):
        key=os.environ['SECRET_KEY']
        tokens=[jwt.encode({'sub':'1'},key,algorithm='HS256'),
                jwt.encode({'sub':'1','exp':datetime.now(timezone.utc)-timedelta(seconds=1)},key,algorithm='HS256'),
                jwt.encode({'sub':'1','exp':datetime.now(timezone.utc)+timedelta(minutes=1)},'wrong-test-key-with-more-than-32-characters',algorithm='HS256')]
        for token in tokens:
            result=self.client.get('/device',headers={'Authorization':'Bearer '+token})
            self.assertEqual(result.status_code,401,result.text)
