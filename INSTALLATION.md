# Exact tested installation

Verified on Windows with CPython 3.12.3 and bootstrap pip 24.0. Other Python versions/platforms are unverified. No package installation occurred while preparing candidate02.

## Server and deterministic demo

From the repository root, create a new environment. The following command names all 33 tested server packages explicitly so that transitive versions match the completed experiment. Do not remove pins or substitute source builds if resolution fails.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --index-url https://pypi.org/simple --only-binary=:all: annotated-doc==0.0.5 annotated-types==0.8.0 anyio==4.14.2 bcrypt==5.0.0 certifi==2026.10.19 cffi==2.1.1 charset-normalizer==3.5.2 click==8.5.0 cryptography==50.0.1 defusedxml==0.7.1 fastapi==0.135.0 fonttools==4.68.0 fpdf2==2.8.8 greenlet==3.5.6 h11==0.16.0 httpcore==1.0.9 httpx==0.28.1 idna==3.15 pdfminer.six==20260107 pdfplumber==0.11.10 pillow==13.0.0 pycparser==3.12 pydantic==2.10.4 pydantic_core==2.27.2 PyJWT==2.14.0 pypdfium2==5.14.0 python-dotenv==1.0.1 python-multipart==0.0.31 SQLAlchemy==2.0.30 starlette==1.3.1 typing_extensions==4.16.0 typing-inspection==0.4.4 uvicorn==0.34.0
.\.venv\Scripts\python -m pip check
```

The experiment verified SHA-256 hashes of downloaded official wheels before offline hash-required installation. This documented command pins versions but does not enforce those hashes; it is not a cross-platform hash lock. The private validation evidence retains exact wheel URLs, hashes and installed-version records. Follow README's key-generation and synthetic database setup after installation. Keep generated keys, .env, test evidence and databases private.

## Separate collector/test supplement

The existing regression module imports collector code. Install this supplement into the same disposable test environment to execute all 18 regressions; it is not needed for the deterministic server demo:

```powershell
.\.venv\Scripts\python -m pip install --index-url https://pypi.org/simple --only-binary=:all: --no-deps requests==2.34.2 psutil==7.2.2 urllib3==2.8.0
.\.venv\Scripts\python -m pip check
.\.venv\Scripts\python -B -m unittest discover -s tests -p "test_*.py" -v
```

The --no-deps supplement command assumes the exact server installation above, which already supplies requests' other dependencies. All 33 existing versions were verified unchanged after the supplement. Collector module import succeeded; the collector was not run against devices. agent/requirements.txt remains the original separate, unpinned agent declaration; it is not the reproducible test setup above.

## Recorded results and limits

36/36 release checks passed before the supplement; 18/18 regressions passed after it (including the 11 previously blocked by missing collector imports). Zero regression failures or collection errors remained. pip check passed. A separate targeted synthetic SQLite run observed the real analyzer returning unsupported ml_confidence as JSON null and ml_anomaly_score zero, with default-off background/external flags, model libraries unloaded and network connections blocked. Disposable databases were removed.

The null-confidence observation harness and logs are retained in private release evidence rather than added to production code or a new regression suite. The release checks were not rerun after the supplement. A non-fatal Starlette TestClient httpx deprecation warning was recorded; no httpx2 substitution was made. Experimental ML, collector operation, browser rendering and optional SMTP/LLM/PDF workflows require separate validation. No production-readiness claim is made.
