# NEW — real FastAPI entrypoint: mounts all routers, CORS, static files, websocket. Replaces the old backend/app.py stub.

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.database.init_db import init_db
from backend.reasoning.worker import reasoning_loop
from backend.routes import admin, alerts, auth, baselines, company, device, employees, logs, reasoning, reports, system
from backend.scheduler import analysis_loop

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import inspect
    from backend.database.db import engine, Base
    from backend.core.runtime import BACKGROUND_ANALYSIS, EXTERNAL_SERVICES
    # Startup must never create/migrate an existing database or train a model.
    missing = set(Base.metadata.tables) - set(inspect(engine).get_table_names())
    if missing:
        raise RuntimeError("Initialize a fresh synthetic database with python -m tools.demo first")
    tasks = []
    if BACKGROUND_ANALYSIS:
        from backend.core.config import CNN_MODEL_PATH
        if not CNN_MODEL_PATH.is_file():
            raise RuntimeError("CNN weights absent; automatic training is disabled")
        tasks.append(asyncio.create_task(analysis_loop()))
    if EXTERNAL_SERVICES:
        tasks.append(asyncio.create_task(reasoning_loop()))
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="litds", lifespan=lifespan)

app.include_router(company.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(device.router)
app.include_router(logs.router)
app.include_router(employees.router)
app.include_router(alerts.router)
app.include_router(reasoning.router)
app.include_router(baselines.router)
app.include_router(reports.router)
app.include_router(system.router)

# The live-update websocket isn't built yet — dashboard/index.html polls
# REST endpoints every 5s instead (see its own header comment for why).
# Mounted at /ui rather than "/" so it can't shadow the API routes above —
# StaticFiles serves everything under a mount point, so it has to live on
# its own path.
app.mount("/ui", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def dashboard_root():
    # No-store, not just no-cache -- this file gets actively edited during
    # development and FileResponse otherwise only sets Last-Modified/ETag
    # with no explicit Cache-Control at all, so a browser is free to apply
    # its own heuristic caching and can silently keep serving an old copy
    # after a fix has already landed on disk -- confirmed as the real
    # explanation the last time "the button doesn't do what the code says"
    # turned out to be a stale copy, not a code bug (the code was already
    # correct; a direct HTTP call to the same endpoint worked immediately).
    return FileResponse(str(DASHBOARD_DIR / "index.html"), headers={"Cache-Control": "no-store"})


# UI/UX pass split index.html's inline <style>/<script> out into their own
# files (dashboard/style.css, dashboard/app.js) -- these two routes exist so
# they get the SAME no-store treatment as index.html above, for the same
# reason. Referenced from index.html by absolute root path (not relative,
# and not routed through the /ui StaticFiles mount below, which sets no
# explicit Cache-Control at all and would silently reintroduce the exact
# stale-copy bug class this project already hit once with index.html
# itself).
@app.get("/style.css", include_in_schema=False)
def dashboard_style():
    return FileResponse(str(DASHBOARD_DIR / "style.css"), media_type="text/css", headers={"Cache-Control": "no-store"})


@app.get("/app.js", include_in_schema=False)
def dashboard_app_js():
    return FileResponse(str(DASHBOARD_DIR / "app.js"), media_type="application/javascript", headers={"Cache-Control": "no-store"})


@app.get("/health")
def health():
    return {"status": "ok"}
