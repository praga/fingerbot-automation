"""
FastAPI Server for Tuya Fingerbot Automation Dashboard
"""
import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .config import load_config, save_config, AppConfig
from .ble_controller import ble_controller
from .scheduler import bot_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("fingerbot.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Tuya Fingerbot Automation Service...")
    config = load_config()
    logger.info(f"Loaded config: Target MAC = {config.device_mac}, Interval = {config.interval_minutes}m")

    if config.auto_start_on_boot:
        logger.info("Auto-starting automation scheduler as configured...")
        bot_scheduler.start(config.interval_minutes, config.stop_after_hours)

    yield

    logger.info("Shutting down Fingerbot Automation Service...")
    bot_scheduler.stop()


app = FastAPI(title="Tuya Fingerbot Automation", lifespan=lifespan)

# Allow CORS for local network dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class StartAutomationRequest(BaseModel):
    interval_minutes: Optional[float] = None
    stop_after_hours: Optional[float] = None


@app.get("/api/status")
async def get_status():
    return bot_scheduler.get_status()


@app.post("/api/automation/start")
async def start_automation(req: Optional[StartAutomationRequest] = None):
    interval = req.interval_minutes if req else None
    stop_hours = req.stop_after_hours if req else None
    explicit_dur = req is not None and "stop_after_hours" in req.model_fields_set
    status = bot_scheduler.start(interval_minutes=interval, stop_after_hours=stop_hours, explicit_duration=explicit_dur)
    return {"status": "started", "data": status}


@app.post("/api/automation/update")
async def update_automation(req: Optional[StartAutomationRequest] = None):
    interval = req.interval_minutes if req else None
    stop_hours = req.stop_after_hours if req else None
    explicit_dur = req is not None and "stop_after_hours" in req.model_fields_set
    status = bot_scheduler.start(interval_minutes=interval, stop_after_hours=stop_hours, explicit_duration=explicit_dur)
    return {"status": "updated", "data": status}


@app.post("/api/automation/stop")
async def stop_automation():
    status = bot_scheduler.stop()
    return {"status": "stopped", "data": status}


@app.post("/api/trigger")
async def trigger_now():
    if ble_controller.is_busy:
        raise HTTPException(status_code=409, detail="BLE interface is currently busy with another operation")
    result = await bot_scheduler.trigger_now()
    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Fingerbot actuation failed")
        )
    return result


@app.get("/api/config")
async def get_config():
    return load_config().model_dump()


@app.post("/api/config")
async def update_config(new_config: AppConfig):
    save_config(new_config)
    # If scheduler is currently running and interval changed, update it
    if bot_scheduler.is_running:
        bot_scheduler.start(new_config.interval_minutes)
    return {"status": "success", "config": new_config.model_dump()}


@app.get("/api/scan")
async def scan_ble_devices():
    if ble_controller.is_busy:
        raise HTTPException(status_code=409, detail="BLE interface is currently in use")
    devices = await ble_controller.scan_nearby(duration=4.0)
    return {"devices": devices}


@app.get("/api/logs")
async def get_logs():
    return {"logs": bot_scheduler.get_logs()}


@app.post("/api/logs/clear")
async def clear_logs():
    bot_scheduler.logs.clear()
    return {"status": "cleared"}


# Mount frontend static directory
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn
    cfg = load_config()
    uvicorn.run("backend.main:app", host="0.0.0.0", port=cfg.port, reload=False)
