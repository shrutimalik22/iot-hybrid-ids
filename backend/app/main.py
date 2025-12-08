# backend/app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import asyncio

from .schemas import (
    DeviceStatus,
    CreateDeviceRequest,
    ToggleRequest,
    StartAttackRequest,
    AttackStatus,
    SecurityEvent,
)
from .models import lab_state

app = FastAPI(title="Hybrid IoT Security Lab")

# CORS for React dev server at http://localhost:5173
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
)


@app.on_event("startup")
async def on_startup():
    loop = asyncio.get_event_loop()
    loop.create_task(lab_state.simulation_loop())
    loop.create_task(lab_state.feature_and_detection_loop())


# -------- device endpoints --------

@app.get("/devices", response_model=list[DeviceStatus])
async def list_devices():
    return lab_state.list_devices()


@app.post("/devices", response_model=DeviceStatus)
async def create_device(req: CreateDeviceRequest):
    dev = lab_state.create_device(req.name, req.device_type)
    return dev.to_status()


@app.post("/devices/toggle", response_model=DeviceStatus)
async def toggle_device(req: ToggleRequest):
    try:
        lab_state.toggle_device(req.device_id, req.online)
    except KeyError:
        raise HTTPException(status_code=404, detail="Device not found")
    dev = lab_state.devices[req.device_id]
    return dev.to_status()


# -------- attack endpoints --------

@app.post("/attack/start", response_model=AttackStatus)
async def start_attack(req: StartAttackRequest):
    try:
        await lab_state.start_attack(
            attack_type=req.attack_type,
            target_device_id=req.target_device_id,
            duration_seconds=req.duration_seconds,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Target device not found")
    return lab_state.current_attack_status()


@app.post("/attack/stop", response_model=AttackStatus)
async def stop_attack():
    await lab_state.stop_attack()
    return lab_state.current_attack_status()


@app.get("/attack/status", response_model=AttackStatus)
async def attack_status():
    return lab_state.current_attack_status()


# -------- events / dashboard --------

@app.get("/events", response_model=list[SecurityEvent])
async def list_events(limit: int = 100):
    return list(reversed(list(lab_state.security_events)[-limit:]))
