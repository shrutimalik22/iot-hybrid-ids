# backend/app/schemas.py
from pydantic import BaseModel
from typing import Optional, Literal, List, Dict
from enum import Enum
from datetime import datetime


class DeviceType(str, Enum):
    CAMERA = "camera"
    ROUTER = "router"
    BULB = "bulb"
    THERMOSTAT = "thermostat"
    LAPTOP = "laptop"
    SENSOR = "sensor"


class AttackType(str, Enum):
    DDOS = "ddos"
    PORTSCAN = "portscan"
    BOTNET = "botnet"


class DeviceStatus(BaseModel):
    id: str
    name: str
    device_type: DeviceType
    ip_address: str
    online: bool
    compromised: bool
    cpu_pct: float
    net_in_kbps: float
    net_out_kbps: float
    conn_count: int
    pkt_rate: float
    unique_dst_ports: int
    last_updated: float
    current_attack: Optional[AttackType] = None
    current_label: str = "benign"
    connected_to: Optional[str] = None   # <-- gateway/router id


class CreateDeviceRequest(BaseModel):
    name: str
    device_type: DeviceType


class ToggleRequest(BaseModel):
    device_id: str
    online: bool


class StartAttackRequest(BaseModel):
    attack_type: AttackType
    target_device_id: str
    duration_seconds: int = 30


class AttackStatus(BaseModel):
    active: bool
    attack_type: Optional[AttackType] = None
    target_device_id: Optional[str] = None
    seconds_remaining: int = 0


class SecurityEvent(BaseModel):
    id: int
    device_id: str
    device_name: str
    ip_address: Optional[str]
    severity: Literal["low", "medium", "high"]
    event_type: str
    message: str
    timestamp: float
    # ML explainability
    scores: Dict[str, float] = {}
    label_hint: Optional[str] = None


class FeatureWindow(BaseModel):
    device_id: str
    timestamp: datetime
    avg_net_in: float
    avg_net_out: float
    max_cpu: float
    avg_cpu: float
    avg_conn_count: float
    avg_pkt_rate: float
    avg_unique_ports: float
    label: str = "benign"
