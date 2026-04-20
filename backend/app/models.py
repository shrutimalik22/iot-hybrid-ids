# backend/app/models.py
import asyncio
import random
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import numpy as np
from joblib import load

from .schemas import (
    DeviceType,
    AttackType,
    DeviceStatus,
    AttackStatus,
    SecurityEvent,
    FeatureWindow,
)
from .config import (
    SIM_TICK_SECONDS,
    FEATURE_WINDOW_SEC,
    FEATURE_STEP_SEC,
    FEATURE_CSV_PATH,
    ISOFOREST_MODEL_PATH,
    RULE_PKT_RATE_TH,
    RULE_CONN_COUNT_TH,
    RULE_UNIQUE_PORTS_TH,
)
from pathlib import Path
import csv
import os


# ---------- helpers ----------

def _gen_ip(octet3: int) -> str:
    return f"192.168.{octet3}.{random.randint(2, 254)}"


@dataclass
class AttackScenario:
    kind: AttackType
    target_id: str
    ends_at: float
@dataclass
class FlowRecord:
    flow_id: str
    src_id: str
    dst_id: str
    start_time: float
    last_seen: float
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0


# inside models.py — replace VirtualDevice class and LabState._init_default_devices

class VirtualDevice:
    def __init__(self, device_id: str, name: str, d_type: DeviceType, ip_octet: int):
        self.device_id = device_id
        self.name = name
        self.device_type = d_type
        self.ip_address = _gen_ip(ip_octet)
        self.online = True
        self.compromised = False
        self.current_attack: Optional[AttackType] = None
        self.connected_to: Optional[str] = None  # will be assigned by LabState

        # base (stable) profile — set once
        self.base_net_in = 0.0
        self.base_net_out = 0.0
        self.base_cpu = 0.0
        self.base_conns = 0
        self.base_pkt_rate = 0.0
        self.base_unique_ports = 0

        # live values
        self.cpu_pct = 0.0
        self.net_in_kbps = 0.0
        self.net_out_kbps = 0.0
        self.conn_count = 0
        self.pkt_rate = 0.0
        self.unique_dst_ports = 0
        self.last_updated = time.time()
        self.current_label = "benign"
# ✅ ADD THIS
        self.active_flows: Dict[str, FlowRecord] = {}

        # initialize stable base
        self._set_base_profile()

    def _set_base_profile(self):
        # Set device-type specific steady base values (not random every tick)
        if self.device_type == DeviceType.CAMERA:
            self.base_net_in = random.uniform(50, 150)
            self.base_net_out = random.uniform(20, 70)
            self.base_cpu = random.uniform(10, 30)
            self.base_conns = random.randint(5, 12)
            self.base_unique_ports = random.randint(3, 8)
        elif self.device_type == DeviceType.ROUTER:
            self.base_net_in = random.uniform(200, 600)
            self.base_net_out = random.uniform(200, 600)
            self.base_cpu = random.uniform(8, 25)
            self.base_conns = random.randint(20, 80)
            self.base_unique_ports = random.randint(10, 40)
        elif self.device_type == DeviceType.BULB:
            self.base_net_in = random.uniform(1, 8)
            self.base_net_out = random.uniform(1, 8)
            self.base_cpu = random.uniform(2, 8)
            self.base_conns = random.randint(1, 4)
            self.base_unique_ports = random.randint(1, 4)
        elif self.device_type == DeviceType.THERMOSTAT:
            self.base_net_in = random.uniform(3, 12)
            self.base_net_out = random.uniform(3, 12)
            self.base_cpu = random.uniform(3, 15)
            self.base_conns = random.randint(2, 7)
            self.base_unique_ports = random.randint(2, 6)
        elif self.device_type == DeviceType.LAPTOP:
            self.base_net_in = random.uniform(80, 200)
            self.base_net_out = random.uniform(40, 150)
            self.base_cpu = random.uniform(5, 35)
            self.base_conns = random.randint(8, 35)
            self.base_unique_ports = random.randint(5, 20)
        else:
            self.base_net_in = random.uniform(5, 30)
            self.base_net_out = random.uniform(2, 20)
            self.base_cpu = random.uniform(5, 20)
            self.base_conns = random.randint(2, 10)
            self.base_unique_ports = random.randint(2, 8)

        # base packet rate derived from connections
        self.base_pkt_rate = max(1.0, self.base_conns * random.uniform(5, 15))

        # initialize live to base
        self.net_in_kbps = round(self.base_net_in, 2)
        self.net_out_kbps = round(self.base_net_out, 2)
        self.cpu_pct = round(self.base_cpu, 2)
        self.conn_count = int(self.base_conns)
        self.pkt_rate = round(self.base_pkt_rate, 2)
        self.unique_dst_ports = int(self.base_unique_ports)

    def tick(self, active_attack: Optional[AttackScenario], router_load_factor: float = 1.0):
        """
        Update device metrics for one tick.
        - Use small jitter around base values (±10-20%) to keep numbers realistic.
        - Apply attack effect ONLY if this device is the target.
        - router_load_factor optionally increases router's net values (set by LabState if needed).
        """
        now = time.time()
        jitter = lambda base, pct=0.12: base * random.uniform(1 - pct, 1 + pct)

        # start from base + small jitter
        net_in = jitter(self.base_net_in, 0.12)
        net_out = jitter(self.base_net_out, 0.12)
        cpu = jitter(self.base_cpu, 0.10)
        conns = max(1, int(jitter(self.base_conns, 0.18)))
        pkt_rate = jitter(self.base_pkt_rate, 0.12)
        ports = max(1, int(jitter(self.base_unique_ports, 0.15)))

        label = "benign"
        self.compromised = False
        self.current_attack = None

        # Only apply attack if active and target matches this device
        if active_attack and active_attack.target_id == self.device_id:
            label = active_attack.kind.value
            self.current_attack = active_attack.kind
            self.compromised = True

            if active_attack.kind == AttackType.DDOS:
                net_in *= random.uniform(6, 18)
                net_out *= random.uniform(4, 12)
                cpu *= random.uniform(1.5, 3.0)
                conns = int(conns * random.uniform(6, 25))
                pkt_rate *= random.uniform(8, 25)
                ports = max(1, int(ports * random.uniform(0.8, 2.0)))

            elif active_attack.kind == AttackType.PORTSCAN:
                net_in *= random.uniform(1.2, 3.2)
                net_out *= random.uniform(1.2, 3.0)
                cpu *= random.uniform(1.1, 2.2)
                conns = int(conns * random.uniform(6, 70))
                pkt_rate *= random.uniform(3, 12)
                ports = max(1, int(ports * random.uniform(10, 250)))

            elif active_attack.kind == AttackType.BOTNET:
             net_in *= random.uniform(10, 25)
             net_out *= random.uniform(10, 25)
             cpu *= random.uniform(3.0, 6.0)
             conns = int(conns * random.uniform(30, 100))
             pkt_rate *= random.uniform(20, 50)
             ports = max(1, int(ports * random.uniform(20, 150)))
                # apply optional router load multiplier (only if this device is router)
        if self.device_type == DeviceType.ROUTER:
            net_in *= router_load_factor
            net_out *= router_load_factor
            cpu *= 1.0 + (router_load_factor - 1.0) * 0.3

        # -------- FLOW SIMULATION --------
        self.active_flows.clear()

        for i in range(conns):
            flow_id = f"{self.device_id}_flow_{i}"

            packets = max(1, int(pkt_rate / max(1, conns)))
            avg_pkt_size = random.randint(200, 1200)
            bytes_total = packets * avg_pkt_size

            flow = FlowRecord(
                flow_id=flow_id,
                src_id=self.device_id,
                dst_id=self.connected_to or "router",
                start_time=now - random.uniform(0.1, 2.0),
                last_seen=now,
                total_fwd_packets=packets,
                total_bwd_packets=int(packets * random.uniform(0.5, 1.2)),
                total_fwd_bytes=bytes_total,
                total_bwd_bytes=int(bytes_total * random.uniform(0.5, 1.2)),
            )

            self.active_flows[flow_id] = flow
        # ---------------------------------

        # finalize values (rounds + safety)
        self.net_in_kbps = round(max(0.0, net_in), 2)
        self.net_out_kbps = round(max(0.0, net_out), 2)
        self.cpu_pct = round(min(100.0, max(0.0, cpu)), 2)
        self.conn_count = int(max(0, conns))
        self.pkt_rate = round(max(0.0, pkt_rate), 2)
        self.unique_dst_ports = int(max(0, ports))
        self.last_updated = now
        self.current_label = label
    def to_status(self) -> DeviceStatus:
        return DeviceStatus(
            id=self.device_id,
            name=self.name,
            device_type=self.device_type,
            ip_address=self.ip_address,
            online=self.online,
            compromised=self.compromised,
            cpu_pct=self.cpu_pct,
            net_in_kbps=self.net_in_kbps,
            net_out_kbps=self.net_out_kbps,
            conn_count=self.conn_count,
            pkt_rate=self.pkt_rate,
            unique_dst_ports=self.unique_dst_ports,
            last_updated=self.last_updated,
            current_attack=self.current_attack,
            current_label=self.current_label,
            connected_to=self.connected_to,
        )


class LabState:
      def __init__(self):
       self.devices: Dict[str, VirtualDevice] = {}
       self.security_events: deque[SecurityEvent] = deque(maxlen=1000)
       self._event_id_counter = 0

       self._active_attack: Optional[AttackScenario] = None
       self._attack_lock = asyncio.Lock()

       self._histories: Dict[str, deque[DeviceStatus]] = defaultdict(
        lambda: deque(maxlen=600)
    )

    # -------- Isolation Forest --------
       self._iso_model = None
       self._load_iso_model()

    # -------- CICIDS RandomForest --------
       self._cicids_model = None
       self._cicids_scaler = None
       self._load_cicids_model()

       self._init_default_devices()
    # -------- devices --------

    # In LabState._init_default_devices replace with:
      def _init_default_devices(self):
      # create router first (core)
         router = self.create_device("Home Router", DeviceType.ROUTER, ip_octet=1)
         router_id = router.device_id

      # create other devices and set their connected_to = router_id
         dev1 = self.create_device("CCTV Front Door", DeviceType.CAMERA, ip_octet=10)
         dev1.connected_to = router_id

         dev2 = self.create_device("Smart Bulb Hall", DeviceType.BULB, ip_octet=11)
         dev2.connected_to = router_id

         dev3 = self.create_device("Smart Thermostat", DeviceType.THERMOSTAT, ip_octet=12)
         dev3.connected_to = router_id

         dev4 = self.create_device("Work Laptop", DeviceType.LAPTOP, ip_octet=20)
         dev4.connected_to = router_id

      # Ensure router remains aware (optional)
         self.devices[router_id].connected_to = None

      def create_device(self, name: str, d_type: DeviceType, ip_octet: int = 50):
        device_id = f"dev-{len(self.devices)+1}"
        dev = VirtualDevice(device_id, name, d_type, ip_octet)
        self.devices[device_id] = dev
        return dev

      def list_devices(self) -> List[DeviceStatus]:
        return [d.to_status() for d in self.devices.values()]

      def toggle_device(self, device_id: str, online: bool):
        d = self.devices.get(device_id)
        if not d:
            raise KeyError(device_id)
        d.online = online

    # -------- attacks --------

      async def start_attack(
        self, attack_type: AttackType, target_device_id: str, duration_seconds: int
    ):
        if target_device_id not in self.devices:
            raise KeyError(target_device_id)
        async with self._attack_lock:
            now = time.time()
            self._active_attack = AttackScenario(
                kind=attack_type,
                target_id=target_device_id,
                ends_at=now + duration_seconds,
            )
            self._push_event(
                device_id=target_device_id,
                severity="medium",
                event_type=f"attack_started:{attack_type.value}",
                message=f"Manual {attack_type.value} attack started for {duration_seconds}s",
            )

      async def stop_attack(self):
        async with self._attack_lock:
            if self._active_attack:
                self._push_event(
                    device_id=self._active_attack.target_id,
                    severity="low",
                    event_type="attack_stopped",
                    message="Attack stopped by user",
                )
            self._active_attack = None

      def current_attack_status(self) -> AttackStatus:
        if not self._active_attack:
            return AttackStatus(active=False, attack_type=None, target_device_id=None, seconds_remaining=0)
        remaining = max(0, int(self._active_attack.ends_at - time.time()))
        if remaining <= 0:
            return AttackStatus(active=False, attack_type=None, target_device_id=None, seconds_remaining=0)
        return AttackStatus(
            active=True,
            attack_type=self._active_attack.kind,
            target_device_id=self._active_attack.target_id,
            seconds_remaining=remaining,
        )

    # -------- simulation loop --------

      async def simulation_loop(self):
        while True:
            await asyncio.sleep(SIM_TICK_SECONDS)
            await self._tick_once()

      async def _tick_once(self):
        now = time.time()
        async with self._attack_lock:
            atk = self._active_attack
            if atk and now >= atk.ends_at:
                self._active_attack = None
                self._push_event(
                    device_id=atk.target_id,
                    severity="low",
                    event_type="attack_auto_end",
                    message="Attack duration finished",
                )
                atk = None

        for dev in self.devices.values():
            if not dev.online:
                continue
            dev.tick(self._active_attack)
            status = dev.to_status()
            if self._active_attack and dev.device_id == self._active_attack.target_id:
             print("TICK LABEL:", status.current_label)
            self._histories[dev.device_id].append(status)

    # -------- feature extraction + ML scoring --------

      def _history_window(self, device_id: str):
        return list(self._histories.get(device_id, []))

      def compute_feature_for_device(self, device_id: str) -> Optional[FeatureWindow]:
        hist = self._history_window(device_id)
        if not hist:
          return None

        now = time.time()
        cutoff = now - FEATURE_WINDOW_SEC
        recent = [h for h in hist if h.last_updated >= cutoff]

        if len(recent) < 4:
            return None

        # -------- EXISTING METRICS --------
        net_in = np.array([h.net_in_kbps for h in recent])
        net_out = np.array([h.net_out_kbps for h in recent])
        cpu = np.array([h.cpu_pct for h in recent])
        conns = np.array([h.conn_count for h in recent])
        pkt = np.array([h.pkt_rate for h in recent])
        ports = np.array([h.unique_dst_ports for h in recent])
        labels = [h.current_label for h in recent]

        attack_labels = [l for l in labels if l != "benign"]

        if attack_labels:
            lab = attack_labels[-1]
        else:
            lab = "benign"

        # -------- FLOW FEATURES --------
        dev = self.devices[device_id]
        flows = list(dev.active_flows.values())

        if flows:
            flow_count = len(flows)

            total_packets = sum(
                f.total_fwd_packets + f.total_bwd_packets for f in flows
            )

            total_bytes = sum(
                f.total_fwd_bytes + f.total_bwd_bytes for f in flows
            )

            avg_packet_size = total_bytes / max(1, total_packets)

            durations = [f.last_seen - f.start_time for f in flows]
            flow_duration_mean = sum(durations) / max(1, len(durations))

            packets_per_second = total_packets / max(1, flow_duration_mean)
            bytes_per_second = total_bytes / max(1, flow_duration_mean)

        else:
            flow_count = 0
            avg_packet_size = 0
            flow_duration_mean = 0
            packets_per_second = 0
            bytes_per_second = 0

        # -------- RETURN FEATURE WINDOW --------
        return FeatureWindow(
            device_id=device_id,
            timestamp=datetime.utcnow(),
            avg_net_in=float(net_in.mean()),
            avg_net_out=float(net_out.mean()),
            max_cpu=float(cpu.max()),
            avg_cpu=float(cpu.mean()),
            avg_conn_count=float(conns.mean()),
            avg_pkt_rate=float(pkt.mean()),
            avg_unique_ports=float(ports.mean()),
            label=lab,
        )

      def _append_feature_to_csv(self, fw: FeatureWindow):
        path = FEATURE_CSV_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        file_exists = path.is_file()
        with path.open("a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(
                    [
                        "device_id",
                        "timestamp",
                        "avg_net_in",
                        "avg_net_out",
                        "max_cpu",
                        "avg_cpu",
                        "avg_conn_count",
                        "avg_pkt_rate",
                        "avg_unique_ports",
                        "label",
                    ]
                )
            writer.writerow(
                [
                    fw.device_id,
                    fw.timestamp.isoformat(),
                    fw.avg_net_in,
                    fw.avg_net_out,
                    fw.max_cpu,
                    fw.avg_cpu,
                    fw.avg_conn_count,
                    fw.avg_pkt_rate,
                    fw.avg_unique_ports,
                    fw.label,
                ]
            )

      def _load_iso_model(self):
        if ISOFOREST_MODEL_PATH.is_file():
            try:
                self._iso_model = load(ISOFOREST_MODEL_PATH)
            except Exception:
                self._iso_model = None


      def _load_cicids_model(self):
        try:
            self._cicids_model = load("models/rf_cicids2017_multiclass_oversampled.joblib")
            self._cicids_scaler = load("models/scaler_cicids2017_oversampled.joblib")
            print("CICIDS RandomForest model loaded")
        except Exception as e:
            print("Failed to load CICIDS model:", e)


      def _rule_score(self, fw: FeatureWindow):
        score = 0.0
        reason = "normal"

        if fw.avg_pkt_rate > RULE_PKT_RATE_TH or fw.avg_conn_count > RULE_CONN_COUNT_TH:
            score += 0.7
            reason = "possible_ddos"

        if fw.avg_unique_ports > RULE_UNIQUE_PORTS_TH:
            score += 0.6
            reason = "possible_portscan"

        if fw.max_cpu > 90 and fw.avg_net_out > 300:
            score += 0.3
            if reason == "normal":
                reason = "suspicious_load"

        return min(score, 1.0), reason


      def _anom_score(self, fw: FeatureWindow):
        if self._iso_model is None:
            return 0.0

        vec = np.array(
            [
                fw.avg_net_in,
                fw.avg_net_out,
                fw.max_cpu,
                fw.avg_cpu,
                fw.avg_conn_count,
                fw.avg_pkt_rate,
                fw.avg_unique_ports,
            ],
            dtype=float,
        ).reshape(1, -1)

        raw = -self._iso_model.decision_function(vec)[0]
        val = max(0.0, min(1.0, raw + 0.5))
        return float(val)


      def _predict_cicids(self, fw: FeatureWindow):

        if self._cicids_model is None:
            return "BENIGN", 0.0

        vec = np.array([
            fw.avg_net_in,
            fw.avg_net_out,
            fw.max_cpu,
            fw.avg_cpu,
            fw.avg_conn_count,
            fw.avg_pkt_rate,
            fw.avg_unique_ports,
        ]).reshape(1, -1)

        vec = self._cicids_scaler.transform(vec)

        pred = self._cicids_model.predict(vec)[0]
        prob = max(self._cicids_model.predict_proba(vec)[0])

        return pred, float(prob)


      def ensemble_decision(self, fw: FeatureWindow):
        rule_s, rule_reason = self._rule_score(fw)
        anom_s = self._anom_score(fw)

        combined = 0.65 * rule_s + 0.35 * anom_s

        severity = "low"
        if combined > 0.85:
            severity = "high"
        elif combined > 0.55:
            severity = "medium"

        alert_type = "none"
        if combined > 0.45:
            alert_type = "hybrid_ids"

        return {
            "combined_score": combined,
            "severity": severity,
            "alert_type": alert_type,
            "rule_score": rule_s,
            "rule_reason": rule_reason,
            "anom_score": anom_s,
        }
      def _push_event(
         self,
         device_id: str,
         severity: str,
         event_type: str,
         message: str,
         scores: dict = None,
         label_hint: str = None,
        ):
        self._event_id_counter += 1

        event = SecurityEvent(
        event_id=self._event_id_counter,
        timestamp=datetime.utcnow(),
        device_id=device_id,
        severity=severity,
        event_type=event_type,
        message=message,
        scores=scores or {},
        label_hint=label_hint,
    )

        self.security_events.append(event)
      async def feature_and_detection_loop(self):
       while True:
        await asyncio.sleep(FEATURE_STEP_SEC)

        for dev_id, dev in self.devices.items():
            if not dev.online:
                continue

            fw = self.compute_feature_for_device(dev_id)

            if not fw:
                continue

            self._append_feature_to_csv(fw)

            decision = self.ensemble_decision(fw)

            if decision["alert_type"] != "none" and decision["combined_score"] > 0.5:
                self._push_event(
                    device_id=dev_id,
                    severity=decision["severity"],
                    event_type=decision["alert_type"],
                    message=f"Hybrid IDS detected anomaly ({decision['rule_reason']})",
                    scores={
                        "combined": decision["combined_score"],
                        "rule": decision["rule_score"],
                        "anom": decision["anom_score"],
                    },
                    label_hint=decision["rule_reason"],
                )
      
# global lab_state instance
lab_state = LabState()