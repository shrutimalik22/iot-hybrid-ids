// frontend/src/api.js
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000";

export async function fetchDevices() {
  const res = await axios.get(`${API_BASE}/devices`);
  return res.data;
}

export async function fetchEvents(limit = 100) {
  const res = await axios.get(`${API_BASE}/events`, {
    params: { limit }
  });
  return res.data;
}

export async function fetchAttackStatus() {
  const res = await axios.get(`${API_BASE}/attack/status`);
  return res.data;
}

export async function startAttack(attack_type, target_device_id, duration_seconds) {
  const res = await axios.post(`${API_BASE}/attack/start`, {
    attack_type,
    target_device_id,
    duration_seconds
  });
  return res.data;
}

export async function stopAttack() {
  const res = await axios.post(`${API_BASE}/attack/stop`);
  return res.data;
}
