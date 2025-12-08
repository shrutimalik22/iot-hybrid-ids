// frontend/src/components/AttackPanel.jsx
import React, { useState } from "react";
import { startAttack, stopAttack } from "../api";

const attackOptions = [
  { value: "ddos", label: "DDoS (flood traffic)" },
  { value: "portscan", label: "Port Scan" },
  { value: "botnet", label: "Botnet C2 Traffic" }
];

export default function AttackPanel({ devices, attackStatus, onStatusChange }) {
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [selectedAttack, setSelectedAttack] = useState("ddos");
  const [duration, setDuration] = useState(30);
  const [busy, setBusy] = useState(false);

  const handleStart = async () => {
    if (!selectedDeviceId) return;
    setBusy(true);
    try {
      const st = await startAttack(selectedAttack, selectedDeviceId, Number(duration));
      onStatusChange?.(st);
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    setBusy(true);
    try {
      const st = await stopAttack();
      onStatusChange?.(st);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold text-slate-100">Attack Simulator</h3>
        {attackStatus?.active ? (
          <span className="text-[10px] text-red-300">
            Active: {attackStatus.attack_type} ({attackStatus.seconds_remaining}s)
          </span>
        ) : (
          <span className="text-[10px] text-emerald-300">No active attack</span>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-slate-400">Target Device</label>
          <select
            className="rounded-lg border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px]"
            value={selectedDeviceId}
            onChange={(e) => setSelectedDeviceId(e.target.value)}
          >
            <option value="">Select device</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} ({d.ip_address})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-slate-400">Attack Type</label>
          <select
            className="rounded-lg border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px]"
            value={selectedAttack}
            onChange={(e) => setSelectedAttack(e.target.value)}
          >
            {attackOptions.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-slate-400">Duration (seconds)</label>
          <input
            type="number"
            min={5}
            max={300}
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            className="w-24 rounded-lg border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px]"
          />
        </div>

        <div className="mt-2 flex items-center gap-2">
          <button
            onClick={handleStart}
            disabled={busy || !selectedDeviceId}
            className="rounded-lg bg-sky-500 px-3 py-1 text-[11px] font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700"
          >
            Start Attack
          </button>
          <button
            onClick={handleStop}
            disabled={busy}
            className="rounded-lg border border-slate-600 px-3 py-1 text-[11px] text-slate-200"
          >
            Stop
          </button>
        </div>
      </div>
    </div>
  );
}
