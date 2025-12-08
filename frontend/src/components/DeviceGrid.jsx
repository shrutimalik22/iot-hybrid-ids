// frontend/src/components/DeviceGrid.jsx
import React from "react";

const severityColor = (status) => {
  if (status.compromised) return "border-red-500/70 bg-red-500/5";
  if (!status.online) return "border-slate-700 bg-slate-900/60";
  return "border-emerald-500/60 bg-emerald-500/5";
};

export default function DeviceGrid({ devices, onSelect, selectedId }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {devices.map((d) => (
        <button
          key={d.id}
          onClick={() => onSelect?.(d)}
          className={`flex flex-col items-start rounded-xl border px-3 py-2 text-left text-xs transition hover:border-sky-400/80 hover:bg-sky-500/5 ${
            severityColor(d)
          } ${selectedId === d.id ? "ring-1 ring-sky-400" : ""}`}
        >
          <div className="flex w-full items-center justify-between">
            <span className="font-semibold text-[13px]">{d.name}</span>
            <span className="rounded-full bg-slate-800 px-2 py-[1px] text-[10px] uppercase tracking-wide text-slate-300">
              {d.device_type}
            </span>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-300">
            <span>IP: {d.ip_address}</span>
            <span>CPU: {d.cpu_pct}%</span>
            <span>
              Net: {d.net_in_kbps.toFixed(0)}/{d.net_out_kbps.toFixed(0)} kbps
            </span>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-400">
            <span>Conns: {d.conn_count}</span>
            <span>Pkts/s: {d.pkt_rate.toFixed(0)}</span>
            <span>Ports: {d.unique_dst_ports}</span>
          </div>
          <div className="mt-1 text-[10px]">
            {d.compromised ? (
              <span className="rounded px-1.5 py-[1px] text-[10px] font-semibold text-red-400">
                COMPROMISED ({d.current_label})
              </span>
            ) : d.online ? (
              <span className="text-emerald-400">Online</span>
            ) : (
              <span className="text-slate-500">Offline</span>
            )}
          </div>
        </button>
      ))}
    </div>
  );
}
