// frontend/src/components/TopologyView.jsx

import React from "react";

/**
 * TopologyView
 * props:
 *  - devices: array of device status objects from backend
 *    {
 *      id, name, device_type, ip_address,
 *      conn_count, pkt_rate, connected_to, compromised, online
 *    }
 */
export default function TopologyView({ devices }) {
  if (!devices || devices.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs text-slate-400">
        <div className="mb-1 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-slate-100">
            Network Topology
          </h3>
          <span className="text-[10px] text-slate-500">logical view</span>
        </div>
        <div className="text-[11px] text-slate-500">No devices available.</div>
      </div>
    );
  }

  // 1) Choose router as central node
  const router =
    devices.find((d) => d.device_type === "router") || devices[0];

  // 2) Children = devices whose connected_to == router.id
  const children = devices.filter((d) => d.connected_to === router.id);

  // 3) Fallback: if nothing explicitly connected, show all non-router devices
  const leafDevices =
    children.length > 0
      ? children
      : devices.filter((d) => d.id !== router.id);

  const statusBadge = (d) => {
    if (!d.online) {
      return (
        <span className="rounded-full bg-slate-700 px-2 py-[1px] text-[9px] font-medium text-slate-200">
          offline
        </span>
      );
    }
    if (d.compromised) {
      return (
        <span className="rounded-full bg-red-500/20 px-2 py-[1px] text-[9px] font-semibold text-red-300">
          compromised
        </span>
      );
    }
    return (
      <span className="rounded-full bg-emerald-500/15 px-2 py-[1px] text-[9px] font-medium text-emerald-300">
        online
      </span>
    );
  };

  const typeLabel = (t) => {
    switch (t) {
      case "router":
        return "core router";
      case "camera":
        return "camera";
      case "bulb":
        return "bulb";
      case "thermostat":
        return "thermostat";
      case "laptop":
        return "laptop";
      default:
        return t;
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs">
      {/* header */}
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold text-slate-100">
          Network Topology
        </h3>
        <span className="text-[10px] text-slate-500">logical view</span>
      </div>

      {/* router node */}
      <div className="flex flex-col items-center gap-3">
        <div className="rounded-2xl border border-sky-500/70 bg-sky-500/10 px-4 py-2 text-center text-[11px] shadow-sm shadow-sky-500/30">
          <div className="font-semibold text-slate-50">{router.name}</div>
          <div className="text-[10px] text-slate-200">{router.ip_address}</div>
          <div className="mt-1 flex items-center justify-center gap-2 text-[9px] text-slate-300">
            <span>{typeLabel(router.device_type)}</span>
            {statusBadge(router)}
          </div>
        </div>

        {/* link line */}
        <div className="h-6 w-px bg-slate-700/80" />

        {/* child devices row */}
        <div className="flex flex-wrap items-start justify-center gap-3">
          {leafDevices.map((d) => (
            <div
              key={d.id}
              className={`flex min-w-[120px] max-w-[160px] flex-col items-center rounded-xl border px-3 py-2 text-[10px] transition
              ${
                d.compromised
                  ? "border-red-500/70 bg-red-500/10 shadow-sm shadow-red-500/40"
                  : "border-slate-700 bg-slate-900/70"
              }`}
            >
              <div className="flex w-full items-center justify-between gap-1">
                <span className="font-semibold text-slate-100 truncate">
                  {d.name}
                </span>
                {statusBadge(d)}
              </div>
              <div className="mt-1 flex w-full items-center justify-between text-[9px] text-slate-400">
                <span>{typeLabel(d.device_type)}</span>
                <span>{d.ip_address}</span>
              </div>
              <div className="mt-1 w-full text-[9px] text-slate-400">
                Conns:{" "}
                <span className="font-semibold text-slate-200">
                  {d.conn_count}
                </span>{" "}
                · Pkts/s:{" "}
                <span className="font-semibold text-slate-200">
                  {Math.round(d.pkt_rate || 0)}
                </span>
              </div>
              <div className="mt-1 w-full text-[9px] text-slate-500">
                via: <span className="font-mono">{router.ip_address}</span>
              </div>
            </div>
          ))}

          {leafDevices.length === 0 && (
            <div className="text-[10px] text-slate-500">
              No downstream devices mapped to this router yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
