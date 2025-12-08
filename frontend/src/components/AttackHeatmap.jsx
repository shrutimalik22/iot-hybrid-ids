// frontend/src/components/AttackHeatmap.jsx
import React, { useMemo } from "react";

/**
 * Generic heatmap:
 * - events: array from backend (/events)
 * - devices: current devices list
 *
 * We don't rely on specific field names.
 * We scan ALL string fields for:
 *   - device name / ip
 *   - attack keywords: ddos / flood / portscan / botnet / c2
 */
export default function AttackHeatmap({ events, devices }) {
  const rows = useMemo(() => {
    const byDevice = new Map();

    // helper: find device key + name from event
    const findDeviceForEvent = (ev, textLower) => {
      // try explicit fields first
      const id = ev.device_id || ev.device || ev.deviceId;
      const name = ev.device_name || ev.device_name || ev.device;
      const ip =
        ev.ip_address || ev.ip || ev.source_ip || ev.src_ip || ev.dst_ip;

      // if device_id present and matches devices list
      if (id && devices) {
        const matchById = devices.find((d) => d.id === id);
        if (matchById) {
          return { key: matchById.id, label: matchById.name };
        }
      }

      // if ip present, match devices by ip_address
      if (ip && devices) {
        const matchByIp = devices.find((d) => d.ip_address === ip);
        if (matchByIp) {
          return { key: matchByIp.id, label: matchByIp.name };
        }
      }

      // else try match by name inside text
      if (devices && devices.length) {
        for (const d of devices) {
          if (
            textLower.includes((d.name || "").toLowerCase()) ||
            textLower.includes((d.ip_address || "").toLowerCase())
          ) {
            return { key: d.id, label: d.name };
          }
        }
      }

      // fallback
      if (name) return { key: name, label: name };
      if (ip) return { key: ip, label: ip };

      return { key: "unknown", label: "Unknown device" };
    };

    // go through all events
    (events || []).forEach((ev) => {
      // combine all string fields into one text blob
      const combinedText = Object.values(ev || {})
        .filter((v) => typeof v === "string")
        .join(" ")
        .toLowerCase();

      if (!combinedText) return;

      // detect attack type from text
      let kind = null;
      if (combinedText.includes("ddos") || combinedText.includes("flood")) {
        kind = "ddos";
      } else if (
        combinedText.includes("portscan") ||
        combinedText.includes("port scan") ||
        combinedText.includes("port-scan")
      ) {
        kind = "portscan";
      } else if (
        combinedText.includes("botnet") ||
        combinedText.includes("c2")
      ) {
        kind = "botnet";
      }

      // if no attack keyword, skip (maybe just info event)
      if (!kind) return;

      // map to device
      const dev = findDeviceForEvent(ev, combinedText);
      if (!byDevice.has(dev.key)) {
        byDevice.set(dev.key, {
          id: dev.key,
          name: dev.label,
          ddos: 0,
          portscan: 0,
          botnet: 0,
          total: 0,
        });
      }
      const row = byDevice.get(dev.key);

      if (kind === "ddos") row.ddos += 1;
      if (kind === "portscan") row.portscan += 1;
      if (kind === "botnet") row.botnet += 1;
      row.total += 1;
    });

    // ensure all devices appear, even if 0
    (devices || []).forEach((d) => {
      const key = d.id || d.ip_address || d.name;
      if (!byDevice.has(key)) {
        byDevice.set(key, {
          id: key,
          name: d.name,
          ddos: 0,
          portscan: 0,
          botnet: 0,
          total: 0,
        });
      }
    });

    return Array.from(byDevice.values()).sort((a, b) => b.total - a.total);
  }, [events, devices]);

  const cellStyle = (count, color) => {
    if (count === 0) {
      return "bg-slate-900/70 text-slate-500";
    }
    if (count === 1) {
      return `${color}-500/25 text-${color}-200`;
    }
    if (count <= 3) {
      return `${color}-500/50 text-${color}-100`;
    }
    return `${color}-500/80 text-slate-50`;
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3 text-xs">
      <div className="mb-2 flex items-center justify-between">
        <div>
          <h3 className="text-[13px] font-semibold text-slate-100">
            Attack Heatmap
          </h3>
          <p className="text-[10px] text-slate-500">
            Per device · counted from current event list
          </p>
        </div>
        <span className="rounded-full bg-fuchsia-500/20 px-2 py-[1px] text-[10px] font-medium text-fuchsia-200">
          Rule + ML alerts
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full border-collapse text-[10px]">
          <thead>
            <tr className="text-slate-400">
              <th className="border-b border-slate-800 px-2 py-1 text-left">
                Device
              </th>
              <th className="border-b border-slate-800 px-2 py-1 text-center">
                DDoS
              </th>
              <th className="border-b border-slate-800 px-2 py-1 text-center">
                Port Scan
              </th>
              <th className="border-b border-slate-800 px-2 py-1 text-center">
                Botnet
              </th>
              <th className="border-b border-slate-800 px-2 py-1 text-center">
                Total
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="text-slate-100">
                <td className="border-b border-slate-900 px-2 py-1">
                  {r.name}
                </td>
                <td
                  className={
                    "border-b border-slate-900 px-2 py-1 text-center " +
                    cellStyle(r.ddos, "bg-red")
                  }
                >
                  {r.ddos}
                </td>
                <td
                  className=
                    {"border-b border-slate-900 px-2 py-1 text-center " +
                    cellStyle(r.portscan, "bg-amber")
                  }
                >
                  {r.portscan}
                </td>
                <td
                  className={
                    "border-b border-slate-900 px-2 py-1 text-center " +
                    cellStyle(r.botnet, "bg-purple")
                  }
                >
                  {r.botnet}
                </td>
                <td className="border-b border-slate-900 px-2 py-1 text-center text-slate-200">
                  {r.total}
                </td>
              </tr>
            ))}

            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-2 py-4 text-center text-[11px] text-slate-500"
                >
                  No attack-related alerts in current event list.
                  Trigger a DDoS / Port Scan / Botnet to populate the heatmap.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
