import { useEffect, useState } from "react";
import { 
  Shield, Activity, Radar, Network, AlertTriangle, Clock, Cpu, Wifi, 
  TrendingUp, BarChart3, MapPin, Server, Lock, Zap, Circle
} from "lucide-react";

import AttackPanel from "./components/AttackPanel.jsx";
import AttackHeatmap from "./components/AttackHeatmap.jsx";
import DeviceGrid from "./components/DeviceGrid.jsx";
import EventLog from "./components/EventLog.jsx";
import TopologyView from "./components/TopologyView.jsx";
import TrafficPanel from "./components/TrafficPanel.jsx";

function SectionCard({ title, icon: Icon, children, className = "" }) {
  return (
    <div
      className={
        "flex flex-col rounded-2xl border bg-gradient-to-br from-slate-800/60 via-blue-900/40 to-slate-900/70 backdrop-blur-2xl shadow-2xl p-6 gap-4 hover:border-blue-500/50 hover:shadow-blue-500/20 transition-all duration-300 border-slate-700/50 " +
        className
      }
    >
      <div className="flex items-center gap-3 border-b border-slate-700/40 pb-4">
        {Icon && (
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-blue-500 via-cyan-500 to-teal-500 flex items-center justify-center flex-shrink-0 shadow-xl shadow-blue-500/40">
            <Icon size={20} className="text-white" />
          </div>
        )}
        <h2 className="text-xs font-bold uppercase tracking-widest text-slate-100">
          {title}
        </h2>
      </div>
      <div className="flex-1 min-h-0">{children}</div>
    </div>
  );
}

function StatCard({ label, value, icon: IconComp, status = "normal" }) {
  const statusConfig = {
    normal: { bg: "from-emerald-900/40 to-teal-900/30", text: "text-emerald-300", icon: "text-emerald-400 shadow-emerald-500/30" },
    warning: { bg: "from-amber-900/40 to-orange-900/30", text: "text-amber-300", icon: "text-amber-400 shadow-amber-500/30" },
    critical: { bg: "from-red-900/40 to-rose-900/30", text: "text-red-300", icon: "text-red-400 shadow-red-500/30" },
  };

  const config = statusConfig[status];

  return (
    <div className={`rounded-lg border border-slate-700/40 bg-gradient-to-br ${config.bg} backdrop-blur-lg px-5 py-4 flex flex-col gap-2 shadow-lg hover:border-blue-500/60 transition-all`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-300">
          {label}
        </span>
        {IconComp && (
          <IconComp size={16} className={`${config.icon} shadow-lg`} />
        )}
      </div>
      <span className={`text-3xl font-black ${config.text}`}>
        {value}
      </span>
    </div>
  );
}

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [historyByDevice, setHistoryByDevice] = useState({});

  useEffect(() => {
    const timer = setInterval(async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/devices");
        const json = await res.json();
        const list = json || [];
        setDevices(list);

        const now = Date.now();
        setHistoryByDevice((prev) => {
          const next = { ...prev };
          list.forEach((d) => {
            const sample = {
              t: now,
              cpu: d.cpu_pct,
              netIn: d.net_in_kbps,
              netOut: d.net_out_kbps,
              conns: d.conn_count,
            };
            const arr = next[d.id] ? [...next[d.id], sample] : [sample];
            next[d.id] = arr.slice(-60);
          });
          return next;
        });
      } catch (e) {
        console.log("device poll error:", e);
      }
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = setInterval(async () => {
      try {
        const r = await fetch("http://127.0.0.1:8000/events");
        const json = await r.json();
        setEvents(json || []);
      } catch (e) {
        console.log("event poll error:", e);
      }
    }, 1500);

    return () => clearInterval(timer);
  }, []);

  const totalDevices = devices?.length || 0;
  const totalEvents = events?.length || 0;
  const criticalEvents = events?.filter(e => e.severity === 'critical').length || 0;
  const avgCPU = devices.length > 0 ? Math.round(devices.reduce((a, d) => a + (d.cpu_pct || 0), 0) / devices.length) : 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 text-slate-50">
      
      {/* HEADER */}
      <div className="w-full border-b border-slate-700/30 bg-gradient-to-b from-slate-900/95 via-blue-900/40 to-slate-900/80 backdrop-blur-2xl sticky top-0 z-40">
        <div className="px-8 py-6">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-4">
              <div className="h-14 w-14 rounded-xl bg-gradient-to-br from-blue-500 via-cyan-500 to-teal-500 flex items-center justify-center shadow-2xl shadow-blue-500/50">
                <Shield className="text-white" size={28} />
              </div>
              <div>
                <h1 className="text-3xl font-black tracking-tight text-white">
                  Hybrid AI-Based IDS for Botnet Detection
                </h1>
                <p className="mt-1 text-sm text-blue-300 font-medium">
                Security BotGuard
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 min-w-fit">
              <StatCard label="Devices" value={totalDevices} icon={Server} status={totalDevices > 0 ? "normal" : "warning"} />
              <StatCard label="Events" value={totalEvents} icon={Activity} status={totalEvents > 5 ? "warning" : "normal"} />
              <StatCard label="Critical" value={criticalEvents} icon={AlertTriangle} status={criticalEvents > 0 ? "critical" : "normal"} />
              <StatCard label="CPU Avg" value={avgCPU + "%"} icon={Zap} status={avgCPU > 70 ? "critical" : avgCPU > 50 ? "warning" : "normal"} />
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="px-8 py-8 space-y-6">
        
        {/* ROW 1: Devices & Attack - Dynamic Grid */}
        <div className="grid grid-cols-1 gap-6 auto-rows-max" style={{
          gridTemplateColumns: devices.length > 0 ? `1fr 1fr` : `1fr`,
        }}>
          <div>
            <SectionCard title="Device Inventory" icon={Network}>
              <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 overflow-hidden h-full">
                <DeviceGrid devices={devices} />
              </div>
            </SectionCard>
          </div>

          {devices.length > 0 && (
            <div>
              <SectionCard title="Threat Simulator" icon={Radar}>
                <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 overflow-hidden h-full">
                  <AttackPanel devices={devices} />
                </div>
              </SectionCard>
            </div>
          )}
        </div>

        {/* ROW 2: Topology */}
        <SectionCard title="Network Architecture" icon={MapPin}>
          <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 overflow-hidden h-80">
            <TopologyView devices={devices} />
          </div>
        </SectionCard>

        {/* ROW 3: Attack Heatmap */}
        <SectionCard title="Threat Distribution" icon={TrendingUp}>
          <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 overflow-hidden h-64">
            <AttackHeatmap events={events} devices={devices} />
          </div>
        </SectionCard>

        {/* ROW 4: Events & Performance - Equal Height & Width */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-8 auto-rows-fr">
          <SectionCard title="Incident Log" icon={Clock}>
            <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 h-96 overflow-hidden flex flex-col">
              <div className="flex-1 overflow-y-auto pr-2">
                <EventLog events={events} />
              </div>
            </div>
          </SectionCard>

          <SectionCard title="System Performance" icon={BarChart3}>
            <div className="rounded-lg border border-slate-700/30 bg-slate-950/40 h-96 overflow-y-auto pr-2">
              <TrafficPanel devices={devices} historyByDevice={historyByDevice} />
            </div>
          </SectionCard>
        </div>

      </div>
    </div>
  );
}