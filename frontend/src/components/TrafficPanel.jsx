import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function TrafficPanel({ devices, historyByDevice }) {
  return (
    <div className="bg-[#111827] rounded-xl p-4 shadow-lg border border-[#1f2937]">
      <h2 className="text-xl mb-3 font-bold neon-yellow">Traffic & CPU Monitor</h2>

      {devices.map((d) => {
        const hist = historyByDevice[d.id] || [];

        const chartData = hist.map((s) => ({
          time: new Date(s.t).toLocaleTimeString().split(" ")[0],
          CPU: s.cpu,
          In: s.netIn,
          Out: s.netOut,
          Conns: s.conns,
        }));

        return (
          <div key={d.id} className="mb-8">
            <h3 className="font-semibold mb-2">{d.name} ({d.ip})</h3>

            <div className="grid grid-cols-2 gap-4">
              
              {/* CPU Chart */}
              <div className="bg-[#151b2c] p-3 rounded-lg">
                <p className="text-sm mb-1">CPU %</p>
                <ResponsiveContainer width="100%" height={120}>
                  <LineChart data={chartData}>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip />
                    <Line type="monotone" dataKey="CPU" stroke="#00eaff" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Network Chart */}
              <div className="bg-[#151b2c] p-3 rounded-lg">
                <p className="text-sm mb-1">Network In/Out kbps</p>
                <ResponsiveContainer width="100%" height={120}>
                  <LineChart data={chartData}>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip />
                    <Line type="monotone" dataKey="In" stroke="#3bff53" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="Out" stroke="#ff4d4d" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
