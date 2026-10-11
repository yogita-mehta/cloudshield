import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { Activity, Cpu, Wifi, AlertTriangle } from 'lucide-react';

export default function TelemetryCharts({ history = [] }) {
  if (!history || history.length === 0) {
    return (
      <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-8 text-center text-xs text-slate-400">
        Collecting telemetry metrics from Prometheus...
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Chart 1: Requests Per Second (RPS) */}
      <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-white">Ingress Requests / sec (RPS)</h3>
          </div>
          <span className="text-xs font-mono text-sky-400 font-bold">
            {history[history.length - 1]?.requests_per_sec || 0} req/s
          </span>
        </div>
        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="rpsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                itemStyle={{ color: '#38bdf8' }}
              />
              <Area type="monotone" dataKey="requests_per_sec" stroke="#0ea5e9" strokeWidth={2} fillOpacity={1} fill="url(#rpsGradient)" name="Requests/sec" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: CPU Utilization & Active Connections */}
      <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-white">System CPU Utilization & Connections</h3>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="text-amber-400">CPU: {history[history.length - 1]?.cpu_utilization || 0}%</span>
            <span className="text-emerald-400">Conn: {history[history.length - 1]?.active_connections || 0}</span>
          </div>
        </div>
        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
              />
              <Line type="monotone" dataKey="cpu_utilization" stroke="#f59e0b" strokeWidth={2} dot={false} name="CPU %" />
              <Line type="monotone" dataKey="active_connections" stroke="#10b981" strokeWidth={2} dot={false} name="Connections" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 3: Latency (ms) */}
      <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Wifi className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Average Latency (ms)</h3>
          </div>
          <span className="text-xs font-mono text-emerald-400 font-bold">
            {history[history.length - 1]?.latency_ms || 0} ms
          </span>
        </div>
        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="latencyGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
              />
              <Area type="monotone" dataKey="latency_ms" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#latencyGradient)" name="Latency (ms)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 4: Error Rate (%) & Bandwidth */}
      <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-semibold text-white">5xx Error Rate & Bandwidth</h3>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="text-rose-400">5xx: {history[history.length - 1]?.error_rate_5xx || 0}%</span>
            <span className="text-purple-400">BW: {history[history.length - 1]?.bandwidth_kbps || 0} kbps</span>
          </div>
        </div>
        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
              />
              <Line type="monotone" dataKey="error_rate_5xx" stroke="#f43f5e" strokeWidth={2} dot={false} name="5xx %" />
              <Line type="monotone" dataKey="bandwidth_kbps" stroke="#a855f7" strokeWidth={2} dot={false} name="Bandwidth (kbps)" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
