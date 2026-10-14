import React from 'react';
import StatusBadge from './StatusBadge';
import { AlertTriangle, CheckCircle, Info } from 'lucide-react';

export default function IncidentTable({ incidents, onSelectIncident }) {
  const sortedIncidents = [...(incidents || [])].sort((a, b) => {
    if (b.id && a.id) return b.id - a.id;
    return new Date(b.timestamp) - new Date(a.timestamp);
  });

  const formatTimestamp = (ts) => {
    if (!ts) return new Date().toLocaleTimeString();
    try {
      const raw = typeof ts === 'string' && !ts.endsWith('Z') ? ts + 'Z' : ts;
      const d = new Date(raw);
      if (isNaN(d.getTime())) return String(ts);
      const local = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const utc = d.toISOString().substr(11, 8);
      return `${local} (${utc} UTC)`;
    } catch (e) {
      return String(ts);
    }
  };

  if (!sortedIncidents || sortedIncidents.length === 0) {
    return (
      <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-8 text-center">
        <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3 opacity-80" />
        <h3 className="text-sm font-semibold text-slate-200">No Security Incidents Detected</h3>
        <p className="text-xs text-slate-400 mt-1">
          Traffic metrics are within safe operational baselines. Upstream load balancer is operating normally.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl overflow-hidden shadow-lg">
      <div className="p-4 border-b border-slate-700/60 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <h2 className="text-sm font-semibold text-white">Security Incidents & Telemetry Events</h2>
        </div>
        <span className="text-xs text-slate-400">Click any row to open the "Why Was This Flagged?" panel</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
            <tr>
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Classification</th>
              <th className="px-4 py-3 font-medium">Mitigation Tier</th>
              <th className="px-4 py-3 font-medium">Source IP</th>
              <th className="px-4 py-3 font-medium">Req / sec</th>
              <th className="px-4 py-3 font-medium">URL Entropy</th>
              <th className="px-4 py-3 font-medium">Verdict Details</th>
              <th className="px-4 py-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/40">
            {sortedIncidents.map((inc) => (
              <tr
                key={inc.id || Math.random()}
                onClick={() => onSelectIncident && onSelectIncident(inc)}
                className="hover:bg-slate-700/40 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 font-mono text-slate-300">
                  {formatTimestamp(inc.timestamp)}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge classification={inc.classification} />
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-700/60 text-slate-200">
                    {inc.mitigation_tier}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-slate-300">
                  {inc.source_ip || 'Cluster'}
                </td>
                <td className="px-4 py-3 font-mono text-slate-200">
                  {inc.requests_per_sec.toFixed(1)}
                </td>
                <td className="px-4 py-3 font-mono text-slate-300">
                  {inc.url_entropy.toFixed(2)}
                </td>
                <td className="px-4 py-3 text-slate-400 max-w-xs truncate" title={inc.verdict_reason}>
                  {inc.verdict_reason || 'N/A'}
                </td>
                <td className="px-4 py-3">
                  <button className="flex items-center space-x-1 px-2 py-1 rounded bg-sky-500/10 text-sky-400 hover:bg-sky-500/20 text-xs font-semibold">
                    <Info className="w-3 h-3" />
                    <span>Explain</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
