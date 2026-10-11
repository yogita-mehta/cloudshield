import React from 'react';
import StatusBadge from './StatusBadge';
import { X, AlertTriangle, ShieldCheck, Activity, Globe, Crosshair, Cpu, CheckCircle } from 'lucide-react';

export default function WhyFlaggedModal({ incident, onClose, onUnblockIp }) {
  if (!incident) return null;

  const isAttack = incident.classification === 'ATTACK';
  const isFlash = incident.classification === 'FLASH_CROWD';

  const rpsRatio = incident.baseline_rps > 0 ? (incident.requests_per_sec / incident.baseline_rps).toFixed(1) : 1;
  const urlEntropyDiff = (incident.url_entropy - 2.5).toFixed(2);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-xl border ${isAttack ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : isFlash ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'}`}>
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white tracking-tight">"Why Was This Flagged?" Analysis</h2>
                <StatusBadge classification={incident.classification} />
              </div>
              <p className="text-xs text-slate-400">Incident #{incident.id} &bull; {new Date(incident.timestamp).toLocaleString()}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Plain-Language Verdict Explanation */}
        <div className={`p-4 rounded-xl border ${isAttack ? 'bg-rose-950/20 border-rose-800/40 text-rose-200' : isFlash ? 'bg-cyan-950/20 border-cyan-800/40 text-cyan-200' : 'bg-slate-800/60 border-slate-700/60 text-slate-200'}`}>
          <div className="flex items-start space-x-2.5">
            <Crosshair className="w-5 h-5 mt-0.5 shrink-0 opacity-80" />
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider mb-1">Detection Engine Reasoning</h4>
              <p className="text-xs leading-relaxed">{incident.verdict_reason || 'Multi-signal baseline deviation triggered threshold rule.'}</p>
            </div>
          </div>
        </div>

        {/* Multi-Signal Breakdown Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          
          {/* Signal 1: Requests Per Second */}
          <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center space-x-1.5">
                <Activity className="w-3.5 h-3.5 text-sky-400" />
                <span>Requests Volume</span>
              </span>
              <span className="font-mono text-white font-bold">{incident.requests_per_sec.toFixed(1)} req/s</span>
            </div>
            <div className="w-full bg-slate-700/60 rounded-full h-2">
              <div className="bg-sky-500 h-2 rounded-full" style={{ width: `${Math.min(100, (incident.requests_per_sec / 50) * 100)}%` }} />
            </div>
            <div className="text-[11px] text-slate-400 flex justify-between">
              <span>Baseline: {incident.baseline_rps?.toFixed(1) || '5.0'} req/s</span>
              <span className="text-amber-300 font-semibold">{rpsRatio}x surge</span>
            </div>
          </div>

          {/* Signal 2: URL Shannon Entropy */}
          <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center space-x-1.5">
                <Globe className="w-3.5 h-3.5 text-purple-400" />
                <span>URL Shannon Entropy</span>
              </span>
              <span className="font-mono text-white font-bold">{incident.url_entropy.toFixed(2)}</span>
            </div>
            <div className="w-full bg-slate-700/60 rounded-full h-2">
              <div className={`h-2 rounded-full ${incident.url_entropy < 1.0 ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ width: `${Math.min(100, (incident.url_entropy / 3.0) * 100)}%` }} />
            </div>
            <div className="text-[11px] text-slate-400 flex justify-between">
              <span>Baseline: 2.50</span>
              <span className={incident.url_entropy < 1.0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                {incident.url_entropy < 1.0 ? 'Low (Target Flood)' : 'Healthy Spread'}
              </span>
            </div>
          </div>

          {/* Signal 3: Source IP Entropy */}
          <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Source-IP Entropy</span>
              <span className="font-mono text-white font-bold">{incident.ip_entropy.toFixed(2)}</span>
            </div>
            <div className="w-full bg-slate-700/60 rounded-full h-2">
              <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${Math.min(100, (incident.ip_entropy / 3.0) * 100)}%` }} />
            </div>
            <div className="text-[11px] text-slate-400">
              <span>Baseline: 2.80</span>
            </div>
          </div>

          {/* Signal 4: Attacker Source IP */}
          <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/60 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Primary Source IP</span>
              <span className="font-mono text-amber-300 font-bold">{incident.source_ip || 'Cluster IP'}</span>
            </div>
            <div className="text-[11px] text-slate-300">
              Mitigation Action: <span className="font-semibold text-sky-400">{incident.mitigation_tier}</span>
            </div>
          </div>

        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <div className="text-xs text-slate-400">
            Enforced Mitigation: <span className="font-bold text-white">{incident.mitigation_tier}</span>
          </div>
          <div className="flex space-x-3">
            {incident.source_ip && onUnblockIp && (
              <button
                onClick={() => onUnblockIp(incident.source_ip)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 transition"
              >
                Unblock IP
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition"
            >
              Close Analysis
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
