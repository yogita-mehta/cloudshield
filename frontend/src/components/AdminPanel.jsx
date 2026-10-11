import React, { useState } from 'react';
import {
  ShieldAlert,
  Sliders,
  Lock,
  Unlock,
  Play,
  RotateCcw,
  PlusCircle,
  Trash2,
  AlertOctagon,
  Users,
  CheckCircle,
} from 'lucide-react';

export default function AdminPanel({
  mitigationStatus,
  onSetTier,
  onBlockIp,
  onUnblockIp,
  onResetSystem,
  onRunSimulation,
  auth,
  onLogin,
  onLogout,
}) {
  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('');
  const [newIp, setNewIp] = useState('');
  const [blockReason, setBlockReason] = useState('Manual block');
  const [simRunning, setSimRunning] = useState(false);

  const handleLoginSubmit = (e) => {
    e.preventDefault();
    onLogin(loginUser, loginPass);
  };

  const handleAddBlock = (e) => {
    e.preventDefault();
    if (newIp.trim()) {
      onBlockIp(newIp.trim(), blockReason);
      setNewIp('');
    }
  };

  const triggerSim = async (type) => {
    setSimRunning(true);
    await onRunSimulation(type);
    setSimRunning(false);
  };

  return (
    <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex items-center justify-between border-b border-slate-700/60 pb-4">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-sky-400" />
          <h2 className="text-base font-bold text-white">Administrator & Control Panel</h2>
        </div>
        <div>
          {auth?.authenticated ? (
            <div className="flex items-center space-x-3 text-xs">
              <span className="text-emerald-400 font-semibold flex items-center space-x-1">
                <Unlock className="w-3.5 h-3.5" />
                <span>Logged in as {auth.username}</span>
              </span>
              <button
                onClick={onLogout}
                className="px-2.5 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs transition"
              >
                Logout
              </button>
            </div>
          ) : (
            <span className="text-xs text-amber-400 flex items-center space-x-1">
              <Lock className="w-3.5 h-3.5" />
              <span>Operator Mode (Login for full controls)</span>
            </span>
          )}
        </div>
      </div>

      {/* Login Form if Not Authenticated */}
      {!auth?.authenticated && (
        <form onSubmit={handleLoginSubmit} className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-700/40 text-xs">
          <input
            type="text"
            placeholder="Username (admin)"
            value={loginUser}
            onChange={(e) => setLoginUser(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-white focus:outline-none focus:border-sky-500"
          />
          <input
            type="password"
            placeholder="Password (cloudshield2026)"
            value={loginPass}
            onChange={(e) => setLoginPass(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-white focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            className="px-4 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-semibold transition"
          >
            Authenticate
          </button>
        </form>
      )}

      {/* Section 1: Manual Mitigation Tier Overrides */}
      <div>
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
          Manual Mitigation Tier Overrides
        </h3>
        <div className="flex flex-wrap gap-2 text-xs">
          <button
            onClick={() => onSetTier('NONE')}
            className={`px-3 py-2 rounded-lg border font-semibold transition ${mitigationStatus?.active_tier === 'NONE' ? 'bg-slate-700 text-white border-slate-500' : 'bg-slate-800/80 text-slate-300 border-slate-700 hover:bg-slate-700'}`}
          >
            Tier 0: Normal
          </button>
          <button
            onClick={() => onSetTier('TIER_1')}
            className={`px-3 py-2 rounded-lg border font-semibold transition ${mitigationStatus?.active_tier === 'TIER_1' ? 'bg-sky-600 text-white border-sky-400' : 'bg-slate-800/80 text-sky-400 border-slate-700 hover:bg-slate-700'}`}
          >
            Tier 1: Rate Limiting
          </button>
          <button
            onClick={() => onSetTier('TIER_2')}
            className={`px-3 py-2 rounded-lg border font-semibold transition ${mitigationStatus?.active_tier === 'TIER_2' ? 'bg-amber-600 text-white border-amber-400' : 'bg-slate-800/80 text-amber-400 border-slate-700 hover:bg-slate-700'}`}
          >
            Tier 2: IP Blocklist
          </button>
          <button
            onClick={() => onSetTier('TIER_3')}
            className={`px-3 py-2 rounded-lg border font-semibold transition ${mitigationStatus?.active_tier === 'TIER_3' ? 'bg-purple-600 text-white border-purple-400' : 'bg-slate-800/80 text-purple-400 border-slate-700 hover:bg-slate-700'}`}
          >
            Tier 3: Scale Out
          </button>
          <button
            onClick={() => onSetTier('TIER_4')}
            className={`px-3 py-2 rounded-lg border font-semibold transition ${mitigationStatus?.active_tier === 'TIER_4' ? 'bg-rose-600 text-white border-rose-400' : 'bg-slate-800/80 text-rose-400 border-slate-700 hover:bg-slate-700'}`}
          >
            Tier 4: Proxy Failover
          </button>
        </div>
      </div>

      {/* Section 2: Safe Lab Simulation Controls */}
      <div>
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
          Lab Evaluation & Attack Simulator (Safe Controls)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <button
            disabled={simRunning}
            onClick={() => triggerSim('attack')}
            className="flex items-center justify-center space-x-2 p-3 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 font-semibold transition"
          >
            <AlertOctagon className="w-4 h-4" />
            <span>Simulate HTTP Flood</span>
          </button>

          <button
            disabled={simRunning}
            onClick={() => triggerSim('flash_crowd')}
            className="flex items-center justify-center space-x-2 p-3 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold transition"
          >
            <Users className="w-4 h-4" />
            <span>Simulate Flash Crowd</span>
          </button>

          <button
            disabled={simRunning}
            onClick={() => triggerSim('honeypot')}
            className="flex items-center justify-center space-x-2 p-3 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 font-semibold transition"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Trip Honeypot Decoy</span>
          </button>

          <button
            disabled={simRunning}
            onClick={onResetSystem}
            className="flex items-center justify-center space-x-2 p-3 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-semibold transition"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Reset Baseline State</span>
          </button>
        </div>
      </div>

      {/* Section 3: IP Blocklist Management */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Tier 2 IP Blocklist ({mitigationStatus?.blocked_ip_count || 0} Blocked)
          </h3>
        </div>

        {/* Add IP Form */}
        <form onSubmit={handleAddBlock} className="flex gap-2 mb-3 text-xs">
          <input
            type="text"
            placeholder="IP Address to block (e.g. 192.168.1.50)"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            className="flex-1 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-semibold flex items-center space-x-1"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Block IP</span>
          </button>
        </form>

        {/* Blocked IPs Table */}
        <div className="bg-slate-900/60 rounded-lg border border-slate-700/60 max-h-36 overflow-y-auto">
          {mitigationStatus?.blocked_ips && mitigationStatus.blocked_ips.length > 0 ? (
            <div className="divide-y divide-slate-800">
              {mitigationStatus.blocked_ips.map((ip) => (
                <div key={ip} className="flex items-center justify-between px-3 py-2 text-xs">
                  <span className="font-mono text-amber-300">{ip}</span>
                  <button
                    onClick={() => onUnblockIp(ip)}
                    className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition"
                    title="Unblock IP"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-3 text-center text-xs text-slate-500">
              No IPs currently in blocklist. All clients within operational thresholds.
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
