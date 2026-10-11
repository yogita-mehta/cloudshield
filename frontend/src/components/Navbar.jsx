import React from 'react';
import { Shield, Activity, Server } from 'lucide-react';

export default function Navbar({ systemOnline, serverNode }) {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">CloudShield</span>
              <span className="px-2 py-0.5 text-xs font-semibold rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                Phase 1 MVP
              </span>
            </div>
            <p className="text-xs text-slate-400">Load-Balancing-Based DDoS Mitigation</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs">
            <Server className="w-4 h-4 text-slate-400" />
            <span className="text-slate-400">Active Proxy:</span>
            <span className="font-mono text-slate-200">Nginx :8080 (Round-Robin Upstream)</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs">
            <span className={`w-2.5 h-2.5 rounded-full ${systemOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
            <span className={systemOnline ? 'text-emerald-400 font-medium' : 'text-rose-400 font-medium'}>
              {systemOnline ? 'Backend Online' : 'Connecting...'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
