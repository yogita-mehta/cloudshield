import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'sky', badge }) {
  const colorMap = {
    sky: 'bg-sky-500/10 text-sky-400 border-sky-500/20',
    emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    amber: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    rose: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  };

  const iconClass = colorMap[color] || colorMap.sky;

  return (
    <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-5 hover:border-slate-600 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg border ${iconClass}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>
      <div className="flex items-baseline space-x-2">
        <span className="text-2xl font-bold tracking-tight text-white">{value}</span>
        {badge && <div>{badge}</div>}
      </div>
      {subtitle && <p className="text-xs text-slate-400 mt-2">{subtitle}</p>}
    </div>
  );
}
