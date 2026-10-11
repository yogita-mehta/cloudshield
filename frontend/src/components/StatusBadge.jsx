import React from 'react';

export default function StatusBadge({ classification }) {
  const normalized = (classification || 'NORMAL').toUpperCase();

  const styles = {
    NORMAL: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    SUSPICIOUS: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    ATTACK: 'bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse',
    FLASH_CROWD: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  };

  const currentStyle = styles[normalized] || 'bg-slate-700/50 text-slate-300 border-slate-600';

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${currentStyle}`}>
      {normalized}
    </span>
  );
}
