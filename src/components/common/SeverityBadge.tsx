import React from 'react';
import type { SeverityLevel } from '../../types/uniguard';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '', size = 'md' }) => {
  const sizeClasses = size === 'sm' 
    ? 'px-1.5 py-0.5 text-[10px] font-semibold tracking-wide' 
    : 'px-2 py-0.5 text-xs font-semibold tracking-wider';

  let colorClasses = '';

  switch (severity) {
    case 'CRITICAL':
      colorClasses = 'bg-red-50 text-red-700 border border-red-200/80';
      break;
    case 'HIGH':
      colorClasses = 'bg-amber-50 text-amber-800 border border-amber-200/80';
      break;
    case 'MEDIUM':
      colorClasses = 'bg-slate-100 text-slate-700 border border-slate-200';
      break;
    case 'LOW':
      colorClasses = 'bg-emerald-50 text-emerald-800 border border-emerald-200/80';
      break;
  }

  return (
    <span className={`inline-flex items-center rounded uppercase font-mono ${sizeClasses} ${colorClasses} ${className}`}>
      {severity}
    </span>
  );
};
