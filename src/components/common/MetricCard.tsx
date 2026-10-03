import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  icon?: React.ElementType;
  badgeText?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtext,
  change,
  changeType = 'neutral',
  icon: Icon,
  badgeText,
}) => {
  return (
    <div className="bg-white border border-slate-200/90 rounded-lg p-4 shadow-xs hover:border-slate-300 transition-colors font-sans">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{title}</span>
        {Icon && <Icon className="w-4 h-4 text-slate-400" />}
        {badgeText && (
          <span className="text-[11px] font-medium text-slate-600 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded font-mono">
            {badgeText}
          </span>
        )}
      </div>

      <div className="mt-2 flex items-baseline justify-between">
        <div className="text-2xl font-bold text-slate-900 tracking-tight font-mono">{value}</div>
        {change && (
          <span
            className={`text-xs font-medium ${
              changeType === 'positive'
                ? 'text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-100'
                : changeType === 'negative'
                ? 'text-red-700 bg-red-50 px-1.5 py-0.5 rounded border border-red-100'
                : 'text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded'
            }`}
          >
            {change}
          </span>
        )}
      </div>

      {subtext && <p className="mt-1 text-xs text-slate-500">{subtext}</p>}
    </div>
  );
};
