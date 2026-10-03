import React from 'react';
import type { EvidenceMetric } from '../../types/uniguard';
import { Info } from 'lucide-react';

interface ExplainabilityBoxProps {
  whyDetected: string;
  evidence: EvidenceMetric[];
  title?: string;
}

export const ExplainabilityBox: React.FC<ExplainabilityBoxProps> = ({
  whyDetected,
  evidence,
  title = 'WHY WAS THIS DETECTED?',
}) => {
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 font-sans">
      <div className="flex items-center gap-2 mb-2">
        <Info className="w-4 h-4 text-teal-700" />
        <h4 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">{title}</h4>
      </div>

      <p className="text-xs text-slate-700 bg-white p-3 rounded border border-slate-200/90 leading-relaxed mb-4">
        "{whyDetected}"
      </p>

      <div className="space-y-3">
        <h5 className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Detection Evidence</h5>
        <div className="space-y-2.5">
          {evidence.map((item, idx) => (
            <div key={idx} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-slate-700">{item.label}</span>
                <span className="font-mono font-semibold text-slate-800">{item.percentage}%</span>
              </div>
              
              <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    item.percentage > 90 
                      ? 'bg-amber-600' 
                      : item.percentage > 80 
                      ? 'bg-teal-600' 
                      : 'bg-slate-500'
                  }`}
                  style={{ width: `${item.percentage}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-500">{item.detail}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
