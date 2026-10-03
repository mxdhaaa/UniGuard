import React from 'react';
import type { ModelMetric } from '../../types/uniguard';

interface ModelsViewProps {
  models: ModelMetric[];
}

export const ModelsView: React.FC<ModelsViewProps> = ({ models }) => {
  return (
    <div className="space-y-6 font-sans">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Machine Learning Detector Registry</h1>
          <span className="text-[10px] font-mono font-semibold bg-amber-100 text-amber-800 border border-amber-200 px-2 py-0.5 rounded">
            PENDING EVALUATION
          </span>
        </div>
        <p className="text-xs text-slate-500 mt-1">
          Machine learning detector models and heuristic feature weights for passive network inspection.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {models.map((model) => (
          <div key={model.id} className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-500 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded uppercase font-semibold">
                  Model: Pending evaluation
                </span>
                <h3 className="text-sm font-bold text-slate-900 mt-1.5">{model.name}</h3>
                <p className="text-xs text-slate-500">{model.type}</p>
              </div>

              <span className="bg-slate-100 text-slate-700 border border-slate-200 px-2 py-0.5 rounded text-[10px] font-mono font-semibold">
                {model.status}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-3 bg-slate-50 p-3 rounded border border-slate-200/80 text-xs font-mono">
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-sans block">Accuracy</span>
                <span className="font-bold text-slate-700">{model.accuracy}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-sans block">F1-Score</span>
                <span className="font-bold text-slate-700">{model.f1Score}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-sans block">Inference</span>
                <span className="font-bold text-slate-700 text-[11px]">{model.avgInferenceMs}</span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block font-sans">
                Feature Importance Weights (Configured)
              </span>
              <div className="space-y-2">
                {model.topFeatures.map((feat, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-700 text-[11px]">{feat.name}</span>
                      <span className="text-slate-500 font-semibold">{(feat.weight * 100).toFixed(0)}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden border border-slate-200/60">
                      <div
                        className="h-full bg-slate-700 rounded-full"
                        style={{ width: `${feat.weight * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-2 text-[11px] text-slate-400 font-mono flex justify-between border-t border-slate-100">
              <span>Status: {model.lastTrained}</span>
              <span>ID: {model.id}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
