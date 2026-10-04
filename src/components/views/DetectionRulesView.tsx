import React, { useState } from 'react';
import { Save } from 'lucide-react';

export const DetectionRulesView: React.FC = () => {
  const [beaconJitterThreshold, setBeaconJitterThreshold] = useState<number>(0.05);
  const [minConfidence, setMinConfidence] = useState<number>(85);
  const [entropyThreshold, setEntropyThreshold] = useState<number>(4.2);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const rules = [
    { id: 'RULE-01', name: 'Low Variance Beaconing Detector', status: 'ACTIVE', model: 'UniGuard-XGBoost', category: 'C2', sensitivity: 'High' },
    { id: 'RULE-02', name: 'High Volume Outbound Exfiltration Anomaly', status: 'ACTIVE', model: 'UniGuard-AutoEncoder', category: 'Exfiltration', sensitivity: 'Medium' },
    { id: 'RULE-03', name: 'Subdomain Encoded DNS Tunneling', status: 'ACTIVE', model: 'UniGuard-DNS-Transformer', category: 'Protocol Misuse', sensitivity: 'High' },
    { id: 'RULE-04', name: 'Lateral Probing & Subnet Fan-out', status: 'ACTIVE', model: 'UniGuard-Recon-XGBoost', category: 'Reconnaissance', sensitivity: 'Medium' },
    { id: 'RULE-05', name: 'Rare TLS JA3 Cipher Suite Anomaly', status: 'ACTIVE', model: 'UniGuard-JA3-Classifier', category: 'Anomaly', sensitivity: 'Low' },
  ];

  const handleSave = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="space-y-6 font-sans">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Passive Detection Rules</h1>
          <p className="text-xs text-slate-500 mt-1">
            Configure detector thresholds, ML confidence bounds, and feature extraction weights.
          </p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-800 hover:bg-teal-900 text-white rounded text-xs font-medium transition-colors shadow-xs"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{savedSuccess ? 'Configuration Saved!' : 'Save Parameters'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Detection Parameter Tuning */}
        <div className="lg:col-span-1 bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-5">
          <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Engine Sensitivity Tuning</h3>
          
          <div className="space-y-4 text-xs">
            <div>
              <div className="flex justify-between mb-1 text-slate-700 font-medium">
                <span>Beacon Jitter Threshold (sec)</span>
                <span className="font-mono font-bold text-slate-900">{beaconJitterThreshold} s</span>
              </div>
              <input
                type="range"
                min="0.01"
                max="0.25"
                step="0.01"
                value={beaconJitterThreshold}
                onChange={(e) => setBeaconJitterThreshold(parseFloat(e.target.value))}
                className="w-full accent-teal-700 cursor-pointer"
              />
              <p className="text-[11px] text-slate-500 mt-1">Lower values reduce false positives for periodic background updates.</p>
            </div>

            <div className="pt-3 border-t border-slate-200">
              <div className="flex justify-between mb-1 text-slate-700 font-medium">
                <span>Min Alert Confidence Cutoff</span>
                <span className="font-mono font-bold text-slate-900">{minConfidence}%</span>
              </div>
              <input
                type="range"
                min="60"
                max="98"
                value={minConfidence}
                onChange={(e) => setMinConfidence(parseInt(e.target.value))}
                className="w-full accent-teal-700 cursor-pointer"
              />
              <p className="text-[11px] text-slate-500 mt-1">Only trigger high-priority alerts above this confidence threshold.</p>
            </div>

            <div className="pt-3 border-t border-slate-200">
              <div className="flex justify-between mb-1 text-slate-700 font-medium">
                <span>DNS Entropy Cutoff (bits/char)</span>
                <span className="font-mono font-bold text-slate-900">{entropyThreshold}</span>
              </div>
              <input
                type="range"
                min="2.0"
                max="6.0"
                step="0.1"
                value={entropyThreshold}
                onChange={(e) => setEntropyThreshold(parseFloat(e.target.value))}
                className="w-full accent-teal-700 cursor-pointer"
              />
              <p className="text-[11px] text-slate-500 mt-1">Flags DNS subdomains with high Shannon entropy.</p>
            </div>
          </div>
        </div>

        {/* Active Heuristics Table */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200 bg-slate-50/50">
            <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Active Detection Rule Registry</h3>
          </div>
          <table className="w-full text-left border-collapse text-xs enterprise-table">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                <th className="py-2.5 px-4">Rule ID</th>
                <th className="py-2.5 px-4">Rule Name</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">Backing Model</th>
                <th className="py-2.5 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50/80">
                  <td className="py-2.5 px-4 font-mono font-semibold text-slate-700">{r.id}</td>
                  <td className="py-2.5 px-4 font-medium text-slate-900">{r.name}</td>
                  <td className="py-2.5 px-4 text-slate-600">{r.category}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-600 text-[11px]">{r.model}</td>
                  <td className="py-2.5 px-4">
                    <span className="bg-emerald-50 text-emerald-800 border border-emerald-200 px-2 py-0.5 rounded font-mono text-[10px] font-semibold">
                      {r.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
