import React, { useState } from 'react';
import type { ThreatDetection } from '../../types/uniguard';
import { SeverityBadge } from '../common/SeverityBadge';
import { ExplainabilityBox } from '../common/ExplainabilityBox';
import { 
  X, 
  CheckCircle, 
  Download, 
  Cpu
} from 'lucide-react';

interface ThreatDetailModalProps {
  threat: ThreatDetection | null;
  onClose: () => void;
  onStatusChange: (id: string, status: ThreatDetection['status']) => void;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  threat,
  onClose,
  onStatusChange,
}) => {
  const [activeTab, setActiveTab] = useState<'evidence' | 'features' | 'timeline' | 'flow'>('evidence');
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  if (!threat) return null;

  const handleExportPCAP = () => {
    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-slate-200 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 font-sans">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-start justify-between bg-slate-50/50">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-slate-900 font-sans tracking-tight">{threat.threat}</h2>
              <SeverityBadge severity={threat.severity} />
              <span className="bg-teal-50 text-teal-800 border border-teal-200 text-xs font-mono font-semibold px-2 py-0.5 rounded">
                {threat.confidence}% confidence
              </span>
              <span className="text-xs text-slate-500 font-mono">ID: {threat.id}</span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Category: <span className="font-medium text-slate-700">{threat.category}</span> &bull; First detected {threat.detectedAgo}
            </p>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Actions Bar */}
        <div className="px-6 py-2.5 bg-slate-100/70 border-b border-slate-200 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-medium">Status:</span>
            <span className="font-mono font-semibold text-slate-800 bg-white px-2 py-0.5 rounded border border-slate-200 uppercase text-[11px]">
              {threat.status}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {threat.status !== 'INVESTIGATING' && (
              <button
                onClick={() => onStatusChange(threat.id, 'INVESTIGATING')}
                className="px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded font-medium transition-colors"
              >
                Mark Investigating
              </button>
            )}
            {threat.status !== 'FALSE_POSITIVE' && (
              <button
                onClick={() => onStatusChange(threat.id, 'FALSE_POSITIVE')}
                className="px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded font-medium transition-colors"
              >
                Mark False Positive
              </button>
            )}
            {threat.status !== 'MITIGATED' && (
              <button
                onClick={() => onStatusChange(threat.id, 'MITIGATED')}
                className="px-2.5 py-1 bg-teal-800 hover:bg-teal-900 text-white rounded font-medium transition-colors flex items-center gap-1"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Resolve / Mitigate
              </button>
            )}
            <button
              onClick={handleExportPCAP}
              className="px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded font-medium transition-colors flex items-center gap-1"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              {downloadSuccess ? 'Downloaded!' : 'Export PCAP Log'}
            </button>
          </div>
        </div>

        {/* Navigation Tabs inside Modal */}
        <div className="flex border-b border-slate-200 px-6 bg-white">
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeTab === 'evidence'
                ? 'border-teal-700 text-teal-900 font-semibold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            Detection Evidence & Reasoning
          </button>
          <button
            onClick={() => setActiveTab('features')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeTab === 'features'
                ? 'border-teal-700 text-teal-900 font-semibold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            Feature Vector Analysis ({threat.featureAnalysis.length})
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeTab === 'timeline'
                ? 'border-teal-700 text-teal-900 font-semibold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            Timeline & Event Flow ({threat.timeline.length})
          </button>
          <button
            onClick={() => setActiveTab('flow')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeTab === 'flow'
                ? 'border-teal-700 text-teal-900 font-semibold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            Flow Information
          </button>
        </div>

        {/* Content Area */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 bg-white">
          {/* Flow Summary Grid Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs">
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-medium">Source Endpoint</span>
              <span className="font-mono font-semibold text-slate-900">{threat.sourceIp}:{threat.sourcePort}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-medium">Destination Target</span>
              <span className="font-mono font-semibold text-slate-900">{threat.destIp}:{threat.destPort}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-medium">Protocol & SNI</span>
              <span className="font-mono font-semibold text-slate-900">{threat.protocol} {threat.flowInfo.tlsSni ? `(${threat.flowInfo.tlsSni})` : ''}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-medium">Passive Driver</span>
              <span className="font-mono font-semibold text-slate-900">{threat.flowInfo.interface}</span>
            </div>
          </div>

          {/* TAB 1: Evidence & Explainability */}
          {activeTab === 'evidence' && (
            <div className="space-y-6">
              <ExplainabilityBox
                whyDetected={threat.whyDetected}
                evidence={threat.evidence}
              />

              <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-slate-600" />
                  <h4 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Model Attribution & Inference</h4>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200/70">
                    <span className="text-slate-500 block text-[11px]">Detector Model</span>
                    <span className="font-mono font-semibold text-slate-900">{threat.modelInfo.name}</span>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200/70">
                    <span className="text-slate-500 block text-[11px]">Inference Latency</span>
                    <span className="font-mono font-semibold text-slate-900">{threat.modelInfo.inferenceLatencyMs} ms</span>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200/70">
                    <span className="text-slate-500 block text-[11px]">Ensemble Voting</span>
                    <span className="font-mono font-semibold text-slate-900">{threat.modelInfo.subDetectorVote}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Feature Analysis Table */}
          {activeTab === 'features' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Feature Variance vs Baseline</h4>
                <span className="text-xs text-slate-500">Normal Range: |Z-score| &lt; 2.0</span>
              </div>
              <div className="border border-slate-200 rounded-lg overflow-hidden">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold uppercase text-[10px]">
                      <th className="p-2.5">Feature Name</th>
                      <th className="p-2.5">Observed Flow Value</th>
                      <th className="p-2.5">Subnet Baseline</th>
                      <th className="p-2.5">Z-Score Deviation</th>
                      <th className="p-2.5">Impact Weight</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 font-mono">
                    {threat.featureAnalysis.map((feat, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/70">
                        <td className="p-2.5 font-medium text-slate-900 font-sans">{feat.name}</td>
                        <td className="p-2.5 text-slate-800">{feat.observed}</td>
                        <td className="p-2.5 text-slate-500">{feat.baseline}</td>
                        <td className="p-2.5">
                          <span className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                            feat.zScore > 4.0 ? 'bg-red-50 text-red-700 border border-red-200' :
                            feat.zScore > 2.5 ? 'bg-amber-50 text-amber-800 border border-amber-200' :
                            'bg-slate-100 text-slate-700'
                          }`}>
                            +{feat.zScore} σ
                          </span>
                        </td>
                        <td className="p-2.5 font-sans">
                          <span className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                            feat.impact === 'HIGH' ? 'bg-red-50 text-red-700' :
                            feat.impact === 'MEDIUM' ? 'bg-amber-50 text-amber-800' :
                            'bg-slate-100 text-slate-600'
                          }`}>
                            {feat.impact}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: Event Timeline */}
          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Chronological Sequence</h4>
              <div className="relative pl-6 border-l-2 border-slate-200 space-y-6 my-2">
                {threat.timeline.map((event, idx) => (
                  <div key={idx} className="relative group">
                    <div className={`absolute -left-[31px] top-0 w-4 h-4 rounded-full border-2 bg-white flex items-center justify-center ${
                      event.type === 'critical' ? 'border-red-600 text-red-600' :
                      event.type === 'warning' ? 'border-amber-600 text-amber-600' :
                      'border-slate-400 text-slate-400'
                    }`}>
                      <div className="w-1.5 h-1.5 rounded-full bg-current" />
                    </div>

                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-slate-500">{event.time}</span>
                        <h5 className="text-xs font-semibold text-slate-900">{event.title}</h5>
                      </div>
                      <p className="text-xs text-slate-600 mt-0.5">{event.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Flow Information Details */}
          {activeTab === 'flow' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3">
                <h5 className="font-semibold text-slate-800 uppercase text-[11px]">Network Telemetry</h5>
                <div className="space-y-2 font-mono">
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Total Packets:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.packets.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Total Volume:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.bytesTotal}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Connection Duration:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.durationSec} seconds</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Avg Inter-packet Gap:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.avgInterPacketTimeMs} ms</span>
                  </div>
                </div>
              </div>

              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3">
                <h5 className="font-semibold text-slate-800 uppercase text-[11px]">Interface & Tagging</h5>
                <div className="space-y-2 font-mono">
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">VLAN ID:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.vlanId || 'Untagged'}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Capture Hook:</span>
                    <span className="font-semibold text-slate-900">{threat.flowInfo.interface}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-200/60 pb-1">
                    <span className="text-slate-500 font-sans">Timestamp (UTC):</span>
                    <span className="font-semibold text-slate-900">{threat.timestamp}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 bg-slate-50 border-t border-slate-200 flex justify-between items-center text-xs">
          <span className="text-slate-500">UniGuard Passive Inspection Engine &bull; Non-intrusive SPAN / TAP analysis</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded font-medium transition-colors"
          >
            Close Investigation
          </button>
        </div>

      </div>
    </div>
  );
};
