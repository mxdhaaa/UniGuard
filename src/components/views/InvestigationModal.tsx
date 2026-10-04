/**
 * UniGuard Flow & Alert Investigation Modal (Milestone 14)
 * 
 * Comprehensive SOC deep-dive investigation interface backed by:
 * GET /api/investigations/flows/{flow_id}
 * GET /api/investigations/alerts/{alert_id}
 */

import { useState, useEffect } from 'react';
import { 
  X, 
  ShieldAlert, 
  Cpu, 
  FileText, 
  Clock, 
  AlertTriangle, 
  CheckCircle2, 
  HelpCircle,
  Network,
  Activity,
  Layers,
  SearchCheck,
  RefreshCw,
} from 'lucide-react';
import { 
  uniguardApi, 
  type InvestigationResponse 
} from '../../api/client';
import { SeverityBadge } from '../common/SeverityBadge';
import type { SeverityLevel } from '../../types/uniguard';

interface InvestigationModalProps {
  flowId?: string | null;
  alertId?: string | null;
  onClose: () => void;
  onOpenReport?: (subject: { flowId?: string; alertId?: string }) => void;
}

export const InvestigationModal: React.FC<InvestigationModalProps> = ({
  flowId,
  alertId,
  onClose,
  onOpenReport,
}) => {
  const [data, setData] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'features' | 'evidence' | 'findings' | 'timeline'>('overview');

  useEffect(() => {
    let isCurrent = true;

    async function fetchInvestigation() {
      setLoading(true);
      setError(null);
      try {
        let res: InvestigationResponse;
        if (flowId) {
          res = await uniguardApi.getFlowInvestigation(flowId);
        } else if (alertId) {
          res = await uniguardApi.getAlertInvestigation(alertId);
        } else {
          return;
        }

        if (isCurrent) {
          setData(res);
        }
      } catch (err: any) {
        if (isCurrent) {
          setError(err?.message || 'Failed to load investigation data');
        }
      } finally {
        if (isCurrent) {
          setLoading(false);
        }
      }
    }

    if (flowId || alertId) {
      fetchInvestigation();
    }

    return () => {
      isCurrent = false;
    };
  }, [flowId, alertId]);

  if (!flowId && !alertId) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-slate-200 rounded-lg shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 font-sans">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="p-1.5 rounded bg-teal-800 text-white">
                <SearchCheck className="w-4 h-4" />
              </div>
              <h2 className="text-base font-bold text-slate-900 tracking-tight">
                SOC Incident Investigation
              </h2>
              {data && (
                <SeverityBadge severity={data.risk_assessment.severity as SeverityLevel || 'LOW'} />
              )}
              {data?.subject && (
                <span className="text-xs font-mono text-slate-500 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded">
                  {data.subject.investigation_id}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Deterministic evidence synthesis and behavior analysis from persisted records.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {data && onOpenReport && (
              <button
                onClick={() => onOpenReport({ flowId: data.subject.flow_id, alertId: data.subject.alert_id || undefined })}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-teal-800 hover:bg-teal-900 text-white rounded transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>View Incident Report</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-700 p-1.5 rounded hover:bg-slate-200/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="p-12 text-center space-y-3">
              <RefreshCw className="w-6 h-6 animate-spin text-teal-700 mx-auto" />
              <p className="text-xs text-slate-600 font-medium">Retrieving persisted investigation telemetry...</p>
            </div>
          )}

          {error && (
            <div className="p-8 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-red-100 text-red-700 flex items-center justify-center mx-auto">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">Investigation Unavailable</h3>
              <p className="text-xs text-red-600 max-w-md mx-auto">{error}</p>
              <button
                onClick={onClose}
                className="mt-2 px-3 py-1.5 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded font-medium"
              >
                Close
              </button>
            </div>
          )}

          {!loading && !error && data && (
            <div>
              {/* Tab Navigation */}
              <div className="flex border-b border-slate-200 bg-slate-50/50 px-6 gap-6 text-xs font-medium text-slate-600">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`py-3 flex items-center gap-1.5 border-b-2 transition-colors ${
                    activeTab === 'overview'
                      ? 'border-teal-700 text-teal-900 font-semibold'
                      : 'border-transparent hover:text-slate-900'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>Overview & Summary</span>
                </button>

                <button
                  onClick={() => setActiveTab('features')}
                  className={`py-3 flex items-center gap-1.5 border-b-2 transition-colors ${
                    activeTab === 'features'
                      ? 'border-teal-700 text-teal-900 font-semibold'
                      : 'border-transparent hover:text-slate-900'
                  }`}
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>16 Canonical Features</span>
                </button>

                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`py-3 flex items-center gap-1.5 border-b-2 transition-colors ${
                    activeTab === 'evidence'
                      ? 'border-teal-700 text-teal-900 font-semibold'
                      : 'border-transparent hover:text-slate-900'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Evidence ({data.evidence.length})</span>
                </button>

                <button
                  onClick={() => setActiveTab('findings')}
                  className={`py-3 flex items-center gap-1.5 border-b-2 transition-colors ${
                    activeTab === 'findings'
                      ? 'border-teal-700 text-teal-900 font-semibold'
                      : 'border-transparent hover:text-slate-900'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Findings ({data.findings.length})</span>
                </button>

                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`py-3 flex items-center gap-1.5 border-b-2 transition-colors ${
                    activeTab === 'timeline'
                      ? 'border-teal-700 text-teal-900 font-semibold'
                      : 'border-transparent hover:text-slate-900'
                  }`}
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>Timeline ({data.timeline.length})</span>
                </button>
              </div>

              {/* Tab View: Overview */}
              {activeTab === 'overview' && (
                <div className="p-6 space-y-6">
                  {/* Executive Summary Callout */}
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-2">
                    <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 uppercase tracking-wider">
                      <SearchCheck className="w-4 h-4 text-teal-700" />
                      <span>Deterministic Investigation Summary</span>
                    </div>
                    <p className="text-xs text-slate-800 leading-relaxed font-sans">
                      {data.summary}
                    </p>
                  </div>

                  {/* Flow 5-Tuple & Protocol Specs */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase">Source Endpoint</span>
                      <div className="font-mono text-xs font-semibold text-slate-900">
                        {data.flow.source_ip || 'N/A'}:{data.flow.source_port ?? 'N/A'}
                      </div>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase">Destination Endpoint</span>
                      <div className="font-mono text-xs font-semibold text-slate-900">
                        {data.flow.destination_ip || 'N/A'}:{data.flow.destination_port ?? 'N/A'}
                      </div>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase">Protocol & Duration</span>
                      <div className="font-mono text-xs font-semibold text-slate-900">
                        {data.flow.protocol || 'TCP'} &bull; {(data.flow.duration || 0).toFixed(2)}s
                      </div>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase">Volume (Packets / Bytes)</span>
                      <div className="font-mono text-xs font-semibold text-slate-900">
                        {data.flow.packet_count ?? 0} pkts &bull; {(data.flow.byte_count ?? 0).toLocaleString()} B
                      </div>
                    </div>
                  </div>

                  {/* ML & Risk Engine Summary */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-4 bg-white border border-slate-200 rounded-lg space-y-2">
                      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Threat Classification
                      </div>
                      <div className="text-sm font-bold text-slate-900">
                        {data.ml_assessment.threat_type || 'NORMAL'}
                      </div>
                      <div className="text-xs text-slate-500">
                        Confidence: <span className="font-mono font-semibold text-slate-700">{((data.ml_assessment.classifier_confidence || 0) * 100).toFixed(1)}%</span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        Model Version: {data.ml_assessment.model_version || '1.0.0'}
                      </div>
                    </div>

                    <div className="p-4 bg-white border border-slate-200 rounded-lg space-y-2">
                      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Anomaly Engine
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold font-mono ${
                          data.ml_assessment.is_anomaly
                            ? 'bg-red-100 text-red-800 border border-red-200'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        }`}>
                          {data.ml_assessment.is_anomaly ? 'ANOMALY DETECTED' : 'NORMAL STATISTICAL PROFILE'}
                        </span>
                      </div>
                      <div className="text-xs text-slate-500">
                        Score: <span className="font-mono font-semibold text-slate-700">{(data.ml_assessment.anomaly_score || 0).toFixed(3)}</span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        IsolationForest Outlier Detector
                      </div>
                    </div>

                    <div className="p-4 bg-white border border-slate-200 rounded-lg space-y-2">
                      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                        Deterministic Risk Assessment
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-bold font-mono text-slate-900">
                          {(data.risk_assessment.risk_score || 0).toFixed(1)}
                        </span>
                        <SeverityBadge severity={data.risk_assessment.severity as SeverityLevel || 'LOW'} />
                      </div>
                      <div className="text-xs text-slate-600">
                        {data.risk_assessment.explanation || 'No elevated risk factors detected.'}
                      </div>
                    </div>
                  </div>

                  {/* Recommended Action */}
                  <div className="bg-amber-50/70 border border-amber-200/80 rounded-lg p-4 space-y-1">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-900">
                      <CheckCircle2 className="w-4 h-4 text-amber-700" />
                      <span>SOC Recommended Action</span>
                    </div>
                    <p className="text-xs text-amber-950 font-medium">
                      {data.recommended_action}
                    </p>
                  </div>

                  {/* Formal Methodological Limitations */}
                  <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-4 space-y-2">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-600">
                      <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
                      <span>Methodological Limitations & Constraints</span>
                    </div>
                    <ul className="list-disc list-inside text-[11px] text-slate-600 space-y-1">
                      {data.limitations.map((lim, idx) => (
                        <li key={idx}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Tab View: 16 Canonical Features */}
              {activeTab === 'features' && (
                <div className="p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                        Canonical Feature Vector (16 Features)
                      </h3>
                      <p className="text-xs text-slate-500">
                        Extracted unidirectional flow features persisted during pipeline analysis.
                      </p>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                      Schema v{data.features.feature_schema_version || '1.0'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {Object.entries(data.features)
                      .filter(([key]) => key !== 'flow_id' && key !== 'feature_schema_version')
                      .map(([featureName, featureValue]) => (
                        <div
                          key={featureName}
                          className="p-3 bg-white border border-slate-200 rounded-md space-y-1 hover:border-slate-300 transition-colors"
                        >
                          <span className="text-[10px] font-mono text-slate-500 truncate block title={featureName}">
                            {featureName}
                          </span>
                          <div className="font-mono text-xs font-bold text-slate-900">
                            {typeof featureValue === 'number'
                              ? Number.isInteger(featureValue)
                                ? featureValue
                                : featureValue.toFixed(4)
                              : String(featureValue ?? 'N/A')}
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Tab View: Evidence */}
              {activeTab === 'evidence' && (
                <div className="p-6 space-y-3">
                  <div className="mb-2">
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Explainability Evidence Items ({data.evidence.length})
                    </h3>
                    <p className="text-xs text-slate-500">
                      Traceable signals produced by the Evidence Engine explaining ML and Risk evaluations.
                    </p>
                  </div>

                  {data.evidence.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-200 rounded-lg">
                      No standalone evidence items recorded for this flow.
                    </div>
                  ) : (
                    data.evidence.map((ev, idx) => (
                      <div
                        key={ev.evidence_id || idx}
                        className="p-4 bg-white border border-slate-200 rounded-lg space-y-2 hover:border-slate-300 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900">{ev.title}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                              {ev.category}
                            </span>
                          </div>
                          <SeverityBadge severity={ev.severity as SeverityLevel || 'LOW'} />
                        </div>
                        <p className="text-xs text-slate-700">{ev.description}</p>
                        <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono pt-1 border-t border-slate-100">
                          <span>Source: {ev.source}</span>
                          {ev.value && <span>Value: {String(ev.value)}</span>}
                          {typeof ev.strength === 'number' && (
                            <span>Contribution: {(ev.strength * 100).toFixed(0)}%</span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab View: Findings */}
              {activeTab === 'findings' && (
                <div className="p-6 space-y-3">
                  <div className="mb-2">
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Synthesized Security Findings ({data.findings.length})
                    </h3>
                    <p className="text-xs text-slate-500">
                      Deterministic security findings compiled directly from persisted database telemetry.
                    </p>
                  </div>

                  {data.findings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-200 rounded-lg">
                      No findings compiled for this investigation subject.
                    </div>
                  ) : (
                    data.findings.map((finding) => (
                      <div
                        key={finding.finding_id}
                        className="p-4 bg-white border border-slate-200 rounded-lg space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900">{finding.title}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-50 text-teal-800 border border-teal-200">
                              {finding.category}
                            </span>
                          </div>
                          <SeverityBadge severity={finding.severity as SeverityLevel || 'LOW'} />
                        </div>
                        <p className="text-xs text-slate-700 leading-relaxed">{finding.description}</p>
                        <div className="text-[10px] font-mono text-slate-400 pt-1">
                          Source: {finding.source} &bull; ID: {finding.finding_id}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab View: Timeline */}
              {activeTab === 'timeline' && (
                <div className="p-6 space-y-4">
                  <div className="mb-2">
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Chronological Evidence Timeline ({data.timeline.length})
                    </h3>
                    <p className="text-xs text-slate-500">
                      Temporal sequence anchored exclusively to persisted database observation timestamps.
                    </p>
                  </div>

                  {data.timeline.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-200 rounded-lg">
                      No chronological timeline events available.
                    </div>
                  ) : (
                    <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                      {data.timeline.map((event, idx) => (
                        <div key={idx} className="relative space-y-1">
                          <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-teal-700 border-2 border-white shadow-xs" />
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900">{event.title}</span>
                            <span className="text-[10px] font-mono text-slate-500">
                              {event.timestamp || 'N/A'}
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 border border-slate-200">
                              {event.event_type}
                            </span>
                          </div>
                          <p className="text-xs text-slate-700">{event.description}</p>
                          <div className="text-[10px] font-mono text-slate-400">
                            Source: {event.source}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-slate-500 text-[11px]">
            <Network className="w-3.5 h-3.5 text-slate-400" />
            <span>Passive SOC Investigation Engine &bull; Strictly Read-Only</span>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
