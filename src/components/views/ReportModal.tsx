/**
 * UniGuard SOC Incident Report Modal (Milestone 14)
 * 
 * Formal SOC incident report viewer backed by:
 * GET /api/reports/flows/{flow_id}
 * GET /api/reports/alerts/{alert_id}
 */

import React, { useState, useEffect } from 'react';
import { 
  X, 
  FileText, 
  Copy, 
  Check, 
  AlertTriangle, 
  ShieldAlert, 
  Info, 
  RefreshCw, 
  SearchCheck, 
  ShieldCheck,
  Cpu,
  Layers,
  ChevronRight
} from 'lucide-react';
import { uniguardApi, type ReportResponse } from '../../api/client';
import { SeverityBadge } from '../common/SeverityBadge';
import type { SeverityLevel } from '../../types/uniguard';

interface ReportModalProps {
  flowId?: string | null;
  alertId?: string | null;
  onClose: () => void;
  onOpenInvestigation?: (subject: { flowId?: string; alertId?: string }) => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  flowId,
  alertId,
  onClose,
  onOpenInvestigation,
}) => {
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    let isCurrent = true;

    async function fetchReport() {
      setLoading(true);
      setError(null);
      try {
        let res: ReportResponse;
        if (flowId) {
          res = await uniguardApi.getFlowReport(flowId);
        } else if (alertId) {
          res = await uniguardApi.getAlertReport(alertId);
        } else {
          setError('No flow ID or alert ID provided.');
          setLoading(false);
          return;
        }

        if (isCurrent) {
          setReport(res);
          setLoading(false);
        }
      } catch (err: any) {
        if (isCurrent) {
          setError(err?.message || 'Failed to load SOC report.');
          setLoading(false);
        }
      }
    }

    fetchReport();

    return () => {
      isCurrent = false;
    };
  }, [flowId, alertId]);

  const handleCopyJson = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API is restricted
      setCopied(false);
    }
  };

  const getSeverityLevel = (sevStr?: string): SeverityLevel => {
    const s = (sevStr || '').toUpperCase();
    if (s === 'CRITICAL') return 'CRITICAL';
    if (s === 'HIGH') return 'HIGH';
    if (s === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 backdrop-blur-xs p-4 sm:p-6 overflow-y-auto animate-in fade-in duration-150">
      <div 
        className="bg-white border border-slate-200 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-teal-50 border border-teal-200 text-teal-800">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900 tracking-tight font-sans">
                  SOC Incident Report
                </h2>
                {report && (
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-semibold">
                    {report.report_id}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500">
                {flowId ? `Flow Assessment: ${flowId}` : `Alert Assessment: ${alertId}`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {report && (
              <>
                <button
                  onClick={handleCopyJson}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors shadow-2xs"
                  title="Copy full JSON report to clipboard"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-teal-600" />
                      <span className="text-teal-700 font-semibold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-500" />
                      <span>Copy JSON</span>
                    </>
                  )}
                </button>

                {onOpenInvestigation && (
                  <button
                    onClick={() => onOpenInvestigation({ flowId: flowId || undefined, alertId: alertId || undefined })}
                    className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold rounded-md bg-teal-800 hover:bg-teal-900 text-white transition-colors shadow-2xs"
                  >
                    <SearchCheck className="w-3.5 h-3.5" />
                    <span>Investigate</span>
                    <ChevronRight className="w-3 h-3 opacity-70" />
                  </button>
                )}
              </>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors"
              aria-label="Close report"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-700">
          {loading && (
            <div className="py-20 flex flex-col items-center justify-center gap-3 text-slate-400">
              <RefreshCw className="w-8 h-8 animate-spin text-teal-600" />
              <p className="text-xs font-medium">Generating SOC Report from Persisted Evidence...</p>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-lg bg-red-50 border border-red-200 text-red-800 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-sm">Failed to Load Incident Report</h4>
                <p className="text-xs text-red-700 mt-1">{error}</p>
              </div>
            </div>
          )}

          {!loading && !error && report && (
            <>
              {/* Report Metadata Banner */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-sans font-semibold">Report Type</span>
                  <span className="font-bold text-slate-800">{report.report_type}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-sans font-semibold">Generated At</span>
                  <span className="text-slate-700">{report.generated_at}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-sans font-semibold">Flow ID</span>
                  <span className="text-slate-800 truncate block" title={report.subject.flow_id}>{report.subject.flow_id}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-sans font-semibold">Alert ID</span>
                  <span className="text-slate-800">{report.subject.alert_id || 'N/A (Flow only)'}</span>
                </div>
              </div>

              {/* Executive Summary */}
              <section className="space-y-2">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 font-sans">
                  <FileText className="w-4 h-4 text-teal-700" />
                  Executive Summary
                </h3>
                <div className="p-4 rounded-lg bg-teal-50/40 border border-teal-200 text-slate-800 text-xs leading-relaxed font-sans shadow-2xs">
                  {report.executive_summary}
                </div>
              </section>

              {/* Assessment Grid: Classification, Risk, Anomaly */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Classification */}
                <div className="p-4 rounded-lg border border-slate-200 bg-white shadow-2xs space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-600 flex items-center gap-1.5">
                      <Cpu className="w-4 h-4 text-slate-500" />
                      Classification
                    </span>
                    <span className="font-mono text-xs font-bold text-slate-900">
                      {Math.round((report.classification?.confidence ?? 0) * 100)}% Conf
                    </span>
                  </div>
                  <div>
                    <div className="text-xs text-slate-400">Threat Type</div>
                    <div className="font-bold text-slate-900 font-mono text-sm mt-0.5">
                      {report.classification?.threat_type || 'BENIGN'}
                    </div>
                  </div>
                  {report.classification?.probabilities && (
                    <div className="space-y-1 pt-1 border-t border-slate-100 text-[11px]">
                      {Object.entries(report.classification.probabilities).map(([k, v]) => (
                        <div key={k} className="flex justify-between items-center text-slate-600">
                          <span className="font-mono text-[10px]">{k}</span>
                          <span className="font-mono font-semibold">{(Number(v) * 100).toFixed(1)}%</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Risk */}
                <div className="p-4 rounded-lg border border-slate-200 bg-white shadow-2xs space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-600 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-amber-500" />
                      Risk Assessment
                    </span>
                    <SeverityBadge severity={getSeverityLevel(report.risk?.severity)} />
                  </div>
                  <div>
                    <div className="text-xs text-slate-400">Risk Score</div>
                    <div className="font-bold text-slate-900 font-mono text-lg mt-0.5">
                      {report.risk?.score !== undefined ? `${report.risk.score}/100` : 'N/A'}
                    </div>
                  </div>
                  {report.risk?.components && (
                    <div className="space-y-1 pt-1 border-t border-slate-100 text-[11px]">
                      {Object.entries(report.risk.components).map(([k, v]) => (
                        <div key={k} className="flex justify-between items-center text-slate-600">
                          <span className="capitalize">{k.replace('_', ' ')}</span>
                          <span className="font-mono font-semibold">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Anomaly */}
                <div className="p-4 rounded-lg border border-slate-200 bg-white shadow-2xs space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-600 flex items-center gap-1.5">
                      <Layers className="w-4 h-4 text-indigo-500" />
                      Anomaly Detection
                    </span>
                    <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${
                      report.anomaly?.is_anomaly
                        ? 'bg-rose-100 text-rose-800'
                        : 'bg-emerald-100 text-emerald-800'
                    }`}>
                      {report.anomaly?.is_anomaly ? 'ANOMALOUS' : 'NORMAL'}
                    </span>
                  </div>
                  <div>
                    <div className="text-xs text-slate-400">Anomaly Score</div>
                    <div className="font-bold text-slate-900 font-mono text-lg mt-0.5">
                      {report.anomaly?.score !== undefined ? Number(report.anomaly.score).toFixed(4) : 'N/A'}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-100">
                    Baseline Deviation: <span className="font-mono font-semibold text-slate-700">{report.anomaly?.baseline_deviation ?? 'Standard'}</span>
                  </div>
                </div>
              </div>

              {/* Findings Section */}
              {report.findings && report.findings.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 font-sans">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    Key Findings ({report.findings.length})
                  </h3>
                  <div className="space-y-2">
                    {report.findings.map((f, i) => (
                      <div key={f.finding_id || i} className="p-3 rounded-lg border border-slate-200 bg-white flex items-start justify-between gap-3 shadow-2xs">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-xs text-slate-900">{f.title}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-600">
                              {f.category}
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 leading-normal">{f.description}</p>
                          <div className="text-[10px] text-slate-400 font-mono">Source: {f.source}</div>
                        </div>
                        <SeverityBadge severity={getSeverityLevel(f.severity)} />
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Evidence Section */}
              {report.evidence && report.evidence.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 font-sans">
                    <ShieldCheck className="w-4 h-4 text-teal-700" />
                    Persisted Evidence ({report.evidence.length})
                  </h3>
                  <div className="border border-slate-200 rounded-lg overflow-hidden shadow-2xs">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="bg-slate-50 text-[11px] font-semibold text-slate-600 border-b border-slate-200">
                        <tr>
                          <th className="py-2.5 px-3">Feature</th>
                          <th className="py-2.5 px-3">Observed Value</th>
                          <th className="py-2.5 px-3">Interpretation</th>
                          <th className="py-2.5 px-3 text-right">Contribution</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 bg-white">
                        {report.evidence.map((ev, idx) => (
                          <tr key={idx} className="hover:bg-slate-50/50">
                            <td className="py-2 px-3 font-mono font-medium text-slate-800">{ev.feature || ev.name}</td>
                            <td className="py-2 px-3 font-mono text-slate-600">{String(ev.value ?? ev.observed_value)}</td>
                            <td className="py-2 px-3 text-slate-600">{ev.interpretation || ev.rule_summary || '--'}</td>
                            <td className="py-2 px-3 text-right font-mono font-semibold text-slate-800">
                              {ev.score !== undefined ? `${Math.round(Number(ev.score) * 100)}%` : '--'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {/* Recommended Action */}
              <section className="space-y-2">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 font-sans">
                  <Check className="w-4 h-4 text-emerald-600" />
                  Recommended Operational Action
                </h3>
                <div className="p-4 rounded-lg bg-emerald-50/50 border border-emerald-200 text-emerald-900 text-xs font-medium leading-relaxed shadow-2xs">
                  {report.recommended_action}
                </div>
              </section>

              {/* SOC Limitations & Disclaimers */}
              {report.limitations && report.limitations.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 font-sans">
                    <Info className="w-4 h-4 text-slate-400" />
                    Analytical Limitations & Scope
                  </h3>
                  <ul className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 space-y-1.5 list-disc list-inside">
                    {report.limitations.map((lim, i) => (
                      <li key={i}>{lim}</li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-100 bg-slate-50/60 flex items-center justify-between text-xs text-slate-500">
          <div>UniGuard Passive Security Operations Center &bull; Confidential Incident Data</div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition-colors shadow-2xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
