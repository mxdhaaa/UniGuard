/**
 * UniGuard Security Alerts View (Milestone 14)
 * 
 * Filterable, paginated SOC alert view backed by:
 * GET /api/dashboard/alerts
 * With real-time WebSocket alert streaming via useAlertSocket.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldAlert, 
  Radio, 
  Filter, 
  RefreshCw, 
  ChevronLeft, 
  ChevronRight, 
  SearchCheck, 
  FileText, 
  AlertTriangle,
  RotateCcw,
  Bell,
  CheckCircle2
} from 'lucide-react';
import { 
  uniguardApi, 
  type DashboardAlertSummary, 
  type PaginationMeta, 
  type AlertFilterParams 
} from '../../api/client';
import { useAlertSocket } from '../../api/useAlertSocket';
import { SeverityBadge } from '../common/SeverityBadge';
import type { SeverityLevel } from '../../types/uniguard';

interface AlertsViewProps {
  onInvestigateAlert: (alertId: string) => void;
  onReportAlert: (alertId: string) => void;
  onInvestigateFlow?: (flowId: string) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  onInvestigateAlert,
  onReportAlert,
  onInvestigateFlow,
}) => {
  const [alerts, setAlerts] = useState<DashboardAlertSummary[]>([]);
  const [meta, setMeta] = useState<PaginationMeta>({
    page: 1,
    page_size: 25,
    total_items: 0,
    total_pages: 0,
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters state
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(25);
  const [severity, setSeverity] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [threatType, setThreatType] = useState<string>('');

  // WebSocket Live alerts integration
  const [incomingLiveAlerts, setIncomingLiveAlerts] = useState<DashboardAlertSummary[]>([]);
  const { status: socketStatus, reconnect } = useAlertSocket({
    onAlertReceived: (newAlert) => {
      setIncomingLiveAlerts((prev) => [newAlert, ...prev.slice(0, 4)]);
    },
  });

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AlertFilterParams = {
        page,
        page_size: pageSize,
      };
      if (severity) params.severity = severity;
      if (statusFilter) params.status = statusFilter;
      if (threatType) params.threat_type = threatType;

      const response = await uniguardApi.getAlerts(params);
      setAlerts(response.data);
      setMeta(response.meta);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch security alerts.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, statusFilter, threatType]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleResetFilters = () => {
    setSeverity('');
    setStatusFilter('');
    setThreatType('');
    setPage(1);
  };

  const getSeverityLevel = (sevStr?: string): SeverityLevel => {
    const s = (sevStr || '').toUpperCase();
    if (s === 'CRITICAL') return 'CRITICAL';
    if (s === 'HIGH') return 'HIGH';
    if (s === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  };

  const hasActiveFilters = severity || statusFilter || threatType;

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-600" />
            Security Incident Alerts
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Persisted high-risk and critical incidents triggered by the Evidence and Risk Engines.
          </p>
        </div>

        <div className="flex items-center gap-3 self-start sm:self-auto">
          {/* WebSocket Status Indicator */}
          <div 
            onClick={() => socketStatus !== 'connected' && reconnect()}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer select-none transition-colors ${
              socketStatus === 'connected'
                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                : socketStatus === 'reconnecting' || socketStatus === 'connecting'
                ? 'bg-amber-50 text-amber-800 border-amber-200 animate-pulse'
                : 'bg-slate-100 text-slate-600 border-slate-200 hover:bg-slate-200'
            }`}
            title={socketStatus === 'connected' ? 'WebSocket stream active' : 'Click to reconnect alert stream'}
          >
            <Radio className={`w-3.5 h-3.5 ${socketStatus === 'connected' ? 'text-emerald-600' : 'text-slate-400'}`} />
            <span className="capitalize">{socketStatus === 'connected' ? 'Live Stream Active' : socketStatus}</span>
          </div>

          <button
            onClick={() => fetchAlerts()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors shadow-2xs disabled:opacity-50"
            title="Refresh Alerts"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-teal-600' : 'text-slate-500'}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Live Incoming Alert Notification Banner */}
      {incomingLiveAlerts.length > 0 && (
        <div className="p-3 rounded-lg bg-amber-50/80 border border-amber-200 text-amber-900 shadow-2xs space-y-2 animate-in fade-in duration-200">
          <div className="flex items-center justify-between text-xs font-bold text-amber-950">
            <div className="flex items-center gap-1.5">
              <Bell className="w-4 h-4 text-amber-700 animate-bounce" />
              <span>Real-Time Ingested Alert ({incomingLiveAlerts.length})</span>
            </div>
            <button
              onClick={() => setIncomingLiveAlerts([])}
              className="text-[11px] text-amber-700 hover:text-amber-950 font-normal"
            >
              Dismiss
            </button>
          </div>
          <div className="space-y-1.5">
            {incomingLiveAlerts.map((liveAlert, idx) => (
              <div 
                key={`${liveAlert.alert_id}-${idx}`}
                className="p-2 rounded bg-white border border-amber-200/60 flex items-center justify-between text-xs gap-3"
              >
                <div className="flex items-center gap-2 truncate">
                  <SeverityBadge severity={getSeverityLevel(liveAlert.severity)} size="sm" />
                  <span className="font-mono font-bold text-slate-800">{liveAlert.threat_type}</span>
                  <span className="text-slate-600 truncate">{liveAlert.summary}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => onInvestigateAlert(liveAlert.alert_id)}
                    className="px-2 py-0.5 text-[11px] font-semibold rounded bg-teal-50 hover:bg-teal-100 text-teal-800 border border-teal-200 transition-colors"
                  >
                    Investigate
                  </button>
                  <button
                    onClick={() => onReportAlert(liveAlert.alert_id)}
                    className="px-2 py-0.5 text-[11px] font-medium rounded bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors"
                  >
                    Report
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="p-3.5 bg-white border border-slate-200 rounded-lg shadow-2xs space-y-3">
        <div className="flex items-center justify-between text-xs font-semibold text-slate-600">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span>Filter Criteria</span>
          </div>
          {hasActiveFilters && (
            <button
              onClick={handleResetFilters}
              className="flex items-center gap-1 text-[11px] text-teal-700 hover:text-teal-900 font-medium transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Filters</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          {/* Threat Type */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Threat Type</label>
            <select
              value={threatType}
              onChange={(e) => {
                setThreatType(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-sans text-xs focus:outline-teal-600 focus:bg-white"
            >
              <option value="">All Types</option>
              <option value="BENIGN">BENIGN</option>
              <option value="DOS_DDOS">DOS_DDOS</option>
              <option value="PORT_SCAN">PORT_SCAN</option>
              <option value="BOTNET_C2">BOTNET_C2</option>
              <option value="BRUTE_FORCE">BRUTE_FORCE</option>
              <option value="WEB_ATTACK">WEB_ATTACK</option>
              <option value="INFILTRATION">INFILTRATION</option>
            </select>
          </div>

          {/* Severity */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-sans text-xs focus:outline-teal-600 focus:bg-white"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Status */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Alert Status</label>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-sans text-xs focus:outline-teal-600 focus:bg-white"
            >
              <option value="">All Statuses</option>
              <option value="NEW">NEW</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="DISMISSED">DISMISSED</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Alerts Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-2xs overflow-hidden">
        {loading && (
          <div className="py-20 flex flex-col items-center justify-center gap-2 text-slate-400">
            <RefreshCw className="w-7 h-7 animate-spin text-teal-600" />
            <p className="text-xs font-medium">Loading security alerts from UniGuard database...</p>
          </div>
        )}

        {error && !loading && (
          <div className="p-6 text-center space-y-3">
            <div className="inline-flex p-3 rounded-full bg-red-50 text-red-600 border border-red-200">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">Error Loading Alerts</h3>
            <p className="text-xs text-red-600 max-w-md mx-auto">{error}</p>
            <button
              onClick={() => fetchAlerts()}
              className="px-3 py-1.5 text-xs font-semibold rounded-md bg-teal-800 text-white hover:bg-teal-900 transition-colors shadow-2xs"
            >
              Retry
            </button>
          </div>
        )}

        {!loading && !error && alerts.length === 0 && (
          <div className="py-16 text-center space-y-3">
            <div className="inline-flex p-3 rounded-full bg-slate-50 text-slate-400 border border-slate-200">
              <CheckCircle2 className="w-6 h-6 text-emerald-500" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">No Alerts Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              {hasActiveFilters
                ? 'No alerts matched your active filter criteria. Try adjusting filters.'
                : 'No alerts have been generated yet. Active network threats will appear here.'}
            </p>
            {hasActiveFilters && (
              <button
                onClick={handleResetFilters}
                className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors shadow-2xs"
              >
                Clear Filters
              </button>
            )}
          </div>
        )}

        {!loading && !error && alerts.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50/80 text-[11px] font-semibold text-slate-600 border-b border-slate-200 uppercase tracking-wider select-none">
                <tr>
                  <th className="py-2.5 px-3">Created / Alert ID</th>
                  <th className="py-2.5 px-3">Flow ID</th>
                  <th className="py-2.5 px-3">Threat Type</th>
                  <th className="py-2.5 px-3">Risk & Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Summary</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {alerts.map((al) => (
                  <tr key={al.alert_id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-2.5 px-3">
                      <div className="font-mono text-[11px] text-slate-500">
                        {al.created_at ? new Date(al.created_at).toLocaleString() : '--'}
                      </div>
                      <div className="font-mono text-[11px] font-bold text-slate-800 truncate max-w-[130px]" title={al.alert_id}>
                        {al.alert_id}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px]">
                      {onInvestigateFlow ? (
                        <button
                          onClick={() => onInvestigateFlow(al.flow_id)}
                          className="text-teal-700 hover:text-teal-900 underline truncate max-w-[120px] block"
                          title={`Investigate Flow ${al.flow_id}`}
                        >
                          {al.flow_id}
                        </button>
                      ) : (
                        <span className="text-slate-600 truncate max-w-[120px] block" title={al.flow_id}>
                          {al.flow_id}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono font-bold text-slate-800">
                      {al.threat_type}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-800">
                          {al.risk_score}
                        </span>
                        <SeverityBadge severity={getSeverityLevel(al.severity)} size="sm" />
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="inline-block px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                        {al.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-600 max-w-xs truncate" title={al.summary}>
                      {al.summary}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => onInvestigateAlert(al.alert_id)}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-semibold rounded bg-teal-50 hover:bg-teal-100 text-teal-800 border border-teal-200 transition-colors shadow-2xs"
                          title="Deep Dive Investigation"
                        >
                          <SearchCheck className="w-3 h-3" />
                          <span>Investigate</span>
                        </button>
                        <button
                          onClick={() => onReportAlert(al.alert_id)}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 transition-colors shadow-2xs"
                          title="Generate Incident Report"
                        >
                          <FileText className="w-3 h-3 text-slate-500" />
                          <span>Report</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="px-4 py-3 bg-slate-50/80 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <span>Rows per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="px-2 py-1 rounded border border-slate-200 bg-white font-mono text-xs focus:outline-teal-600"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <span className="text-slate-400 font-mono">
              &bull; Total: {meta.total_items} alerts
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="font-mono text-slate-500">
              Page {meta.page} of {Math.max(1, meta.total_pages)}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="p-1 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 disabled:opacity-40 disabled:pointer-events-none transition-colors"
                aria-label="Previous page"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage((p) => (meta.total_pages ? Math.min(meta.total_pages, p + 1) : p + 1))}
                disabled={page >= meta.total_pages || loading}
                className="p-1 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 disabled:opacity-40 disabled:pointer-events-none transition-colors"
                aria-label="Next page"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
