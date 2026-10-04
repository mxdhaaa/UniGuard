/**
 * UniGuard Network Flows View (Milestone 14)
 * 
 * Server-side paginated & filtered SOC flow view backed by:
 * GET /api/dashboard/flows
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Activity, 
  Search, 
  Filter, 
  RefreshCw, 
  ChevronLeft, 
  ChevronRight, 
  SearchCheck, 
  FileText, 
  AlertTriangle,
  RotateCcw
} from 'lucide-react';
import { 
  uniguardApi, 
  type DashboardFlowSummary, 
  type PaginationMeta, 
  type FlowFilterParams 
} from '../../api/client';
import { SeverityBadge } from '../common/SeverityBadge';
import type { SeverityLevel } from '../../types/uniguard';

interface FlowsViewProps {
  onInvestigateFlow: (flowId: string) => void;
  onReportFlow: (flowId: string) => void;
}

export const FlowsView: React.FC<FlowsViewProps> = ({
  onInvestigateFlow,
  onReportFlow,
}) => {
  const [flows, setFlows] = useState<DashboardFlowSummary[]>([]);
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
  const [threatType, setThreatType] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [anomalyFilter, setAnomalyFilter] = useState<string>(''); // '', 'true', 'false'
  const [sourceIp, setSourceIp] = useState<string>('');
  const [destIp, setDestIp] = useState<string>('');

  const fetchFlows = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: FlowFilterParams = {
        page,
        page_size: pageSize,
      };
      if (threatType) params.threat_type = threatType;
      if (severity) params.severity = severity;
      if (anomalyFilter === 'true') params.is_anomaly = true;
      if (anomalyFilter === 'false') params.is_anomaly = false;
      if (sourceIp.trim()) params.source_ip = sourceIp.trim();
      if (destIp.trim()) params.destination_ip = destIp.trim();

      const response = await uniguardApi.getFlows(params);
      setFlows(response.data);
      setMeta(response.meta);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch network flows.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, threatType, severity, anomalyFilter, sourceIp, destIp]);

  useEffect(() => {
    fetchFlows();
  }, [fetchFlows]);

  const handleResetFilters = () => {
    setThreatType('');
    setSeverity('');
    setAnomalyFilter('');
    setSourceIp('');
    setDestIp('');
    setPage(1);
  };

  const getSeverityLevel = (sevStr?: string): SeverityLevel => {
    const s = (sevStr || '').toUpperCase();
    if (s === 'CRITICAL') return 'CRITICAL';
    if (s === 'HIGH') return 'HIGH';
    if (s === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  };

  const hasActiveFilters = threatType || severity || anomalyFilter || sourceIp || destIp;

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Activity className="w-5 h-5 text-teal-700" />
            Network Traffic Flows
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Persisted passive network flows classified by ML and scored by the UniGuard Risk Engine.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={() => fetchFlows()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors shadow-2xs disabled:opacity-50"
            title="Refresh Flows"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-teal-600' : 'text-slate-500'}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

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

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 text-xs">
          {/* Source IP */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Source IP</label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.10"
              value={sourceIp}
              onChange={(e) => {
                setSourceIp(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-mono text-xs focus:outline-teal-600 focus:bg-white"
            />
          </div>

          {/* Dest IP */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Dest IP</label>
            <input
              type="text"
              placeholder="e.g. 10.0.0.1"
              value={destIp}
              onChange={(e) => {
                setDestIp(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-mono text-xs focus:outline-teal-600 focus:bg-white"
            />
          </div>

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

          {/* Anomaly */}
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">Anomaly</label>
            <select
              value={anomalyFilter}
              onChange={(e) => {
                setAnomalyFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50/50 font-sans text-xs focus:outline-teal-600 focus:bg-white"
            >
              <option value="">All Statuses</option>
              <option value="true">Anomalous Only</option>
              <option value="false">Normal Only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Flow Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-2xs overflow-hidden">
        {loading && (
          <div className="py-20 flex flex-col items-center justify-center gap-2 text-slate-400">
            <RefreshCw className="w-7 h-7 animate-spin text-teal-600" />
            <p className="text-xs font-medium">Loading network flows from UniGuard database...</p>
          </div>
        )}

        {error && !loading && (
          <div className="p-6 text-center space-y-3">
            <div className="inline-flex p-3 rounded-full bg-red-50 text-red-600 border border-red-200">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">Error Loading Flows</h3>
            <p className="text-xs text-red-600 max-w-md mx-auto">{error}</p>
            <button
              onClick={() => fetchFlows()}
              className="px-3 py-1.5 text-xs font-semibold rounded-md bg-teal-800 text-white hover:bg-teal-900 transition-colors shadow-2xs"
            >
              Retry
            </button>
          </div>
        )}

        {!loading && !error && flows.length === 0 && (
          <div className="py-16 text-center space-y-3">
            <div className="inline-flex p-3 rounded-full bg-slate-50 text-slate-400 border border-slate-200">
              <Search className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">No Flows Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              {hasActiveFilters
                ? 'No network flows matched your active filter criteria. Try adjusting or clearing filters.'
                : 'No network flows have been ingested into the UniGuard database yet.'}
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

        {!loading && !error && flows.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50/80 text-[11px] font-semibold text-slate-600 border-b border-slate-200 uppercase tracking-wider select-none">
                <tr>
                  <th className="py-2.5 px-3">Timestamp / Flow ID</th>
                  <th className="py-2.5 px-3">Endpoints (Src &rarr; Dst)</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Threat Type</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Anomaly</th>
                  <th className="py-2.5 px-3">Risk & Severity</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {flows.map((flow) => (
                  <tr key={flow.flow_id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-2.5 px-3">
                      <div className="font-mono text-[11px] text-slate-500">
                        {flow.timestamp ? new Date(flow.timestamp).toLocaleString() : '--'}
                      </div>
                      <div className="font-mono text-[11px] font-bold text-slate-800 truncate max-w-[140px]" title={flow.flow_id}>
                        {flow.flow_id}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px]">
                      <div className="text-slate-800 font-medium">
                        {flow.source_ip}:{flow.source_port}
                      </div>
                      <div className="text-slate-500">
                        &rarr; {flow.destination_ip}:{flow.destination_port}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-700 font-medium">
                      {flow.protocol}
                    </td>
                    <td className="py-2.5 px-3 font-mono font-bold text-slate-800">
                      {flow.threat_type}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-700">
                      {(flow.classifier_confidence * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                          flow.is_anomaly
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {flow.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {Number(flow.anomaly_score).toFixed(3)}
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-800">
                          {flow.risk_score}
                        </span>
                        <SeverityBadge severity={getSeverityLevel(flow.severity)} size="sm" />
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => onInvestigateFlow(flow.flow_id)}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-semibold rounded bg-teal-50 hover:bg-teal-100 text-teal-800 border border-teal-200 transition-colors shadow-2xs"
                          title="Deep Dive Investigation"
                        >
                          <SearchCheck className="w-3 h-3" />
                          <span>Investigate</span>
                        </button>
                        <button
                          onClick={() => onReportFlow(flow.flow_id)}
                          className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 transition-colors shadow-2xs"
                          title="Generate SOC Incident Report"
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
              &bull; Total: {meta.total_items} flows
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
