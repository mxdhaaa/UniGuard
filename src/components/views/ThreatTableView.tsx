import React, { useState } from 'react';
import type { ThreatDetection } from '../../types/uniguard';
import { SeverityBadge } from '../common/SeverityBadge';
import { Search, Filter, Eye } from 'lucide-react';

interface ThreatTableViewProps {
  threats: ThreatDetection[];
  onSelectThreat: (threat: ThreatDetection) => void;
}

export const ThreatTableView: React.FC<ThreatTableViewProps> = ({
  threats,
  onSelectThreat,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredThreats = threats.filter((t) => {
    if (filterSeverity !== 'ALL' && t.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && t.status !== filterStatus) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        t.threat.toLowerCase().includes(q) ||
        t.sourceIp.includes(q) ||
        t.destIp.includes(q) ||
        t.protocol.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden font-sans">
      <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 flex-1 min-w-[240px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by threat, IP, or protocol..."
              className="w-full pl-8 pr-3 py-1 bg-white border border-slate-200 rounded text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-teal-600 font-sans"
            />
          </div>

          <div className="flex items-center gap-1 text-slate-500">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-medium">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-white border border-slate-200 rounded py-1 px-2 text-slate-800 text-xs focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1 text-slate-500">
            <span className="font-medium">Status:</span>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-white border border-slate-200 rounded py-1 px-2 text-slate-800 text-xs focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="MITIGATED">Mitigated</option>
              <option value="WHITELISTED">Whitelisted</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>
        </div>

        <div className="text-slate-500 text-xs font-mono">
          Showing <span className="font-semibold text-slate-800">{filteredThreats.length}</span> of {threats.length} detections
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs enterprise-table">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <th className="py-2.5 px-4">Severity</th>
              <th className="py-2.5 px-4">Threat</th>
              <th className="py-2.5 px-4">Confidence</th>
              <th className="py-2.5 px-4 font-mono">Source</th>
              <th className="py-2.5 px-4 font-mono">Destination</th>
              <th className="py-2.5 px-4">Protocol</th>
              <th className="py-2.5 px-4">Detected</th>
              <th className="py-2.5 px-4">Status</th>
              <th className="py-2.5 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 font-sans">
            {filteredThreats.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400 bg-slate-50/30">
                  <p className="text-xs font-medium">No security detections match the selected filter criteria.</p>
                </td>
              </tr>
            ) : (
              filteredThreats.map((threat) => (
                <tr
                  key={threat.id}
                  onClick={() => onSelectThreat(threat)}
                  className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                >
                  <td className="py-2.5 px-4">
                    <SeverityBadge severity={threat.severity} size="sm" />
                  </td>
                  <td className="py-2.5 px-4 font-semibold text-slate-900 group-hover:text-teal-900 transition-colors">
                    {threat.threat}
                    <span className="block text-[10px] font-normal text-slate-500">{threat.category}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="font-mono font-semibold text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 text-[11px]">
                      {threat.confidence}%
                    </span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-800">
                    {threat.sourceIp}
                    <span className="text-slate-400 text-[10px] font-sans">:{threat.sourcePort}</span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-800">
                    {threat.destIp}
                    <span className="text-slate-400 text-[10px] font-sans">:{threat.destPort}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="font-mono text-[11px] text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">
                      {threat.protocol}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-500 font-mono text-[11px]">
                    {threat.detectedAgo}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className={`inline-flex items-center text-[10px] font-mono font-medium px-2 py-0.5 rounded uppercase ${
                      threat.status === 'ACTIVE' ? 'bg-amber-50 text-amber-800 border border-amber-200' :
                      threat.status === 'INVESTIGATING' ? 'bg-blue-50 text-blue-800 border border-blue-200' :
                      threat.status === 'MITIGATED' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' :
                      'bg-slate-100 text-slate-600 border border-slate-200'
                    }`}>
                      {threat.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectThreat(threat);
                      }}
                      className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-teal-900 font-medium bg-slate-100 hover:bg-slate-200 px-2 py-1 rounded transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5 text-slate-500" />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
