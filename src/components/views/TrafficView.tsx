import React, { useState } from 'react';
import type { NetworkTrafficPoint } from '../../types/uniguard';
import { Search } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface TrafficViewProps {
  timeseries: NetworkTrafficPoint[];
}

export const TrafficView: React.FC<TrafficViewProps> = ({ timeseries }) => {
  const [filterProtocol, setFilterProtocol] = useState<string>('ALL');
  const [searchIP, setSearchIP] = useState<string>('');

  const sampleFlows = [
    { id: 'FL-9901', src: '10.24.8.21', dst: '185.220.101.5', proto: 'TCP', port: 443, pkts: 482, bytes: '1.42 MB', sni: 'api.telemetry-update-check.net', status: 'FLAGGED' },
    { id: 'FL-9902', src: '10.24.4.109', dst: '91.218.114.22', proto: 'UDP', port: 443, pkts: 14890, bytes: '128.4 MB', sni: 'cdn-static-backup-cloud.org', status: 'FLAGGED' },
    { id: 'FL-9903', src: '10.24.12.84', dst: '10.24.0.2', proto: 'DNS', port: 53, pkts: 2150, bytes: '480 KB', sni: 'ns1.auth-tunnel-domain.com', status: 'FLAGGED' },
    { id: 'FL-9904', src: '10.24.1.15', dst: '142.250.190.46', proto: 'HTTPS', port: 443, pkts: 920, bytes: '4.8 MB', sni: 'www.google.com', status: 'NORMAL' },
    { id: 'FL-9905', src: '10.24.3.40', dst: '13.107.42.14', proto: 'HTTPS', port: 443, pkts: 1840, bytes: '12.1 MB', sni: 'teams.microsoft.com', status: 'NORMAL' },
    { id: 'FL-9906', src: '10.24.8.44', dst: '10.24.10.12', proto: 'TCP', port: 3389, pkts: 340, bytes: '45 KB', sni: '-', status: 'FLAGGED' },
    { id: 'FL-9907', src: '10.24.2.80', dst: '151.101.65.140', proto: 'HTTPS', port: 443, pkts: 310, bytes: '1.2 MB', sni: 'github.com', status: 'NORMAL' },
  ];

  return (
    <div className="space-y-6 font-sans">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Traffic Telemetry</h1>
          <span className="text-[10px] font-mono font-semibold bg-slate-100 text-slate-700 border border-slate-200 px-2 py-0.5 rounded">
            DEMO TRAFFIC CAPTURE
          </span>
        </div>
        <p className="text-xs text-slate-500 mt-1">
          Flow metadata inspector for passive network inspection <code className="font-mono text-slate-700 font-semibold bg-slate-100 px-1 rounded">eth0</code> (Awaiting live sensor).
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Demo Bandwidth Throughput</h3>
          <span className="text-xs font-mono text-slate-500">Sample peak: 1.74 GB/s</span>
        </div>
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeseries}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
              <XAxis dataKey="time" stroke="#94A3B8" fontSize={11} tickLine={false} />
              <YAxis stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} tickFormatter={(v) => `${v} GB/s`} />
              <Tooltip contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#CBD5E1', borderRadius: '6px', fontSize: '12px' }} />
              <Area type="monotone" dataKey="gbps" stroke="#0D9488" strokeWidth={2} fill="#F0FDFA" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchIP}
                onChange={(e) => setSearchIP(e.target.value)}
                placeholder="Filter flow IP or SNI host..."
                className="pl-8 pr-3 py-1 bg-white border border-slate-200 rounded text-xs focus:outline-none"
              />
            </div>
            <select
              value={filterProtocol}
              onChange={(e) => setFilterProtocol(e.target.value)}
              className="bg-white border border-slate-200 rounded py-1 px-2 text-xs"
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="DNS">DNS</option>
              <option value="UDP">UDP</option>
              <option value="HTTPS">HTTPS</option>
            </select>
          </div>
          <span className="text-slate-500 font-mono text-xs">Sample Flow Inspector</span>
        </div>

        <table className="w-full text-left border-collapse text-xs enterprise-table">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <th className="py-2.5 px-4">Flow ID</th>
              <th className="py-2.5 px-4 font-mono">Source IP</th>
              <th className="py-2.5 px-4 font-mono">Destination IP</th>
              <th className="py-2.5 px-4">Protocol</th>
              <th className="py-2.5 px-4">TLS SNI / Host</th>
              <th className="py-2.5 px-4">Packets</th>
              <th className="py-2.5 px-4">Bytes</th>
              <th className="py-2.5 px-4">Inspection Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 font-mono">
            {sampleFlows.map((flow) => (
              <tr key={flow.id} className="hover:bg-slate-50/80">
                <td className="py-2.5 px-4 text-slate-600 font-semibold">{flow.id}</td>
                <td className="py-2.5 px-4 text-slate-900">{flow.src}</td>
                <td className="py-2.5 px-4 text-slate-900">{flow.dst}:{flow.port}</td>
                <td className="py-2.5 px-4 font-sans">
                  <span className="bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded text-[11px] font-semibold">{flow.proto}</span>
                </td>
                <td className="py-2.5 px-4 text-slate-700 font-sans">{flow.sni}</td>
                <td className="py-2.5 px-4 text-slate-800">{flow.pkts.toLocaleString()}</td>
                <td className="py-2.5 px-4 text-slate-800">{flow.bytes}</td>
                <td className="py-2.5 px-4 font-sans">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                    flow.status === 'FLAGGED' ? 'bg-amber-50 text-amber-800 border border-amber-200' : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                  }`}>
                    {flow.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
