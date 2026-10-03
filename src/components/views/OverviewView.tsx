import React from 'react';
import type { ThreatDetection, NetworkTrafficPoint, ModelMetric } from '../../types/uniguard';
import { MetricCard } from '../common/MetricCard';
import { ThreatTableView } from './ThreatTableView';
import { Activity, ShieldAlert, Cpu, ArrowUpRight, BarChart2 } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

interface OverviewViewProps {
  threats: ThreatDetection[];
  trafficTimeseries: NetworkTrafficPoint[];
  models: ModelMetric[];
  onSelectThreat: (threat: ThreatDetection) => void;
  onNavigateToTab: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  threats,
  trafficTimeseries,
  onSelectThreat,
  onNavigateToTab,
}) => {
  const activeThreats = threats.filter((t) => t.status === 'NEW' || t.status === 'ACTIVE' || t.status === 'INVESTIGATING');
  const criticalCount = activeThreats.filter((t) => t.severity === 'CRITICAL').length;
  const highCount = activeThreats.filter((t) => t.severity === 'HIGH').length;

  // MVP threat categories supported
  const threatCategories = [
    { category: 'C2 Beaconing', count: threats.filter((t) => t.category === 'C2 Beaconing').length, severity: 'HIGH' },
    { category: 'DDoS', count: threats.filter((t) => t.category === 'DDoS').length, severity: 'CRITICAL' },
    { category: 'DNS Tunnelling / DGA', count: threats.filter((t) => t.category === 'DNS Tunnelling / DGA').length, severity: 'HIGH' },
    { category: 'Reconnaissance / Port Scanning', count: threats.filter((t) => t.category === 'Reconnaissance / Port Scanning').length, severity: 'MEDIUM' },
  ];

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">System Overview</h1>
            <span className="text-[10px] font-mono font-semibold bg-amber-100 text-amber-800 border border-amber-200 px-2 py-0.5 rounded">
              DEMO DATA & REPLAY MODE
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Passive network inspection, threat telemetry, and detector performance.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">Sensor Interface:</span>
          <span className="font-mono text-xs font-semibold text-slate-800 bg-white border border-slate-200 px-2.5 py-1 rounded">
            eth0 (Passive sensor)
          </span>
        </div>
      </div>

      {/* Top-Level Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Network Traffic"
          value="1.68 GB/s"
          subtext="Demo traffic (Awaiting live sensor)"
          change="Demo stream"
          changeType="neutral"
          icon={Activity}
        />

        <MetricCard
          title="Flow Rate"
          value="5,480"
          subtext="Flows per second (Demo replay)"
          change="Replay rate"
          changeType="neutral"
          badgeText="Demo traffic"
        />

        <MetricCard
          title="Active Threats"
          value={activeThreats.length}
          subtext={`${criticalCount} Critical, ${highCount} High (Demo alerts)`}
          change={activeThreats.length > 0 ? 'Action Recommended' : 'All Clear'}
          changeType={activeThreats.length > 0 ? 'negative' : 'positive'}
          icon={ShieldAlert}
        />

        <MetricCard
          title="High-Risk Detections"
          value={threats.filter((t) => t.severity === "CRITICAL" || t.severity === "HIGH").length}
          subtext="Critical and high-severity detections"
          change="Pending eval"
          changeType="neutral"
          badgeText="Model: Pending evaluation"
        />
      </div>

      {/* Middle Grid: Traffic Timeseries & Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Traffic Activity Area Chart */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Traffic Activity</h3>
                <span className="text-[10px] font-mono text-slate-400">Demo Replay Timeseries</span>
              </div>
              <p className="text-[11px] text-slate-500">Bandwidth throughput (GB/s) & flow rate over sample window</p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-teal-700" />
                <span className="text-slate-600 text-[11px]">Throughput (GB/s)</span>
              </div>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficTimeseries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorGbps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0D9488" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#0D9488" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                <XAxis dataKey="time" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={{ stroke: '#E2E8F0' }} />
                <YAxis stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} tickFormatter={(val) => `${val} GB/s`} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#CBD5E1', borderRadius: '6px', fontSize: '12px', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}
                  itemStyle={{ color: '#0F172A', fontWeight: 600 }}
                  formatter={(val: any) => [`${val} GB/s (Demo)`, 'Throughput']}
                />
                <Area type="monotone" dataKey="gbps" stroke="#0D9488" strokeWidth={2} fillOpacity={1} fill="url(#colorGbps)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution Bar Chart */}
        <div className="lg:col-span-1 bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Threat Distribution</h3>
              <p className="text-[11px] text-slate-500">MVP Detection Categories</p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatCategories} layout="vertical" margin={{ top: 10, right: 10, left: 10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" horizontal={false} />
                <XAxis type="number" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis dataKey="category" type="category" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} width={130} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#CBD5E1', borderRadius: '6px', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#475569" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Recent Detections Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Recent Threat Detections</h2>
            <span className="text-[10px] font-mono text-slate-500">(Demo scenario callset)</span>
          </div>
          <button
            onClick={() => onNavigateToTab('threats')}
            className="text-xs text-teal-800 hover:text-teal-900 font-semibold flex items-center gap-1"
          >
            <span>View All Detections</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <ThreatTableView
          threats={threats}
          onSelectThreat={onSelectThreat}
        />
      </div>

      {/* Detection Performance Summary Bar */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-slate-100 flex items-center justify-center text-slate-700 font-bold shrink-0">
            <Cpu className="w-4 h-4 text-teal-700" />
          </div>
          <div>
            <span className="font-semibold text-slate-900 block">Avg Inference Latency</span>
            <span className="text-slate-500 font-mono">Awaiting benchmark</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-slate-100 flex items-center justify-center text-slate-700 font-bold shrink-0">
            <Activity className="w-4 h-4 text-teal-700" />
          </div>
          <div>
            <span className="font-semibold text-slate-900 block">Model Evaluation</span>
            <span className="text-slate-500 font-mono">Pending evaluation</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-slate-100 flex items-center justify-center text-slate-700 font-bold shrink-0">
            <BarChart2 className="w-4 h-4 text-teal-700" />
          </div>
          <div>
            <span className="font-semibold text-slate-900 block">Active Rule Heuristics</span>
            <span className="text-slate-500 font-mono">4 MVP Detectors active</span>
          </div>
        </div>
      </div>

    </div>
  );
};

