import React from 'react';
import type { PassiveSensorMetrics } from '../../types/uniguard';
import { Server, Activity, Cpu, HardDrive } from 'lucide-react';

interface SystemViewProps {
  sensor: PassiveSensorMetrics;
}

export const SystemView: React.FC<SystemViewProps> = ({ sensor }) => {
  return (
    <div className="space-y-6 font-sans">
      <div>
        <h1 className="text-xl font-bold text-slate-900 tracking-tight">System & Sensor Diagnostics</h1>
        <p className="text-xs text-slate-500 mt-1">
          Hardware resource status and passive network sensor driver configuration.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Sensor Mode</span>
            <Server className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-400" />
            <span className="text-sm font-bold text-slate-900 font-mono">{sensor.status}</span>
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Input: {sensor.captureEngine}</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Packet Drop Rate</span>
            <Activity className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-sm font-bold text-slate-700 font-mono">
            {sensor.dropRatePercent}
          </div>
          <span className="text-[11px] text-slate-500 font-medium mt-1 block">Awaiting sensor benchmark</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>CPU Core Load</span>
            <Cpu className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-sm font-bold text-slate-700 font-mono">
            {sensor.cpuUsagePercent}
          </div>
          <span className="text-[11px] text-slate-500 font-medium mt-1 block">Awaiting sensor telemetry</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Ring Buffer Pool</span>
            <HardDrive className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-sm font-bold text-slate-700 font-mono">
            {sensor.bufferUtilizationPercent}
          </div>
          <span className="text-[11px] text-slate-500 font-medium mt-1 block">Awaiting sensor telemetry</span>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Passive Sensor Configuration</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="bg-slate-50 p-3 rounded border border-slate-200">
            <span className="text-slate-500 text-[11px] font-sans block">Node / Host</span>
            <span className="font-bold text-slate-900">uniguard-sensor-01</span>
          </div>
          <div className="bg-slate-50 p-3 rounded border border-slate-200">
            <span className="text-slate-500 text-[11px] font-sans block">Ingestion Engine</span>
            <span className="font-bold text-slate-900">PCAP / Flow Input</span>
          </div>
          <div className="bg-slate-50 p-3 rounded border border-slate-200">
            <span className="text-slate-500 text-[11px] font-sans block">Sensor Status</span>
            <span className="font-bold text-slate-700">Awaiting live traffic</span>
          </div>
        </div>
      </div>
    </div>
  );
};
