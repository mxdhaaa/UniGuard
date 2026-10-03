import React from 'react';
import { Search, Radio, Bell, RefreshCw, Layers } from 'lucide-react';

interface HeaderProps {
  isLive: boolean;
  onToggleLive: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  notificationCount: number;
  onNotificationClick: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  isLive,
  onToggleLive,
  searchQuery,
  onSearchChange,
  notificationCount,
  onNotificationClick,
}) => {
  return (
    <header className="h-14 bg-white border-b border-slate-200 px-6 flex items-center justify-between sticky top-0 z-10 font-sans">
      {/* Search Input & Scope */}
      <div className="flex items-center gap-4 flex-1 max-w-xl">
        <div className="relative w-full max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search flows, IP address (10.24.x.x), threat, or protocol..."
            className="w-full pl-9 pr-4 py-1.5 bg-slate-50 border border-slate-200 rounded text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-teal-600 font-sans"
          />
        </div>

        <div className="hidden md:flex items-center gap-1.5 text-xs text-slate-500 bg-slate-100/80 px-2.5 py-1 rounded border border-slate-200 shrink-0">
          <Layers className="w-3.5 h-3.5 text-slate-400" />
          <span className="font-mono text-[11px] text-slate-700">Subnet: 10.24.0.0/16</span>
        </div>
      </div>

      {/* Status Bar Controls */}
      <div className="flex items-center gap-4">
        {/* Passive Sensor Status */}
        <div className="flex items-center gap-2 text-xs border-r border-slate-200 pr-4">
          <div className="flex items-center gap-1.5 bg-slate-100 text-slate-700 border border-slate-200 px-2 py-0.5 rounded text-[11px] font-medium">
            <Radio className="w-3 h-3 text-slate-500" />
            <span>Passive sensor (PCAP / Flow Input)</span>
          </div>
          <span className="text-slate-300 text-[11px]">|</span>
          <span className="text-[11px] text-slate-400 font-mono">Drops: Not measured</span>
        </div>

        {/* Demo Traffic Toggle */}
        <button
          onClick={onToggleLive}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
            isLive
              ? 'bg-slate-900 text-white border-slate-900'
              : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
          }`}
          title="Toggle demo replay stream simulation"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLive ? 'animate-spin text-teal-400' : 'text-slate-400'}`} />
          <span>{isLive ? 'Demo Traffic: Active' : 'Demo Traffic: Paused'}</span>
        </button>

        {/* Notifications */}
        <button
          onClick={onNotificationClick}
          className="relative p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded transition-colors"
          title="Alert Notifications"
        >
          <Bell className="w-4 h-4" />
          {notificationCount > 0 && (
            <span className="absolute top-1 right-1 w-2 h-2 bg-amber-500 rounded-full" />
          )}
        </button>
      </div>
    </header>
  );
};
