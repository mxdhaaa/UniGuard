import React from 'react';
import type { NavTab } from '../../types/uniguard';
import { 
  LayoutDashboard, 
  Activity, 
  ShieldAlert, 
  Sliders, 
  Cpu, 
  PlayCircle, 
  Server, 
  Settings,
  ShieldCheck
} from 'lucide-react';

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  activeThreatCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onTabChange, activeThreatCount }) => {
  const navItems: { id: NavTab; label: string; icon: React.ElementType; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'flows', label: 'Network Flows', icon: Activity },
    { id: 'alerts', label: 'SOC Alerts', icon: ShieldAlert, badge: activeThreatCount },
    { id: 'ingestion', label: 'PCAP & Ingestion', icon: Server },
    { id: 'traffic', label: 'Live Telemetry', icon: PlayCircle },
    { id: 'threats', label: 'Threat Incidents', icon: ShieldCheck },
    { id: 'detection', label: 'Detection Rules', icon: Sliders },
    { id: 'models', label: 'ML Models', icon: Cpu },
    { id: 'replay-lab', label: 'Replay Lab', icon: PlayCircle },
    { id: 'system', label: 'Sensor System', icon: Server },
  ];

  return (
    <aside className="w-60 bg-white border-r border-slate-200 flex flex-col justify-between h-screen sticky top-0 shrink-0 select-none z-20 font-sans">
      <div>
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-100 flex items-center gap-3">
          <div className="w-7 h-7 rounded bg-teal-800 text-white flex items-center justify-center font-bold text-xs shadow-xs">
            <ShieldCheck className="w-4 h-4 text-teal-200" />
          </div>
          <div>
            <div className="font-mono font-bold text-sm text-slate-900 tracking-wider">UNIGUARD</div>
            <div className="text-[10px] text-slate-500 font-medium">Passive Network Intelligence</div>
          </div>
        </div>

        {/* Navigation Section */}
        <nav className="p-3 space-y-1">
          <div className="px-2 py-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
            Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                  isActive
                    ? 'bg-slate-100 text-teal-900 font-semibold border-l-2 border-teal-700 rounded-l-none pl-2.5'
                    : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-teal-700' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-full ${
                    isActive ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700 border border-slate-200'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Settings */}
      <div className="p-3 border-t border-slate-100">
        <button
          onClick={() => onTabChange('settings')}
          className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
            activeTab === 'settings'
              ? 'bg-slate-100 text-teal-900 font-semibold border-l-2 border-teal-700 rounded-l-none pl-2.5'
              : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
          }`}
        >
          <Settings className={`w-4 h-4 ${activeTab === 'settings' ? 'text-teal-700' : 'text-slate-400'}`} />
          <span>Settings</span>
        </button>

        <div className="mt-3 px-3 py-2 rounded bg-slate-50 border border-slate-200/60 flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-slate-400" />
            <span className="font-medium text-slate-600">Passive Sensor</span>
          </div>
          <span className="font-mono text-slate-500 text-[10px]">PCAP / Flow</span>
        </div>
      </div>
    </aside>
  );
};
