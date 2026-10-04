import { useState, useEffect } from 'react';
import type { NavTab, ThreatDetection, NetworkTrafficPoint, ReplayStatus } from './types/uniguard';
import { INITIAL_THREATS, MOCK_TIMESERIES_TRAFFIC, REPLAY_SCENARIOS, SENSOR_METRICS, REGISTERED_MODELS } from './data/mockData';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewView } from './components/views/OverviewView';
import { FlowsView } from './components/views/FlowsView';
import { AlertsView } from './components/views/AlertsView';
import { IngestionPcapView } from './components/views/IngestionPcapView';
import { InvestigationModal } from './components/views/InvestigationModal';
import { ReportModal } from './components/views/ReportModal';
import { ThreatTableView } from './components/views/ThreatTableView';
import { ThreatDetailModal } from './components/views/ThreatDetailModal';
import { ReplayLabView } from './components/views/ReplayLabView';
import { TrafficView } from './components/views/TrafficView';
import { DetectionRulesView } from './components/views/DetectionRulesView';
import { ModelsView } from './components/views/ModelsView';
import { SystemView } from './components/views/SystemView';
import { SettingsView } from './components/views/SettingsView';
import { ShieldAlert, X } from 'lucide-react';
import { uniguardApi } from './api/client';

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [threats, setThreats] = useState<ThreatDetection[]>(INITIAL_THREATS);
  const [trafficTimeseries, setTrafficTimeseries] = useState<NetworkTrafficPoint[]>(MOCK_TIMESERIES_TRAFFIC);
  const [selectedThreat, setSelectedThreat] = useState<ThreatDetection | null>(null);
  const [isLive, setIsLive] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [investigationTarget, setInvestigationTarget] = useState<{ flowId?: string; alertId?: string } | null>(null);
  const [reportTarget, setReportTarget] = useState<{ flowId?: string; alertId?: string } | null>(null);

  // Fetch real backend detection data if backend API is running
  useEffect(() => {
    async function fetchBackendDetections() {
      try {
        const res = await fetch('http://localhost:8000/api/v1/detections');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            const mappedThreats: ThreatDetection[] = data.map((d: any) => ({
              id: d.id,
              severity: d.severity,
              threat: d.threat_class.replace('_', ' '),
              category: d.threat_class === 'DNS_TUNNELLING_DGA' ? 'DNS Tunnelling / DGA' :
                        d.threat_class === 'C2_BEACONING' ? 'C2 Beaconing' :
                        d.threat_class === 'DDoS' ? 'DDoS' : 'Reconnaissance / Port Scanning',
              confidence: Math.round(d.confidence * 100),
              sourceIp: d.source.split(':')[0] || d.source,
              sourcePort: parseInt(d.source.split(':')[1]) || 80,
              destIp: d.destination.split(':')[0] || d.destination,
              destPort: parseInt(d.destination.split(':')[1]) || 443,
              protocol: d.protocol || 'TCP',
              detectedAgo: 'Just now',
              timestamp: d.timestamp,
              status: d.status || 'ACTIVE',
              isDemoData: false,
              flowInfo: {
                packets: 120,
                bytesTotal: '14.2 KB',
                durationSec: 10,
                avgInterPacketTimeMs: 120,
                interface: 'eth0 (Passive sensor)',
              },
              whyDetected: d.evidence.map((e: any) => e.interpretation).join(' '),
              evidence: d.evidence.map((e: any) => ({
                label: e.feature,
                percentage: typeof e.value === 'number' ? Math.min(100, Math.round(e.value * 100)) : 85,
                detail: e.interpretation,
              })),
              featureAnalysis: d.evidence.map((e: any) => ({
                name: e.feature,
                observed: String(e.value),
                baseline: 'Standard',
                zScore: 3.2,
                impact: 'HIGH' as const,
              })),
              timeline: [
                { time: d.timestamp.substring(11, 19) + ' Z', title: 'Detector Fired', description: `Detected by ${d.detector}`, type: 'critical' as const }
              ],
              modelInfo: {
                name: d.detector,
                version: 'Pending evaluation',
                inferenceLatencyMs: 'Awaiting benchmark',
                subDetectorVote: '1 / 1 detector confirmed',
              },
            }));
            setThreats(mappedThreats);
          }
        }
      } catch (err) {
        // Backend offline fallback to initial local state
      }
    }

    fetchBackendDetections();
  }, []);

  // Replay Lab State
  const [replayStatus, setReplayStatus] = useState<ReplayStatus>({
    isRunning: false,
    scenarioId: null,
    flowsProcessed: 0,
    totalFlows: 2500,
    threatsDetected: 0,
    processingLatencyMs: 'Awaiting benchmark',
    speed: '5x',
    progressPercent: 0,
  });

  // Simulated live traffic stream tick
  useEffect(() => {
    if (!isLive) return;

    const interval = setInterval(() => {
      setTrafficTimeseries((prev) => {
        const nextGbps = parseFloat((1.3 + Math.random() * 0.45).toFixed(2));
        const nextFlows = Math.floor(4500 + Math.random() * 1200);

        const now = new Date();
        const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;

        const updated = [...prev.slice(1), {
          time: timeStr,
          gbps: nextGbps,
          flowsPerSec: nextFlows,
          httpPackets: Math.floor(nextFlows * 4.8),
          dnsPackets: Math.floor(nextFlows * 1.1),
          otherPackets: Math.floor(nextFlows * 2.0),
          isDemoData: true,
        }];
        return updated;
      });
    }, 3000);

    return () => clearInterval(interval);
  }, [isLive]);

  // Replay execution timer effect
  useEffect(() => {
    if (!replayStatus.isRunning) return;

    const speedMultiplier = parseInt(replayStatus.speed) || 5;
    const stepInterval = 400 / speedMultiplier;

    const interval = setInterval(() => {
      setReplayStatus((prev) => {
        if (!prev.isRunning) return prev;
        const newProcessed = prev.flowsProcessed + Math.floor(25 * (speedMultiplier / 2));
        const progress = Math.min(100, Math.floor((newProcessed / prev.totalFlows) * 100));
        
        let newThreats = prev.threatsDetected;
        if (Math.random() > 0.8) {
          newThreats += 1;
        }

        if (newProcessed >= prev.totalFlows) {
          setToastMessage('Replay Scenario Execution Completed.');
          return {
            ...prev,
            isRunning: false,
            flowsProcessed: prev.totalFlows,
            progressPercent: 100,
          };
        }

        return {
          ...prev,
          flowsProcessed: newProcessed,
          threatsDetected: newThreats,
          progressPercent: progress,
        };
      });
    }, stepInterval);

    return () => clearInterval(interval);
  }, [replayStatus.isRunning, replayStatus.speed]);

  const handleStartReplay = (scenarioId: string, speed: string) => {
    const scenario = REPLAY_SCENARIOS.find((s) => s.id === scenarioId) || REPLAY_SCENARIOS[0];
    setReplayStatus({
      isRunning: true,
      scenarioId,
      flowsProcessed: 0,
      totalFlows: scenario.flowCount,
      threatsDetected: 0,
      processingLatencyMs: 'Awaiting benchmark',
      speed,
      progressPercent: 0,
    });
    setToastMessage(`Replay Lab: Started scenario "${scenario.name}".`);
  };

  const handleStopReplay = () => {
    setReplayStatus((prev) => ({ ...prev, isRunning: false }));
    setToastMessage('Replay Lab execution stopped.');
  };

  const handleThreatStatusChange = (id: string, newStatus: ThreatDetection['status']) => {
    setThreats((prev) =>
      prev.map((t) => (t.id === id ? { ...t, status: newStatus } : t))
    );
    if (selectedThreat && selectedThreat.id === id) {
      setSelectedThreat((prev) => (prev ? { ...prev, status: newStatus } : null));
    }
    setToastMessage(`Threat ${id} status updated to ${newStatus}.`);
  };

  const [activeThreatsCount, setActiveThreatsCount] = useState<number>(0);
  useEffect(() => {
    async function fetchAlertCount() {
      try {
        const response = await uniguardApi.getAlerts({ page: 1, page_size: 1 });
        setActiveThreatsCount(response.meta.total_items);
      } catch {
        setActiveThreatsCount(0);
      }
    }
    fetchAlertCount();
  }, []);

  return (
    <div className="flex h-screen bg-[#F7F8FA] text-slate-900 overflow-hidden font-sans">
      {/* Compact Professional Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        activeThreatCount={activeThreatsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <Header
          isLive={isLive}
          onToggleLive={() => setIsLive(!isLive)}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          notificationCount={activeThreatsCount}
          onNotificationClick={() => setActiveTab('threats')}
        />

        {/* Dynamic View Container */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto space-y-6">
            
            {/* Notification Toast */}
            {toastMessage && (
              <div className="bg-slate-900 text-white text-xs px-4 py-2.5 rounded-md shadow-md flex items-center justify-between animate-in fade-in slide-in-from-top-2 duration-200 font-sans">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-teal-400" />
                  <span>{toastMessage}</span>
                </div>
                <button
                  onClick={() => setToastMessage(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* TAB VIEWS */}
            {activeTab === 'overview' && (
              <OverviewView
                threats={threats}
                trafficTimeseries={trafficTimeseries}
                models={REGISTERED_MODELS}
                onSelectThreat={setSelectedThreat}
                onNavigateToTab={setActiveTab}
                onInvestigateFlow={(flowId) => setInvestigationTarget({ flowId })}
                onInvestigateAlert={(alertId) => setInvestigationTarget({ alertId })}
              />
            )}

            {activeTab === 'flows' && (
              <FlowsView
                onInvestigateFlow={(flowId) => setInvestigationTarget({ flowId })}
                onReportFlow={(flowId) => setReportTarget({ flowId })}
              />
            )}

            {activeTab === 'alerts' && (
              <AlertsView
                onInvestigateAlert={(alertId) => setInvestigationTarget({ alertId })}
                onReportAlert={(alertId) => setReportTarget({ alertId })}
                onInvestigateFlow={(flowId) => setInvestigationTarget({ flowId })}
              />
            )}

            {activeTab === 'ingestion' && (
              <IngestionPcapView
                onNavigateToFlows={() => setActiveTab('flows')}
              />
            )}

            {activeTab === 'traffic' && (
              <TrafficView timeseries={trafficTimeseries} />
            )}

            {activeTab === 'threats' && (
              <div className="space-y-4">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 tracking-tight">Security Threats & Incidents</h1>
                  <p className="text-xs text-slate-500 mt-1">
                    Complete passive network security operations callset and active threat alerts.
                  </p>
                </div>
                <ThreatTableView
                  threats={threats}
                  onSelectThreat={setSelectedThreat}
                />
              </div>
            )}

            {activeTab === 'detection' && (
              <DetectionRulesView />
            )}

            {activeTab === 'models' && (
              <ModelsView models={REGISTERED_MODELS} />
            )}

            {activeTab === 'replay-lab' && (
              <ReplayLabView
                scenarios={REPLAY_SCENARIOS}
                replayStatus={replayStatus}
                onStartReplay={handleStartReplay}
                onStopReplay={handleStopReplay}
                onSelectThreat={setSelectedThreat}
              />
            )}

            {activeTab === 'system' && (
              <SystemView sensor={SENSOR_METRICS} />
            )}

            {activeTab === 'settings' && (
              <SettingsView />
            )}

          </div>
        </main>
      </div>

      {/* Threat Detail Modal / Drawer */}
      <ThreatDetailModal
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onStatusChange={handleThreatStatusChange}
      />

      {/* Deep-Dive Investigation Modal */}
      {investigationTarget && (
        <InvestigationModal
          flowId={investigationTarget.flowId}
          alertId={investigationTarget.alertId}
          onClose={() => setInvestigationTarget(null)}
          onOpenReport={(subject) => {
            setInvestigationTarget(null);
            setReportTarget(subject);
          }}
        />
      )}

      {/* Incident Report Modal */}
      {reportTarget && (
        <ReportModal
          flowId={reportTarget.flowId}
          alertId={reportTarget.alertId}
          onClose={() => setReportTarget(null)}
          onOpenInvestigation={(subject) => {
            setReportTarget(null);
            setInvestigationTarget(subject);
          }}
        />
      )}
    </div>
  );
}

export default App;


