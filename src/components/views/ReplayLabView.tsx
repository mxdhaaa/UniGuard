import React, { useState, useEffect } from 'react';
import type { ReplayScenario, ReplayStatus, ThreatDetection } from '../../types/uniguard';
import { Play, Square, Activity } from 'lucide-react';

interface ReplayLabViewProps {
  scenarios: ReplayScenario[];
  replayStatus: ReplayStatus;
  onStartReplay: (scenarioId: string, speed: string) => void;
  onStopReplay: () => void;
  onSelectThreat: (threat: ThreatDetection) => void;
}

export const ReplayLabView: React.FC<ReplayLabViewProps> = ({
  scenarios,
  replayStatus,
  onStartReplay,
  onStopReplay,
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(scenarios[0].id);
  const [replaySpeed, setReplaySpeed] = useState<string>('5x');
  const [logConsole, setLogConsole] = useState<{ id: string; time: string; msg: string; type: 'info' | 'threat' | 'sys' }[]>([]);

  const selectedScenario = scenarios.find((s) => s.id === selectedScenarioId) || scenarios[0];

  useEffect(() => {
    if (replayStatus.isRunning) {
      const interval = setInterval(() => {
        const timestamp = new Date().toISOString().substring(11, 19) + ' Z';
        const flowId = Math.floor(10000 + Math.random() * 90000);
        const isThreat = Math.random() > 0.78;

        if (isThreat) {
          setLogConsole((prev) => [
            {
              id: Math.random().toString(),
              time: timestamp,
              msg: `DEMO REPLAY THREAT [Flow #${flowId}] — Matched ${selectedScenario.threatCategory} rule signature`,
              type: 'threat',
            },
            ...prev.slice(0, 49),
          ]);
        } else {
          setLogConsole((prev) => [
            {
              id: Math.random().toString(),
              time: timestamp,
              msg: `Replay Flow #${flowId} (${(Math.random() * 1.5 + 0.2).toFixed(2)} KB) -> Feature extraction complete`,
              type: 'info',
            },
            ...prev.slice(0, 49),
          ]);
        }
      }, 600 / (parseInt(replaySpeed) || 1));

      return () => clearInterval(interval);
    }
  }, [replayStatus.isRunning, replaySpeed, selectedScenario]);

  return (
    <div className="space-y-6 font-sans">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Replay Lab</h1>
          <span className="text-[10px] font-mono font-semibold bg-amber-100 text-amber-800 border border-amber-200 px-2 py-0.5 rounded">
            SYNTHETIC REPLAY HARNESS
          </span>
        </div>
        <p className="text-xs text-slate-500 mt-1">
          Synthetic network traffic injection harness for evaluating passive detection heuristics against test scenarios.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-4">
            <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Select Scenario</h3>
            
            <div className="space-y-2">
              {scenarios.map((scen) => (
                <button
                  key={scen.id}
                  disabled={replayStatus.isRunning}
                  onClick={() => setSelectedScenarioId(scen.id)}
                  className={`w-full text-left p-3 rounded border transition-colors ${
                    selectedScenarioId === scen.id
                      ? 'bg-slate-100 border-teal-700 text-slate-900 shadow-2xs'
                      : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900">{scen.name}</span>
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-200/60 px-1.5 py-0.5 rounded">
                      {scen.flowCount} flows
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1.5 line-clamp-2 leading-relaxed">
                    "{scen.description}"
                  </p>
                </button>
              ))}
            </div>

            <div className="pt-3 border-t border-slate-200 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-600 font-medium">Replay Rate multiplier:</span>
                <select
                  value={replaySpeed}
                  onChange={(e) => setReplaySpeed(e.target.value)}
                  disabled={replayStatus.isRunning}
                  className="bg-white border border-slate-200 rounded px-2 py-1 text-slate-800 font-mono text-xs focus:outline-none"
                >
                  <option value="1x">1x (Real-time)</option>
                  <option value="5x">5x (Accelerated)</option>
                  <option value="10x">10x (High Throughput)</option>
                </select>
              </div>

              <div className="flex items-center gap-2 pt-2">
                {!replayStatus.isRunning ? (
                  <button
                    onClick={() => onStartReplay(selectedScenario.id, replaySpeed)}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-teal-800 hover:bg-teal-900 text-white rounded font-medium text-xs transition-colors shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Start Replay</span>
                  </button>
                ) : (
                  <button
                    onClick={onStopReplay}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-800 text-white rounded font-medium text-xs transition-colors shadow-xs"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    <span>Stop Replay</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Status</span>
              <div className="mt-1 flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${replayStatus.isRunning ? 'bg-amber-500 animate-pulse' : 'bg-slate-300'}`} />
                <span className="font-mono text-sm font-bold text-slate-900">
                  {replayStatus.isRunning ? 'REPLAYING...' : 'IDLE'}
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Flows Processed</span>
              <div className="mt-1 font-mono text-sm font-bold text-slate-900">
                {replayStatus.flowsProcessed.toLocaleString()} / {selectedScenario.flowCount.toLocaleString()}
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Threats Detected</span>
              <div className="mt-1 font-mono text-sm font-bold text-amber-700">
                {replayStatus.threatsDetected}
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Processing Latency</span>
              <div className="mt-1 font-mono text-xs font-bold text-slate-700">
                {replayStatus.processingLatencyMs}
              </div>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-2">
            <div className="flex justify-between text-xs text-slate-600 font-medium">
              <span>Replay Execution Progress</span>
              <span className="font-mono">{replayStatus.progressPercent}%</span>
            </div>
            <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
              <div 
                className="h-full bg-teal-700 transition-all duration-300 rounded-full"
                style={{ width: `${replayStatus.progressPercent}%` }}
              />
            </div>
          </div>

          <div className="bg-slate-900 text-slate-200 border border-slate-800 rounded-lg p-4 font-mono text-xs shadow-xs space-y-2">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-400 text-[11px] font-sans">
              <div className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-teal-400" />
                <span>Synthetic Replay Console Feed</span>
              </div>
              <span className="text-[10px] bg-slate-800 px-2 py-0.5 rounded text-slate-300">Replay Lab</span>
            </div>

            <div className="h-64 overflow-y-auto space-y-1.5 pr-2 pt-1">
              {logConsole.length === 0 ? (
                <div className="text-slate-500 text-center pt-24 font-sans text-xs">
                  Click [ Start Replay ] to initiate synthetic scenario injection.
                </div>
              ) : (
                logConsole.map((log) => (
                  <div key={log.id} className={`flex items-start gap-2 ${log.type === 'threat' ? 'text-amber-400 bg-amber-950/30 p-1 rounded border border-amber-900/40' : 'text-slate-300'}`}>
                    <span className="text-slate-500 text-[11px] shrink-0">[{log.time}]</span>
                    <span>{log.msg}</span>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
