/**
 * UniGuard Ingestion & PCAP Replay Lab View (Milestone 14)
 * 
 * Live network capture orchestration & PCAP upload/processing:
 * GET  /api/ingestion/status
 * POST /api/ingestion/start
 * POST /api/ingestion/stop
 * POST /api/pcap/upload
 * GET  /api/pcap/status/{job_id}
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Square, 
  UploadCloud, 
  FileUp, 
  AlertTriangle, 
  RefreshCw, 
  Server, 
  Activity, 
  ArrowRight
} from 'lucide-react';
import { 
  uniguardApi, 
  type IngestionStatusResponse, 
  type PcapStatusResponse 
} from '../../api/client';

interface IngestionPcapViewProps {
  onNavigateToFlows?: () => void;
}

export const IngestionPcapView: React.FC<IngestionPcapViewProps> = ({
  onNavigateToFlows,
}) => {
  // Ingestion State
  const [ingestion, setIngestion] = useState<IngestionStatusResponse | null>(null);
  const [ingestionLoading, setIngestionLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [ingestionError, setIngestionError] = useState<string | null>(null);

  // PCAP Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<PcapStatusResponse | null>(null);
  const [jobPolling, setJobPolling] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Fetch Ingestion Status
  const fetchIngestionStatus = async () => {
    try {
      const res = await uniguardApi.getIngestionStatus();
      setIngestion(res);
      setIngestionError(null);
    } catch (err: any) {
      setIngestionError(err?.message || 'Unable to retrieve ingestion engine status.');
    } finally {
      setIngestionLoading(false);
    }
  };

  useEffect(() => {
    fetchIngestionStatus();
    // Poll ingestion status periodically (every 5 seconds)
    const interval = setInterval(fetchIngestionStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartIngestion = async () => {
    setActionLoading(true);
    setIngestionError(null);
    try {
      const res = await uniguardApi.startIngestion();
      setIngestion(res);
    } catch (err: any) {
      setIngestionError(err?.message || 'Failed to start passive ingestion.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStopIngestion = async () => {
    setActionLoading(true);
    setIngestionError(null);
    try {
      const res = await uniguardApi.stopIngestion();
      setIngestion(res);
    } catch (err: any) {
      setIngestionError(err?.message || 'Failed to stop passive ingestion.');
    } finally {
      setActionLoading(false);
    }
  };

  // PCAP file selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setUploadError(null);
    }
  };

  // Upload and start polling
  const handleUploadPcap = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setUploadError(null);
    try {
      const uploadRes = await uniguardApi.uploadPcap(selectedFile);
      setUploading(false);
      setJobPolling(true);

      // Immediately fetch initial status
      const initialStatus = await uniguardApi.getPcapStatus(uploadRes.job_id);
      setActiveJob(initialStatus);

      // Poll until finished or error
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await uniguardApi.getPcapStatus(uploadRes.job_id);
          setActiveJob(statusRes);

          if (statusRes.status === 'COMPLETED' || statusRes.status === 'FAILED') {
            clearInterval(pollInterval);
            setJobPolling(false);
            // Refresh ingestion metrics after PCAP processing
            fetchIngestionStatus();
          }
        } catch {
          clearInterval(pollInterval);
          setJobPolling(false);
        }
      }, 1500);
    } catch (err: any) {
      setUploadError(err?.message || 'PCAP upload failed.');
      setUploading(false);
    }
  };

  const isIngestionRunning = ingestion?.state?.toUpperCase() === 'RUNNING';

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <Server className="w-5 h-5 text-teal-700" />
          Ingestion & PCAP Processing
        </h1>
        <p className="text-xs text-slate-500 mt-1">
          Orchestrate passive sensor packet capture or upload PCAP/PCAPNG capture files for flow extraction.
        </p>
      </div>

      {/* Grid: 2 columns for Ingestion Status & PCAP Processing */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Card 1: Passive Ingestion Engine */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-2xs overflow-hidden flex flex-col justify-between">
          <div>
            <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/60">
              <div className="flex items-center gap-2.5">
                <Activity className="w-4 h-4 text-teal-700" />
                <h2 className="text-sm font-bold text-slate-900 font-sans">
                  Passive Capture Engine
                </h2>
              </div>
              <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                isIngestionRunning 
                  ? 'bg-emerald-100 text-emerald-800 animate-pulse'
                  : 'bg-slate-200 text-slate-700'
              }`}>
                {ingestion?.state || 'UNKNOWN'}
              </span>
            </div>

            <div className="p-5 space-y-4">
              {ingestionError && (
                <div className="p-3 rounded-md bg-red-50 border border-red-200 text-red-800 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{ingestionError}</span>
                </div>
              )}

              {/* Status metrics grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Sensor Interface</div>
                  <div className="font-mono font-bold text-xs text-slate-800 truncate mt-1">
                    {ingestion?.interface || '--'}
                  </div>
                </div>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Capture Filter</div>
                  <div className="font-mono font-bold text-xs text-slate-800 truncate mt-1">
                    {ingestion?.capture_filter || 'none'}
                  </div>
                </div>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Active Flows</div>
                  <div className="font-mono font-bold text-xs text-slate-800 mt-1">
                    {ingestion?.active_flows ?? 0}
                  </div>
                </div>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Packets Captured</div>
                  <div className="font-mono font-bold text-xs text-teal-800 mt-1">
                    {ingestion?.packets_captured ?? 0}
                  </div>
                </div>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Flows Completed</div>
                  <div className="font-mono font-bold text-xs text-slate-800 mt-1">
                    {ingestion?.flows_completed ?? 0}
                  </div>
                </div>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200/80">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Errors</div>
                  <div className="font-mono font-bold text-xs text-rose-700 mt-1">
                    {ingestion?.errors ?? 0}
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-500 leading-relaxed">
                The passive capture engine binds directly to the local network interface or socket, aggregating raw Ethernet frames into bidirectional IP flows for real-time feature extraction.
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="p-4 border-t border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <button
              onClick={fetchIngestionStatus}
              disabled={ingestionLoading}
              className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors shadow-2xs"
            >
              Refresh Status
            </button>

            <div className="flex items-center gap-2">
              {isIngestionRunning ? (
                <button
                  onClick={handleStopIngestion}
                  disabled={actionLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-rose-600 hover:bg-rose-700 text-white transition-colors shadow-2xs disabled:opacity-50"
                >
                  <Square className="w-3.5 h-3.5" />
                  <span>Stop Capture</span>
                </button>
              ) : (
                <button
                  onClick={handleStartIngestion}
                  disabled={actionLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-teal-800 hover:bg-teal-900 text-white transition-colors shadow-2xs disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Start Capture</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Card 2: PCAP Ingestion & Processing */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-2xs overflow-hidden flex flex-col justify-between">
          <div>
            <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/60">
              <div className="flex items-center gap-2.5">
                <FileUp className="w-4 h-4 text-teal-700" />
                <h2 className="text-sm font-bold text-slate-900 font-sans">
                  PCAP File Processing
                </h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">
                .pcap / .pcapng
              </span>
            </div>

            <div className="p-5 space-y-4">
              {uploadError && (
                <div className="p-3 rounded-md bg-red-50 border border-red-200 text-red-800 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {/* Upload Drop Zone / Picker */}
              <div 
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center gap-2.5 text-center cursor-pointer transition-colors ${
                  selectedFile 
                    ? 'border-teal-500 bg-teal-50/20' 
                    : 'border-slate-300 hover:border-teal-600 bg-slate-50/50'
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".pcap,.pcapng"
                  className="hidden"
                />
                <UploadCloud className={`w-8 h-8 ${selectedFile ? 'text-teal-700' : 'text-slate-400'}`} />
                {selectedFile ? (
                  <div>
                    <span className="font-mono text-xs font-bold text-slate-800 block">
                      {selectedFile.name}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &bull; Click to change
                    </span>
                  </div>
                ) : (
                  <div>
                    <span className="text-xs font-semibold text-slate-700 block">
                      Click to choose PCAP file
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Supported formats: Wireshark (.pcap, .pcapng)
                    </span>
                  </div>
                )}
              </div>

              {/* Active PCAP Job Status Card */}
              {activeJob && (
                <div className="p-3.5 rounded-lg border border-slate-200 bg-slate-50/80 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] font-bold text-slate-800 truncate max-w-[200px]" title={activeJob.filename}>
                      {activeJob.filename}
                    </span>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      activeJob.status === 'COMPLETED'
                        ? 'bg-emerald-100 text-emerald-800'
                        : activeJob.status === 'FAILED'
                        ? 'bg-rose-100 text-rose-800'
                        : 'bg-amber-100 text-amber-800 animate-pulse'
                    }`}>
                      {activeJob.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="p-2 rounded bg-white border border-slate-200/80">
                      <div className="text-[9px] uppercase font-semibold text-slate-400">Packets</div>
                      <div className="font-mono font-bold text-slate-800 mt-0.5">{activeJob.packets_processed}</div>
                    </div>
                    <div className="p-2 rounded bg-white border border-slate-200/80">
                      <div className="text-[9px] uppercase font-semibold text-slate-400">Flows Extracted</div>
                      <div className="font-mono font-bold text-teal-800 mt-0.5">{activeJob.flows_extracted}</div>
                    </div>
                    <div className="p-2 rounded bg-white border border-slate-200/80">
                      <div className="text-[9px] uppercase font-semibold text-slate-400">Job ID</div>
                      <div className="font-mono font-semibold text-slate-600 truncate mt-0.5" title={activeJob.job_id}>
                        {activeJob.job_id.substring(0, 8)}...
                      </div>
                    </div>
                  </div>

                  {activeJob.error_message && (
                    <div className="text-xs text-rose-700 font-mono">
                      Error: {activeJob.error_message}
                    </div>
                  )}

                  {activeJob.status === 'COMPLETED' && onNavigateToFlows && (
                    <button
                      onClick={onNavigateToFlows}
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs font-semibold rounded bg-teal-800 hover:bg-teal-900 text-white transition-colors shadow-2xs mt-2"
                    >
                      <span>View Extracted Flows</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Upload Button */}
          <div className="p-4 border-t border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <span className="text-xs text-slate-500">
              {jobPolling ? 'Processing PCAP file in background...' : 'Ready for upload'}
            </span>

            <button
              onClick={handleUploadPcap}
              disabled={!selectedFile || uploading || jobPolling}
              className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded-md bg-teal-800 hover:bg-teal-900 text-white transition-colors shadow-2xs disabled:opacity-50 disabled:pointer-events-none"
            >
              {uploading || jobPolling ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>{uploading ? 'Uploading...' : 'Processing...'}</span>
                </>
              ) : (
                <>
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>Process PCAP</span>
                </>
              )}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
