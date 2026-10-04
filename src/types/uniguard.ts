export type NavTab = 
  | 'overview' 
  | 'flows'
  | 'alerts'
  | 'ingestion'
  | 'traffic' 
  | 'threats' 
  | 'detection' 
  | 'models' 
  | 'replay-lab' 
  | 'system' 
  | 'settings';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ThreatStatus = 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED' | 'WHITELISTED' | 'FALSE_POSITIVE';

export interface EvidenceMetric {
  label: string;
  percentage: number; // 0-100
  detail: string;
}

export interface FeatureValue {
  name: string;
  observed: string;
  baseline: string;
  zScore: number;
  impact: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface TimelineEvent {
  time: string;
  title: string;
  description: string;
  type: 'info' | 'warning' | 'critical';
}

export interface ThreatDetection {
  id: string;
  severity: SeverityLevel;
  threat: string;
  category: 'C2 Beaconing' | 'DDoS' | 'DNS Tunnelling / DGA' | 'Reconnaissance / Port Scanning';
  confidence: number;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'HTTPS';
  detectedAgo: string;
  timestamp: string;
  status: ThreatStatus;
  isDemoData: boolean;
  
  flowInfo: {
    packets: number;
    bytesTotal: string;
    durationSec: number;
    avgInterPacketTimeMs: number;
    tlsSni?: string;
    vlanId?: number;
    interface: string;
  };

  whyDetected: string;
  evidence: EvidenceMetric[];
  featureAnalysis: FeatureValue[];
  timeline: TimelineEvent[];

  modelInfo: {
    name: string;
    version: string;
    inferenceLatencyMs: string; // "Awaiting benchmark" or "Demo estimation"
    subDetectorVote: string;
  };
}

export interface NetworkTrafficPoint {
  time: string;
  gbps: number;
  flowsPerSec: number;
  httpPackets: number;
  dnsPackets: number;
  otherPackets: number;
  isDemoData?: boolean;
}

export interface ReplayScenario {
  id: string;
  name: string;
  description: string;
  targetProtocol: string;
  flowCount: number;
  threatCategory: string;
  recommendedSpeed: '1x' | '5x' | '10x' | 'REALTIME';
}

export interface ReplayStatus {
  isRunning: boolean;
  scenarioId: string | null;
  flowsProcessed: number;
  totalFlows: number;
  threatsDetected: number;
  processingLatencyMs: string;
  speed: string;
  progressPercent: number;
}

export interface PassiveSensorMetrics {
  interfaceName: string;
  status: 'Awaiting sensor input' | 'Demo driver active' | 'Passive sensor';
  captureEngine: 'PCAP / Flow Input' | 'Passive sensor';
  dropRatePercent: string;
  bufferUtilizationPercent: string;
  throughputMbps: string;
  cpuUsagePercent: string;
  memoryUsagePercent: string;
  uptimeSeconds: number;
}

export interface ModelMetric {
  id: string;
  name: string;
  type: string;
  version: string;
  status: 'Pending evaluation' | 'Demo Model' | 'Active';
  accuracy: string; // "--" or "Pending evaluation"
  f1Score: string;
  avgInferenceMs: string;
  lastTrained: string;
  topFeatures: { name: string; weight: number }[];
}
