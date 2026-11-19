export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "NEW" | "INVESTIGATING" | "CLOSED";
export type Resolution = "TRUE_POSITIVE" | "BENIGN_TRUE_POSITIVE" | "FALSE_POSITIVE" | "DUPLICATE";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const STATUSES: AlertStatus[] = ["NEW", "INVESTIGATING", "CLOSED"];
export const RESOLUTIONS: Resolution[] = ["TRUE_POSITIVE", "BENIGN_TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE"];

export interface AlertRow {
  id: number;
  ruleId: string;
  title: string;
  severity: Severity;
  riskScore: number;
  status: AlertStatus;
  resolution: Resolution | null;
  assignee: string | null;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  mitreTechniqueName: string | null;
  srcIp: string | null;
  dstIp: string | null;
  host: string | null;
  username: string | null;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  anomalyScore: number | null;
}

export interface Alert extends AlertRow {
  description: string;
  scoreFactors: Record<string, number>;
  evidence: Record<string, unknown>;
  summary: string | null;
  summarySource: string | null;
}

export interface Activity {
  id: number;
  actor: string;
  action: string;
  fromStatus: AlertStatus | null;
  toStatus: AlertStatus | null;
  note: string | null;
  createdAt: string;
}

export interface EventView {
  id: number;
  time: string;
  type: string;
  source: string;
  srcIp: string | null;
  dstIp: string | null;
  dstPort: number | null;
  host: string | null;
  username: string | null;
  process: string | null;
  commandLine: string | null;
  bytes: number | null;
  packets: number | null;
  datasetLabel: string | null;
}

export interface AlertDetail {
  alert: Alert;
  mitreUrl: string | null;
  playbook: string[];
  activity: Activity[];
  events: EventView[];
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface Count {
  key: string;
  count: number;
}

export interface Overview {
  totalAlerts: number;
  openAlerts: number;
  openCritical: number;
  meanMinutesToClose: number | null;
  bySeverity: Record<Severity, number>;
  byStatus: Record<AlertStatus, number>;
  byTactic: Count[];
  byRule: Count[];
  timeline: { bucket: string; low: number; medium: number; high: number; critical: number }[];
  eventsBySource: Count[];
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  logic: string;
  baseScore: number;
  mitreTechnique: string;
  mitreTechniqueName: string;
  mitreTactic: string;
  mitreUrl: string;
}

export interface AlertFilters {
  status: AlertStatus[];
  severity: Severity[];
  tactic: string;
  ruleId: string;
  q: string;
  sort: string;
  dir: "asc" | "desc";
  page: number;
}
