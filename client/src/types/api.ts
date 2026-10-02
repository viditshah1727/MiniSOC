// Types for everything the MiniSOC API returns. They mirror the server's
// responses, so the compiler catches a page reading a field that isn't there.

export type Role = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type EventType =
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'NETWORK_CONNECTION'
  | 'PROCESS_EXECUTION'
  | 'DNS_QUERY'
  | 'FILE_DOWNLOAD';
export type AlertStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type IndicatorType = 'IP' | 'DOMAIN' | 'HASH';
export type Reputation = 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
export type ActivityType = 'CREATED' | 'STATUS_CHANGE' | 'ASSIGNMENT' | 'NOTE' | 'ALERT_LINKED';

export interface User {
  id: number;
  email: string;
  name: string;
  role: Role;
}

export interface Session {
  user: User;
  features: { simulation: boolean; aiAssistant: boolean };
}

export interface Pagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface Page<T> {
  items: T[];
  pagination: Pagination;
}

// ─── Events ─────────────────────────────────────────────────────────────────

export interface SecurityEvent {
  id: number;
  timestamp: string;
  source: string;
  eventType: EventType;
  severity: Severity;
  sourceIp: string | null;
  destinationIp: string | null;
  destinationPort: number | null;
  hostname: string | null;
  username: string | null;
  message: string;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

export interface EventListItem extends SecurityEvent {
  alertCount: number;
}

export interface AlertSummary {
  id: number;
  title: string;
  severity: Severity;
  status: AlertStatus;
  riskScore: number;
  detectedAt: string;
  rule: { code: string; name: string };
}

export interface EventDetail extends SecurityEvent {
  alerts: AlertSummary[];
}

// ─── Alerts ─────────────────────────────────────────────────────────────────

export interface AlertListItem {
  id: number;
  title: string;
  severity: Severity;
  status: AlertStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  sourceIp: string | null;
  hostname: string | null;
  username: string | null;
  detectedAt: string;
  incidentId: number | null;
  rule: { code: string; name: string };
  mitreTechnique: { id: string; name: string } | null;
  threatIntel: { reputation: Reputation } | null;
}

export interface RiskFactor {
  label: string;
  points: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
}

export interface Indicator {
  id: number;
  indicator: string;
  type: IndicatorType;
  reputation: Reputation;
  confidence: number;
  source: string;
  description: string | null;
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
}

export interface IndicatorListItem extends Indicator {
  alertCount: number;
}

export interface Activity {
  id: number;
  type: ActivityType;
  message: string;
  createdAt: string;
  user: { id: number; name: string } | null;
}

export interface AlertDetail {
  id: number;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  riskFactors: RiskFactor[];
  evidence: Record<string, unknown>;
  sourceIp: string | null;
  hostname: string | null;
  username: string | null;
  detectedAt: string;
  updatedAt: string;
  rule: {
    id: number;
    code: string;
    name: string;
    description: string;
    severity: Severity;
    threshold: number | null;
    windowMinutes: number | null;
    recommendedSteps: string[];
    techniques: { id: string; name: string; tactics: string[] }[];
  };
  mitreTechnique: MitreTechnique | null;
  threatIntel: Indicator | null;
  event: SecurityEvent;
  evidenceEvents: SecurityEvent[];
  incident: { id: number; title: string; status: IncidentStatus; severity: Severity } | null;
  activities: Activity[];
  relatedAlerts: AlertListItem[];
}

// ─── Incidents ──────────────────────────────────────────────────────────────

export interface IncidentListItem {
  id: number;
  title: string;
  description: string | null;
  severity: Severity;
  status: IncidentStatus;
  assignee: { id: number; name: string } | null;
  alertCount: number;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentDetail extends Omit<IncidentListItem, 'alertCount' | 'assignee'> {
  assignee: User | null;
  alerts: AlertListItem[];
  events: SecurityEvent[];
  activities: Activity[];
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

export type DashboardRange = '24h' | '7d';

export interface DashboardStats {
  range: DashboardRange;
  since: string;
  kpis: {
    totalEvents: number;
    eventsInRange: number;
    totalAlerts: number;
    openAlerts: number;
    criticalOpenAlerts: number;
    openIncidents: number;
    overallRisk: { score: number; level: RiskLevel };
  };
  eventsOverTime: { bucket: string; events: number; alerts: number }[];
  alertsBySeverity: { severity: Severity; count: number }[];
  topSourceIps: { ip: string; alerts: number; events: number; reputation: Reputation | null }[];
  detectionsByRule: { code: string; name: string; count: number }[];
  recentCriticalAlerts: AlertListItem[];
  recentEvents: Pick<
    SecurityEvent,
    'id' | 'timestamp' | 'eventType' | 'severity' | 'source' | 'sourceIp' | 'hostname' | 'username' | 'message'
  >[];
  activeIncidents: IncidentListItem[];
}

// ─── MITRE, rules, simulation ───────────────────────────────────────────────

export interface MitreTechniqueRow extends MitreTechnique {
  rules: { id: number; code: string; name: string; enabled: boolean }[];
  alertCount: number;
  openAlertCount: number;
}

export interface DetectionRuleRow {
  id: number;
  code: string;
  name: string;
  description: string;
  severity: Severity;
  threshold: number | null;
  windowMinutes: number | null;
  enabled: boolean;
  techniques: { id: string; name: string }[];
  alertCount: number;
  thresholdLabel: string | null;
  tunable: { threshold: boolean; windowMinutes: boolean };
}

/** Optional AI assistant output (POST /api/alerts/:id/ai-analysis). Advisory only. */
export interface AiAnalysis {
  summary: string;
  explanation: string;
  likelyAttackBehavior: string;
  mitreTechnique: { id: string; name: string; rationale: string };
  investigationSteps: string[];
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  model: string;
  generatedAt: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  expectedRules: string[];
}

export interface SimulationResult {
  scenario: { id: string; name: string };
  eventsIngested: number;
  alerts: { id: number; title: string; severity: Severity; riskScore: number; rule: { code: string; name: string } }[];
}

/** Messages pushed by GET /api/stream (Server-Sent Events). */
export type LiveUpdate =
  | { type: 'event.created'; id: number }
  | { type: 'alert.created'; id: number; title: string; severity: Severity; riskScore: number }
  | { type: 'alert.updated'; id: number; status: AlertStatus }
  | { type: 'incident.created'; id: number; title: string; severity: Severity }
  | { type: 'incident.updated'; id: number; status: IncidentStatus };
