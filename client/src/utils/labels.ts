// Display names and colours for the enums the API returns.
import type {
  AlertStatus,
  EventType,
  IncidentStatus,
  IndicatorType,
  Reputation,
  RiskLevel,
  Role,
  Severity,
} from '../types/api';

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

/** Severity/risk colours (hex mirrors of the --color-sev-* tokens, for SVG charts). */
export const SEVERITY_COLOR: Record<Severity | RiskLevel, string> = {
  CRITICAL: '#d03b3b',
  HIGH: '#ec835a',
  MEDIUM: '#fab219',
  LOW: '#8a9bb4',
  INFO: '#5d697b',
};

export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  OPEN: 'Open',
  INVESTIGATING: 'Investigating',
  RESOLVED: 'Resolved',
  FALSE_POSITIVE: 'False positive',
};

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  OPEN: 'Open',
  INVESTIGATING: 'Investigating',
  RESOLVED: 'Resolved',
  CLOSED: 'Closed',
};

export const EVENT_TYPE_LABEL: Record<EventType, string> = {
  AUTH_SUCCESS: 'Login success',
  AUTH_FAILURE: 'Login failure',
  NETWORK_CONNECTION: 'Network connection',
  PROCESS_EXECUTION: 'Process execution',
  DNS_QUERY: 'DNS query',
  FILE_DOWNLOAD: 'File download',
};

export const REPUTATION_LABEL: Record<Reputation, string> = {
  MALICIOUS: 'Malicious',
  SUSPICIOUS: 'Suspicious',
  BENIGN: 'Benign',
};

export const INDICATOR_TYPE_LABEL: Record<IndicatorType, string> = {
  IP: 'IP address',
  DOMAIN: 'Domain',
  HASH: 'File hash',
};

export const ROLE_LABEL: Record<Role, string> = {
  ADMIN: 'Admin',
  ANALYST: 'Analyst',
  VIEWER: 'Viewer',
};

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const ALERT_STATUSES: AlertStatus[] = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
export const INCIDENT_STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];
export const EVENT_TYPES = Object.keys(EVENT_TYPE_LABEL) as EventType[];
