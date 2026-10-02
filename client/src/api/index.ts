// Every MiniSOC API call, grouped by resource and fully typed.
import type {
  Activity,
  AiAnalysis,
  AlertDetail,
  AlertListItem,
  AlertStatus,
  DashboardRange,
  DashboardStats,
  DetectionRuleRow,
  EventDetail,
  EventListItem,
  IncidentDetail,
  IncidentListItem,
  IncidentStatus,
  Indicator,
  IndicatorListItem,
  IndicatorType,
  MitreTechniqueRow,
  Reputation,
  Scenario,
  Session,
  Severity,
  SimulationResult,
  User,
} from '../types/api';
import { type QueryParams, request, requestPage, toQueryString } from './client';

export interface NewIndicator {
  type: IndicatorType;
  indicator: string;
  reputation: Reputation;
  confidence: number;
  source: string;
  description?: string;
}

export interface NewIncident {
  alertIds: number[];
  title?: string;
  description?: string;
  severity?: Severity;
  assigneeId?: number | null;
}

export const api = {
  auth: {
    me: () => request<Session>('/auth/me'),
    login: (email: string, password: string) =>
      request<{ user: User }>('/auth/login', { method: 'POST', body: { email, password } }),
    logout: () => request<{ loggedOut: boolean }>('/auth/logout', { method: 'POST' }),
  },

  dashboard: {
    stats: (range: DashboardRange, signal?: AbortSignal) =>
      request<DashboardStats>('/dashboard/stats', { params: { range }, signal }),
  },

  events: {
    list: (params: QueryParams, signal?: AbortSignal) => requestPage<EventListItem>('/events', { params, signal }),
    get: (id: number, signal?: AbortSignal) => request<EventDetail>(`/events/${id}`, { signal }),
  },

  alerts: {
    list: (params: QueryParams, signal?: AbortSignal) => requestPage<AlertListItem>('/alerts', { params, signal }),
    get: (id: number, signal?: AbortSignal) => request<AlertDetail>(`/alerts/${id}`, { signal }),
    update: (id: number, body: { status?: AlertStatus; note?: string }) =>
      request<AlertDetail>(`/alerts/${id}`, { method: 'PATCH', body }),
    analyze: (id: number) => request<AiAnalysis>(`/alerts/${id}/ai-analysis`, { method: 'POST' }),
  },

  incidents: {
    list: (params: QueryParams, signal?: AbortSignal) => requestPage<IncidentListItem>('/incidents', { params, signal }),
    get: (id: number, signal?: AbortSignal) => request<IncidentDetail>(`/incidents/${id}`, { signal }),
    create: (body: NewIncident) => request<IncidentDetail>('/incidents', { method: 'POST', body }),
    update: (id: number, body: { status?: IncidentStatus; assigneeId?: number | null }) =>
      request<IncidentDetail>(`/incidents/${id}`, { method: 'PATCH', body }),
    addNote: (id: number, content: string) =>
      request<Activity>(`/incidents/${id}/notes`, { method: 'POST', body: { content } }),
  },

  threatIntel: {
    list: (params: QueryParams, signal?: AbortSignal) =>
      requestPage<IndicatorListItem>('/threat-intelligence', { params, signal }),
    create: (body: NewIndicator) => request<Indicator>('/threat-intelligence', { method: 'POST', body }),
  },

  mitre: {
    techniques: (signal?: AbortSignal) => request<MitreTechniqueRow[]>('/mitre/techniques', { signal }),
  },

  rules: {
    list: (signal?: AbortSignal) => request<DetectionRuleRow[]>('/rules', { signal }),
    update: (id: number, body: { enabled?: boolean; threshold?: number; windowMinutes?: number }) =>
      request<DetectionRuleRow>(`/rules/${id}`, { method: 'PATCH', body }),
  },

  users: {
    list: (signal?: AbortSignal) => request<User[]>('/users', { signal }),
  },

  simulation: {
    scenarios: (signal?: AbortSignal) => request<Scenario[]>('/simulate/scenarios', { signal }),
    run: (scenario: string) => request<SimulationResult>('/simulate', { method: 'POST', body: { scenario } }),
  },

  /** CSV exports are plain links: the browser downloads them with the session cookie. */
  reports: {
    url: (report: 'alerts' | 'events' | 'incidents', params: QueryParams = {}) =>
      `/api/reports/${report}.csv${toQueryString(params)}`,
  },
};
