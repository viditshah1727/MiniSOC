import type { Request, Response } from 'express';
import { alertFilterSchema } from '../schemas/alerts.js';
import { eventFilterSchema } from '../schemas/events.js';
import { incidentFilterSchema } from '../schemas/incidents.js';
import * as reportService from '../services/reportService.js';

function sendCsv(res: Response, name: string, csv: string) {
  const date = new Date().toISOString().slice(0, 10);
  res.attachment(`minisoc-${name}-${date}.csv`); // Content-Disposition: attachment
  res.type('text/csv').send(csv);
}

/** GET /api/reports/alerts.csv (accepts the alert list filters) */
export async function exportAlerts(req: Request, res: Response) {
  sendCsv(res, 'alerts', await reportService.alertsCsv(alertFilterSchema.parse(req.query)));
}

/** GET /api/reports/events.csv (accepts the event list filters) */
export async function exportEvents(req: Request, res: Response) {
  sendCsv(res, 'events', await reportService.eventsCsv(eventFilterSchema.parse(req.query)));
}

/** GET /api/reports/incidents.csv (accepts the incident list filters) */
export async function exportIncidents(req: Request, res: Response) {
  sendCsv(res, 'incidents', await reportService.incidentsCsv(incidentFilterSchema.parse(req.query)));
}
