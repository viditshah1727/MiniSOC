import type { Request, Response } from 'express';
import { idParamSchema } from '../schemas/common.js';
import { eventInputSchema, eventQuerySchema } from '../schemas/events.js';
import * as eventService from '../services/eventService.js';
import { buildPagination, sendData, sendPage } from '../utils/respond.js';

/** POST /api/events: ingest one event and run detection on it. */
export async function createEvent(req: Request, res: Response) {
  const input = eventInputSchema.parse(req.body);
  const { event, alerts } = await eventService.ingestEvent(input);

  sendData(
    res,
    {
      event,
      alerts: alerts.map((alert) => ({
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        riskScore: alert.riskScore,
        rule: alert.rule,
      })),
    },
    201,
  );
}

/** GET /api/events */
export async function listEvents(req: Request, res: Response) {
  const query = eventQuerySchema.parse(req.query);
  const { items, total } = await eventService.listEvents(query);
  sendPage(res, items, buildPagination(query.page, query.pageSize, total));
}

/** GET /api/events/:id */
export async function getEvent(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  sendData(res, await eventService.getEvent(id));
}
