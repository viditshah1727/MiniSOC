import type { Request, Response } from 'express';
import { currentUser } from '../middleware/auth.js';
import { idParamSchema } from '../schemas/common.js';
import {
  incidentCreateSchema,
  incidentNoteSchema,
  incidentQuerySchema,
  incidentUpdateSchema,
} from '../schemas/incidents.js';
import * as incidentService from '../services/incidentService.js';
import { buildPagination, sendData, sendPage } from '../utils/respond.js';

/** GET /api/incidents */
export async function listIncidents(req: Request, res: Response) {
  const query = incidentQuerySchema.parse(req.query);
  const { items, total } = await incidentService.listIncidents(query);
  sendPage(res, items, buildPagination(query.page, query.pageSize, total));
}

/** GET /api/incidents/:id */
export async function getIncident(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  sendData(res, await incidentService.getIncidentDetail(id));
}

/** POST /api/incidents */
export async function createIncident(req: Request, res: Response) {
  const input = incidentCreateSchema.parse(req.body);
  sendData(res, await incidentService.createIncident(input, currentUser(req)), 201);
}

/** PATCH /api/incidents/:id */
export async function updateIncident(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  const input = incidentUpdateSchema.parse(req.body);
  sendData(res, await incidentService.updateIncident(id, input, currentUser(req)));
}

/** POST /api/incidents/:id/notes */
export async function addIncidentNote(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  const { content } = incidentNoteSchema.parse(req.body);
  sendData(res, await incidentService.addIncidentNote(id, content, currentUser(req)), 201);
}
