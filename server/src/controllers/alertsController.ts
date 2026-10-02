import type { Request, Response } from 'express';
import { currentUser } from '../middleware/auth.js';
import { alertQuerySchema, alertUpdateSchema } from '../schemas/alerts.js';
import { idParamSchema } from '../schemas/common.js';
import * as aiAnalysisService from '../services/aiAnalysisService.js';
import * as alertService from '../services/alertService.js';
import { buildPagination, sendData, sendPage } from '../utils/respond.js';

/** GET /api/alerts */
export async function listAlerts(req: Request, res: Response) {
  const query = alertQuerySchema.parse(req.query);
  const { items, total } = await alertService.listAlerts(query);
  sendPage(res, items, buildPagination(query.page, query.pageSize, total));
}

/** GET /api/alerts/:id */
export async function getAlert(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  sendData(res, await alertService.getAlertDetail(id));
}

/** PATCH /api/alerts/:id */
export async function updateAlert(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  const input = alertUpdateSchema.parse(req.body);
  sendData(res, await alertService.updateAlert(id, input, currentUser(req)));
}

/** POST /api/alerts/:id/ai-analysis (optional feature; read-only) */
export async function analyzeAlert(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  sendData(res, await aiAnalysisService.analyzeAlert(id));
}
