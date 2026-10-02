import type { Request, Response } from 'express';
import { indicatorCreateSchema, indicatorQuerySchema } from '../schemas/threatIntel.js';
import * as threatIntelService from '../services/threatIntelService.js';
import { buildPagination, sendData, sendPage } from '../utils/respond.js';

/** GET /api/threat-intelligence */
export async function listIndicators(req: Request, res: Response) {
  const query = indicatorQuerySchema.parse(req.query);
  const { items, total } = await threatIntelService.listIndicators(query);
  sendPage(res, items, buildPagination(query.page, query.pageSize, total));
}

/** POST /api/threat-intelligence */
export async function createIndicator(req: Request, res: Response) {
  const input = indicatorCreateSchema.parse(req.body);
  sendData(res, await threatIntelService.createIndicator(input), 201);
}
