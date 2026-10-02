import type { Request, Response } from 'express';
import { z } from 'zod';
import * as dashboardService from '../services/dashboardService.js';
import { sendData } from '../utils/respond.js';

const dashboardQuerySchema = z.object({
  range: z.enum(['24h', '7d']).default('24h'),
});

/** GET /api/dashboard/stats?range=24h|7d */
export async function getStats(req: Request, res: Response) {
  const { range } = dashboardQuerySchema.parse(req.query);
  sendData(res, await dashboardService.getDashboardStats(range));
}
