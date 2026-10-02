import type { Request, Response } from 'express';
import * as mitreService from '../services/mitreService.js';
import { sendData } from '../utils/respond.js';

/** GET /api/mitre/techniques */
export async function listTechniques(_req: Request, res: Response) {
  sendData(res, await mitreService.listTechniques());
}
