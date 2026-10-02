import type { Request, Response } from 'express';
import { prisma } from '../db.js';
import { sendData } from '../utils/respond.js';

/** GET /api/health: liveness check that also verifies the database connection. */
export async function getHealth(_req: Request, res: Response) {
  try {
    await prisma.$queryRaw`SELECT 1`;
    sendData(res, { status: 'ok', database: 'up' });
  } catch {
    res.status(503).json({ success: false, message: 'Database unavailable' });
  }
}
