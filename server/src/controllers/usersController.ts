import type { Request, Response } from 'express';
import * as userService from '../services/userService.js';
import { sendData } from '../utils/respond.js';

/** GET /api/users: used for the incident assignee picker. */
export async function listUsers(_req: Request, res: Response) {
  sendData(res, await userService.listUsers());
}
