import type { Request, Response } from 'express';
import { currentUser } from '../middleware/auth.js';
import { idParamSchema } from '../schemas/common.js';
import { ruleUpdateSchema } from '../schemas/rules.js';
import * as ruleService from '../services/ruleService.js';
import { sendData } from '../utils/respond.js';

/** GET /api/rules */
export async function listRules(_req: Request, res: Response) {
  sendData(res, await ruleService.listRules());
}

/** PATCH /api/rules/:id */
export async function updateRule(req: Request, res: Response) {
  const { id } = idParamSchema.parse(req.params);
  const input = ruleUpdateSchema.parse(req.body);
  sendData(res, await ruleService.updateRule(id, input, currentUser(req)));
}
