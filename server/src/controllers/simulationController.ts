import type { Request, Response } from 'express';
import { z } from 'zod';
import { SCENARIO_IDS } from '../simulation/scenarios.js';
import * as simulationService from '../services/simulationService.js';
import { sendData } from '../utils/respond.js';

const runScenarioSchema = z.object({ scenario: z.enum(SCENARIO_IDS) });

/** GET /api/simulate/scenarios */
export function listScenarios(_req: Request, res: Response) {
  sendData(res, simulationService.listScenarios());
}

/** POST /api/simulate */
export async function runScenario(req: Request, res: Response) {
  const { scenario } = runScenarioSchema.parse(req.body);
  sendData(res, await simulationService.runScenario(scenario), 201);
}
