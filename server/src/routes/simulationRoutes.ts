import { Router } from 'express';
import { listScenarios, runScenario } from '../controllers/simulationController.js';
import { requireRole } from '../middleware/auth.js';

// DEMO ONLY: mounted behind requireAuth, and only when ENABLE_SIMULATION=true.
export function simulationRoutes() {
  const router = Router();
  router.get('/scenarios', listScenarios);
  router.post('/', requireRole('ADMIN', 'ANALYST'), runScenario);
  return router;
}
