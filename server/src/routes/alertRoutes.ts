import { Router } from 'express';
import { analyzeAlert, getAlert, listAlerts, updateAlert } from '../controllers/alertsController.js';
import { requireRole } from '../middleware/auth.js';
import { createAiRateLimiter } from '../middleware/rateLimit.js';

// Mounted behind requireAuth.
export function alertRoutes() {
  const router = Router();
  router.get('/', listAlerts);
  router.get('/:id', getAlert);
  router.patch('/:id', requireRole('ADMIN', 'ANALYST'), updateAlert);
  router.post('/:id/ai-analysis', requireRole('ADMIN', 'ANALYST'), createAiRateLimiter(), analyzeAlert);
  return router;
}
