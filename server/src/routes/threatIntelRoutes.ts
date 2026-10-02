import { Router } from 'express';
import { createIndicator, listIndicators } from '../controllers/threatIntelController.js';
import { requireRole } from '../middleware/auth.js';

// Mounted behind requireAuth.
export function threatIntelRoutes() {
  const router = Router();
  router.get('/', listIndicators);
  router.post('/', requireRole('ADMIN', 'ANALYST'), createIndicator);
  return router;
}
