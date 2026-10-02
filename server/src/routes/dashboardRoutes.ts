import { Router } from 'express';
import { getStats } from '../controllers/dashboardController.js';

// Mounted behind requireAuth.
export function dashboardRoutes() {
  const router = Router();
  router.get('/stats', getStats);
  return router;
}
