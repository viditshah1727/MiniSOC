import { Router } from 'express';
import { listTechniques } from '../controllers/mitreController.js';

// Mounted behind requireAuth.
export function mitreRoutes() {
  const router = Router();
  router.get('/techniques', listTechniques);
  return router;
}
