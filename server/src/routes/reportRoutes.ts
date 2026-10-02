import { Router } from 'express';
import { exportAlerts, exportEvents, exportIncidents } from '../controllers/reportsController.js';

// Mounted behind requireAuth.
export function reportRoutes() {
  const router = Router();
  router.get('/alerts.csv', exportAlerts);
  router.get('/events.csv', exportEvents);
  router.get('/incidents.csv', exportIncidents);
  return router;
}
