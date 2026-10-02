import { Router } from 'express';
import {
  addIncidentNote,
  createIncident,
  getIncident,
  listIncidents,
  updateIncident,
} from '../controllers/incidentsController.js';
import { requireRole } from '../middleware/auth.js';

// Mounted behind requireAuth. Reading is open to every role; changes need ANALYST+.
export function incidentRoutes() {
  const router = Router();
  const canEdit = requireRole('ADMIN', 'ANALYST');

  router.get('/', listIncidents);
  router.get('/:id', getIncident);
  router.post('/', canEdit, createIncident);
  router.patch('/:id', canEdit, updateIncident);
  router.post('/:id/notes', canEdit, addIncidentNote);
  return router;
}
