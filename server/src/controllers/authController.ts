import type { Request, Response } from 'express';
import { config } from '../config.js';
import { currentUser, SESSION_COOKIE, sessionCookieOptions } from '../middleware/auth.js';
import { loginSchema } from '../schemas/auth.js';
import { createSessionToken, verifyCredentials } from '../services/authService.js';
import { sendData } from '../utils/respond.js';

/** POST /api/auth/login */
export async function login(req: Request, res: Response) {
  const { email, password } = loginSchema.parse(req.body);
  const user = await verifyCredentials(email, password);

  res.cookie(SESSION_COOKIE, createSessionToken(user.id), sessionCookieOptions);
  sendData(res, { user });
}

/** POST /api/auth/logout */
export function logout(_req: Request, res: Response) {
  const { maxAge: _maxAge, ...clearOptions } = sessionCookieOptions;
  res.clearCookie(SESSION_COOKIE, clearOptions);
  sendData(res, { loggedOut: true });
}

/** GET /api/auth/me: the current user plus which optional features are on. */
export function me(req: Request, res: Response) {
  sendData(res, {
    user: currentUser(req),
    features: {
      simulation: config.enableSimulation,
      aiAssistant: Boolean(config.anthropicApiKey),
    },
  });
}
