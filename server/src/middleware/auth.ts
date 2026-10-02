// Authentication (who are you?) and authorization (are you allowed?).
import type { CookieOptions, Request, RequestHandler } from 'express';
import { config } from '../config.js';
import type { Role } from '../generated/prisma/enums.js';
import { findSessionUser, readSessionToken } from '../services/authService.js';
import type { AuthUser } from '../types/express.js';
import { forbidden, unauthorized } from '../utils/AppError.js';

export const SESSION_COOKIE = 'minisoc_session';

export const sessionCookieOptions: CookieOptions = {
  httpOnly: true, // not readable from JavaScript (limits XSS damage)
  sameSite: 'strict', // never sent on cross-site requests (blocks CSRF)
  secure: config.isProduction, // HTTPS-only in production
  path: '/api',
  maxAge: config.sessionHours * 60 * 60 * 1000,
};

/** Rejects the request with 401 unless it carries a valid session cookie. */
export const requireAuth: RequestHandler = async (req, _res, next) => {
  const token: unknown = req.cookies?.[SESSION_COOKIE];
  const userId = typeof token === 'string' ? readSessionToken(token) : null;
  const user = userId ? await findSessionUser(userId) : null;
  if (!user) throw unauthorized();

  req.user = user;
  next();
};

/** Rejects the request with 403 unless the user has one of the given roles. */
export function requireRole(...allowed: Role[]): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) throw unauthorized();
    if (!allowed.includes(req.user.role)) throw forbidden();
    next();
  };
}

/** The logged-in user (for handlers behind requireAuth). */
export function currentUser(req: Request): AuthUser {
  if (!req.user) throw unauthorized();
  return req.user;
}
