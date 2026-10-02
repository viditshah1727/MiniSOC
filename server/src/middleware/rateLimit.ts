// Rate limiting slows down password guessing against our own login form.
// In-memory counters are fine for a single server process.
import { rateLimit } from 'express-rate-limit';

const FIFTEEN_MINUTES = 15 * 60 * 1000;

/** At most 10 failed login attempts per IP address every 15 minutes. */
export function createLoginRateLimiter() {
  return rateLimit({
    windowMs: FIFTEEN_MINUTES,
    limit: 10,
    skipSuccessfulRequests: true, // only failed attempts count
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Too many failed login attempts. Try again in 15 minutes.' },
  });
}

/** The optional AI assistant costs money per call: keep it to a human pace. */
export function createAiRateLimiter() {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Too many AI analysis requests. Try again in a minute.' },
  });
}

/** Generous cap on event ingestion so one client cannot flood the database. */
export function createIngestRateLimiter() {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: 600,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Event ingestion rate limit exceeded' },
  });
}
