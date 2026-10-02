// Centralised error handling. Every error thrown in a route, controller or
// service ends up here (Express 5 forwards rejected promises automatically),
// so responses are always consistent: { success: false, message, errors? }.
// Stack traces and internal details are logged, never sent to the client.
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { Prisma } from '../generated/prisma/client.js';
import { AppError } from '../utils/AppError.js';
import { logger } from '../utils/logger.js';

export const notFoundHandler: RequestHandler = (req, res) => {
  res.status(404).json({ success: false, message: `Route not found: ${req.method} ${req.originalUrl}` });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ success: false, message: err.message });
    return;
  }

  // Input failed a zod schema: report which fields and why.
  if (err instanceof ZodError) {
    const errors = err.issues.map((issue) => ({
      field: issue.path.join('.') || '(root)',
      message: issue.message,
    }));
    res.status(400).json({ success: false, message: 'Validation failed', errors });
    return;
  }

  // Errors raised by express.json() before our code runs.
  const bodyErrorType = (err as { type?: string }).type;
  if (bodyErrorType === 'entity.parse.failed') {
    res.status(400).json({ success: false, message: 'Request body is not valid JSON' });
    return;
  }
  if (bodyErrorType === 'entity.too.large') {
    res.status(413).json({ success: false, message: 'Request body is too large' });
    return;
  }

  // Database constraint violations that reach us are client mistakes.
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === 'P2002') {
      res.status(409).json({ success: false, message: 'A record with these values already exists' });
      return;
    }
    if (err.code === 'P2025') {
      res.status(404).json({ success: false, message: 'Record not found' });
      return;
    }
  }

  logger.error(`Unhandled error on ${req.method} ${req.originalUrl}`, err);
  res.status(500).json({ success: false, message: 'Internal server error' });
};
