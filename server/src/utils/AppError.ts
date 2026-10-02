// An error that is safe to show to the API client. Anything that is NOT an
// AppError is treated as an unexpected bug: logged, and hidden behind a 500.
export class AppError extends Error {
  readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
  }
}

export const badRequest = (message: string) => new AppError(400, message);
export const unauthorized = (message = 'Authentication required') => new AppError(401, message);
export const forbidden = (message = 'You do not have permission to perform this action') =>
  new AppError(403, message);
export const notFound = (resource: string) => new AppError(404, `${resource} not found`);
export const conflict = (message: string) => new AppError(409, message);
