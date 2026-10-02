// GET /api/stream: real-time updates via Server-Sent Events (SSE).
//
// Why SSE and not WebSockets: updates only flow server -> browser, SSE is
// plain HTTP (the session cookie and requireAuth just work), the browser
// reconnects automatically, and no extra library is needed.
import type { Request, Response } from 'express';
import { type LiveUpdate, subscribeToLiveUpdates } from '../utils/liveUpdates.js';

const HEARTBEAT_MS = 25_000; // keeps proxies from closing an idle connection

export function streamLiveUpdates(req: Request, res: Response) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // disable buffering in nginx-style proxies
  });
  res.write('retry: 5000\n\n'); // browser reconnect delay after a drop

  const unsubscribe = subscribeToLiveUpdates((update: LiveUpdate) => {
    res.write(`data: ${JSON.stringify(update)}\n\n`);
  });
  const heartbeat = setInterval(() => res.write(': ping\n\n'), HEARTBEAT_MS);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}
