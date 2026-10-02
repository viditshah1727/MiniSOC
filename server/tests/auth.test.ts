import jwt from 'jsonwebtoken';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { envSchema } from '../src/config.js';
import { prisma } from '../src/db.js';
import { hashPassword } from '../src/services/authService.js';
import { buildApp, loginAs, resetDatabase, TEST_PASSWORD, TEST_USERS } from './helpers.js';

const app = buildApp();

beforeEach(async () => {
  await resetDatabase();
});

function sessionCookie(res: request.Response): string {
  const cookies = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = cookies?.find((c) => c.startsWith('minisoc_session='));
  if (!cookie) throw new Error('no session cookie set');
  return cookie;
}

describe('POST /api/auth/login', () => {
  it('logs in with valid credentials and sets a hardened session cookie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_USERS.ANALYST.email, password: TEST_PASSWORD })
      .expect(200);

    expect(res.body).toMatchObject({
      success: true,
      data: { user: { email: TEST_USERS.ANALYST.email, role: 'ANALYST' } },
    });
    expect(res.body.data.user).not.toHaveProperty('passwordHash');

    const cookie = sessionCookie(res);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    expect(cookie).toMatch(/Path=\/api/);
  });

  it('accepts the email case-insensitively', async () => {
    await request(app)
      .post('/api/auth/login')
      .send({ email: '  ANALYST@Test.Local ', password: TEST_PASSWORD })
      .expect(200);
  });

  it('returns the same generic error for a wrong password and an unknown email', async () => {
    const wrongPassword = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_USERS.ANALYST.email, password: 'not-the-password' })
      .expect(401);
    const unknownEmail = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@test.local', password: 'whatever' })
      .expect(401);

    expect(wrongPassword.body).toEqual({ success: false, message: 'Invalid email or password' });
    expect(unknownEmail.body).toEqual(wrongPassword.body);
    expect(wrongPassword.headers['set-cookie']).toBeUndefined();
  });

  it('rejects malformed input with field-level validation errors', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'not-an-email' }).expect(400);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('Validation failed');
    const fields = res.body.errors.map((e: { field: string }) => e.field);
    expect(fields).toEqual(expect.arrayContaining(['email', 'password']));
  });

  it('rate-limits repeated failed attempts from the same client', async () => {
    const limitedApp = buildApp(); // fresh limiter state
    for (let i = 0; i < 10; i++) {
      await request(limitedApp)
        .post('/api/auth/login')
        .send({ email: TEST_USERS.ANALYST.email, password: `guess-${i}` })
        .expect(401);
    }
    const blocked = await request(limitedApp)
      .post('/api/auth/login')
      .send({ email: TEST_USERS.ANALYST.email, password: TEST_PASSWORD })
      .expect(429);
    expect(blocked.body.success).toBe(false);
  });
});

describe('session handling', () => {
  it('GET /api/auth/me requires a session', async () => {
    const res = await request(app).get('/api/auth/me').expect(401);
    expect(res.body).toEqual({ success: false, message: 'Authentication required' });
  });

  it('GET /api/auth/me returns the user and feature flags', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/auth/me').expect(200);

    expect(res.body.data.user).toMatchObject({ email: TEST_USERS.VIEWER.email, role: 'VIEWER' });
    expect(res.body.data.features).toEqual({ simulation: true, aiAssistant: false });
  });

  it('rejects a token signed with the wrong secret', async () => {
    const forged = jwt.sign({}, 'attacker-controlled-secret-attacker-controlled', { subject: '1' });
    await request(app).get('/api/auth/me').set('Cookie', `minisoc_session=${forged}`).expect(401);
  });

  it('rejects an unsigned "alg: none" token', async () => {
    const unsigned = jwt.sign({}, '', { subject: '1', algorithm: 'none' });
    await request(app).get('/api/auth/me').set('Cookie', `minisoc_session=${unsigned}`).expect(401);
  });

  it('rejects a valid token once the user no longer exists', async () => {
    const agent = await loginAs(app, 'ANALYST');
    await prisma.user.delete({ where: { email: TEST_USERS.ANALYST.email } });
    await agent.get('/api/auth/me').expect(401);
  });

  it('POST /api/auth/logout clears the session cookie', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent.post('/api/auth/logout').expect(200);
    expect(sessionCookie(res)).toMatch(/Expires=Thu, 01 Jan 1970/);
    await agent.get('/api/auth/me').expect(401);
  });
});

describe('password storage', () => {
  it('stores salted bcrypt hashes, never plaintext', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { email: TEST_USERS.ADMIN.email } });
    expect(user.passwordHash).not.toContain(TEST_PASSWORD);
    expect(user.passwordHash).toMatch(/^\$2[aby]\$\d{2}\$/);

    const again = await hashPassword(TEST_PASSWORD);
    expect(again).not.toBe(user.passwordHash); // random salt per hash
  });

  it('uses a bcrypt cost of 12 unless configured otherwise', () => {
    expect(envSchema.shape.BCRYPT_ROUNDS.parse(undefined)).toBe(12);
  });
});
