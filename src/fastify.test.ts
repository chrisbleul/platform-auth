import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { registerPlatformAuth, requireAuth } from './fastify.js';

function buildApp() {
  const app = Fastify({ logger: false });
  registerPlatformAuth(app);

  app.get('/public', async () => ({ ok: true }));
  app.get('/protected', { preHandler: requireAuth }, async (request) => ({ user: request.user }));

  return app;
}

describe('registerPlatformAuth', () => {
  it('laesst eine Route ohne requireAuth unabhaengig vom Header durch', async () => {
    const app = buildApp();
    const res = await app.inject({ method: 'GET', url: '/public' });
    expect(res.statusCode).toBe(200);
  });

  it('setzt request.user, wenn beide Header vorhanden sind', async () => {
    const app = buildApp();
    const res = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: { 'x-auth-user-id': 'u1', 'x-auth-user-email': 'a@b.de' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ user: { userId: 'u1', email: 'a@b.de' } });
  });
});

describe('requireAuth', () => {
  it('antwortet mit 500 (nicht 401), wenn beide Header fehlen', async () => {
    // Plattform-Vertrag Abschnitt 3.3: ein fehlender Header ist ein
    // Konfigurationsfehler, kein anonymer Zugriff -- das ist der zentrale
    // Verhaltensunterschied, den AP6.1 vereinheitlichen soll.
    const app = buildApp();
    const res = await app.inject({ method: 'GET', url: '/protected' });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: 'Konfigurationsfehler: keine Identität' });
  });

  it('antwortet mit 500, wenn nur einer der beiden Header vorhanden ist', async () => {
    const app = buildApp();
    const res = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: { 'x-auth-user-id': 'u1' },
    });
    expect(res.statusCode).toBe(500);
  });
});
