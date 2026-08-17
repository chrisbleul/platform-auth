import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

export interface CurrentUser {
  userId: string;
  email: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: CurrentUser;
  }
}

/**
 * Kein eigener Login -- die Anmeldung macht ausschliesslich cgo-auth.
 * nginx prueft jede Anfrage per auth_request gegen cgo-auth und setzt danach
 * X-Auth-User-Id/-Email selbst; ein vom Client gesendeter Wert wird dabei
 * verworfen (docs/arbeitsanweisung-app-plattform.md Abschnitt 3a im
 * CGOPlattform-Repo). Diese App muss den Headern nur noch vertrauen, nicht
 * mehr selbst pruefen.
 *
 * Setzt request.user, wenn die Header da sind -- entscheidet aber selbst
 * nicht, ob eine Route Auth braucht (siehe requireAuth). So bleiben
 * ungeschuetzte Routen wie /api/health weiterhin ohne Identitaet erreichbar.
 */
export function registerPlatformAuth(app: FastifyInstance): void {
  app.decorateRequest('user', undefined);

  app.addHook('onRequest', async (request) => {
    const userId = request.headers['x-auth-user-id'];
    const email = request.headers['x-auth-user-email'];
    if (typeof userId === 'string' && typeof email === 'string') {
      request.user = { userId, email };
    }
  });
}

/**
 * preHandler fuer Routen, die eine angemeldete Identitaet voraussetzen.
 * Fehlt der Header, ist das kein anonymer Zugriff, sondern ein
 * Konfigurationsfehler -- ohne nginx davor waere die Route gar nicht
 * erreichbar (Plattform-Vertrag Abschnitt 3.3: "mit 500 abbrechen, nicht
 * als anonymer Zugriff behandeln").
 */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (request.user === undefined) {
    request.log.error('X-Auth-User-Id fehlt -- Anfrage kam nicht durch nginx auth_request');
    await reply.code(500).send({ error: 'Konfigurationsfehler: keine Identität' });
  }
}
