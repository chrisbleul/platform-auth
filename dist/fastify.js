import { parseTimestamp, verifyIdentity } from './signature.js';
/**
 * Kein eigener Login -- die Anmeldung macht ausschliesslich cgo-auth.
 * nginx prueft jede Anfrage per auth_request gegen cgo-auth und setzt danach
 * X-Auth-User-Id/-Email selbst; ein vom Client gesendeter Wert wird dabei
 * verworfen (docs/arbeitsanweisung-app-plattform.md Abschnitt 3a im
 * CGOPlattform-Repo).
 *
 * Mit options.key prueft die App zusaetzlich X-Auth-Signature (siehe signature.ts), damit nur
 * Header gelten, die cgo-auth fuer genau diese App ausgestellt hat. Ungueltige oder fehlende
 * Signaturen werden verworfen: request.user bleibt leer, requireAuth antwortet mit 500.
 *
 * Setzt request.user, wenn die Header da sind -- entscheidet aber selbst
 * nicht, ob eine Route Auth braucht (siehe requireAuth). So bleiben
 * ungeschuetzte Routen wie /api/health weiterhin ohne Identitaet erreichbar.
 */
export function registerPlatformAuth(app, options) {
    app.decorateRequest('user', undefined);
    const key = options?.key ? options.key : undefined;
    if (!key) {
        app.log.warn('PLATFORM_AUTH_KEY fehlt: Identitaetsheader werden ohne Signaturpruefung uebernommen');
    }
    app.addHook('onRequest', async (request) => {
        const userId = request.headers['x-auth-user-id'];
        const email = request.headers['x-auth-user-email'];
        if (typeof userId !== 'string' || typeof email !== 'string')
            return;
        if (key && options) {
            const signature = request.headers['x-auth-signature'];
            const timestamp = parseTimestamp(request.headers['x-auth-timestamp']);
            const identity = { slug: options.slug, userId, email, timestamp };
            const verifyOptions = options.maxSkewSeconds === undefined ? {} : { maxSkewSeconds: options.maxSkewSeconds };
            if (typeof signature !== 'string' ||
                !verifyIdentity(key, identity, signature, verifyOptions)) {
                request.log.warn('Identitaetsheader ohne gueltige Signatur verworfen');
                return;
            }
        }
        request.user = { userId, email };
    });
}
/**
 * preHandler fuer Routen, die eine angemeldete Identitaet voraussetzen.
 * Fehlt der Header, ist das kein anonymer Zugriff, sondern ein
 * Konfigurationsfehler -- ohne nginx davor waere die Route gar nicht
 * erreichbar (Plattform-Vertrag Abschnitt 3.3: "mit 500 abbrechen, nicht
 * als anonymer Zugriff behandeln").
 */
export async function requireAuth(request, reply) {
    if (request.user === undefined) {
        request.log.error('X-Auth-User-Id fehlt -- Anfrage kam nicht durch nginx auth_request');
        await reply.code(500).send({ error: 'Konfigurationsfehler: keine Identität' });
    }
}
//# sourceMappingURL=fastify.js.map