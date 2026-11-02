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
export interface PlatformAuthOptions {
    /** Registry-Slug der App ("todo", "kitchen", ...), Teil der Signatur. */
    slug: string;
    /**
     * Schluessel der App (PLATFORM_AUTH_KEY, abgeleitet mit bin/derive-app-key.sh im
     * CGOPlattform-Repo). Gesetzt: nur signierte Identitaetsheader werden uebernommen. Leer oder
     * nicht gesetzt: die Header werden wie bisher ungeprueft uebernommen (Uebergangsbetrieb).
     */
    key?: string | undefined;
    maxSkewSeconds?: number;
}
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
export declare function registerPlatformAuth(app: FastifyInstance, options?: PlatformAuthOptions): void;
/**
 * preHandler fuer Routen, die eine angemeldete Identitaet voraussetzen.
 * Fehlt der Header, ist das kein anonymer Zugriff, sondern ein
 * Konfigurationsfehler -- ohne nginx davor waere die Route gar nicht
 * erreichbar (Plattform-Vertrag Abschnitt 3.3: "mit 500 abbrechen, nicht
 * als anonymer Zugriff behandeln").
 */
export declare function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void>;
