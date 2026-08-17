export interface CurrentUser {
    id: string;
    email: string;
}
/** Wird geworfen, wenn X-Auth-User-Id/-Email fehlen -- siehe currentUser(). */
export declare class ConfigurationError extends Error {
}
/** Alles, was next/headers' headers() und die Web-Standard-Headers-Klasse
 * gemeinsam haben -- absichtlich kein next-Import hier, damit dieses Paket
 * ohne Next.js als Abhaengigkeit auskommt und nicht an eine Next-Version
 * gebunden ist. */
export interface ReadonlyHeadersLike {
    get(name: string): string | null;
}
/**
 * nginx prueft jede Anfrage zentral gegen cgo-auth (auth_request) und setzt
 * X-Auth-User-Id/-Email erst NACH erfolgreicher Pruefung -- vom Client
 * mitgeschickte Werte werden dabei verworfen
 * (docs/arbeitsanweisung-app-plattform.md Abschnitt 3a im
 * CGOPlattform-Repo). Ein Request erreicht die App ueberhaupt nur, wenn die
 * Pruefung erfolgreich war; fehlen die Header trotzdem, lief der Request
 * nicht ueber nginx (z.B. direkter Aufruf waehrend der lokalen Entwicklung).
 *
 * Fuer Server Components/Server Actions: das Werfen ist hier beabsichtigt,
 * Next faengt es mit der naechsten error.tsx/dem Standard-Fehler-UI ab
 * (Plattform-Vertrag Abschnitt 3.3: ein fehlender Header ist ein
 * Konfigurationsfehler, kein anonymer Zugriff). Fuer Route Handler, die
 * JSON liefern muessen, requireUserOrResponse() weiter unten verwenden.
 */
export declare function currentUser(headersList: ReadonlyHeadersLike): CurrentUser;
/**
 * Variante fuer app/api/.../route.ts-Handler: liefert entweder den Nutzer
 * oder eine fertige 500-JSON-Response, statt ungefangen zu werfen (was in
 * einem Route Handler sonst Next's generische HTML-Fehlerseite ausliefert
 * -- falsch fuer einen JSON-Endpunkt). Aufrufer prueft "instanceof Response".
 */
export declare function requireUserOrResponse(headersList: ReadonlyHeadersLike): CurrentUser | Response;
