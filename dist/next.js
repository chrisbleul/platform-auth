import { parseTimestamp, verifyIdentity } from './signature.js';
/** Wird geworfen, wenn X-Auth-User-Id/-Email fehlen -- siehe currentUser(). */
export class ConfigurationError extends Error {
}
const MISSING_HEADER_MESSAGE = 'Kein Auth-Header gesetzt -- Request kam nicht ueber nginx/auth_request.';
export function currentUser(headersList, options) {
    const id = headersList.get('x-auth-user-id');
    const email = headersList.get('x-auth-user-email');
    if (!id || !email) {
        throw new ConfigurationError(MISSING_HEADER_MESSAGE);
    }
    if (options?.key) {
        const signature = headersList.get('x-auth-signature');
        const timestamp = parseTimestamp(headersList.get('x-auth-timestamp'));
        if (!signature ||
            !verifyIdentity(options.key, { slug: options.slug, userId: id, email, timestamp }, signature)) {
            throw new ConfigurationError('Identitaetsheader ohne gueltige Signatur -- Request kam nicht ueber nginx/auth_request.');
        }
    }
    return { id, email };
}
/**
 * Variante fuer app/api/.../route.ts-Handler: liefert entweder den Nutzer
 * oder eine fertige 500-JSON-Response, statt ungefangen zu werfen (was in
 * einem Route Handler sonst Next's generische HTML-Fehlerseite ausliefert
 * -- falsch fuer einen JSON-Endpunkt). Aufrufer prueft "instanceof Response".
 */
export function requireUserOrResponse(headersList, options) {
    try {
        return currentUser(headersList, options);
    }
    catch (error) {
        if (error instanceof ConfigurationError) {
            return Response.json({ error: 'Konfigurationsfehler: keine Identität' }, { status: 500 });
        }
        throw error;
    }
}
//# sourceMappingURL=next.js.map