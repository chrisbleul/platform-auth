/**
 * Signierte Identitaetsheader zwischen cgo-auth und den Apps.
 *
 * Ohne Signatur vertraut jede App X-Auth-User-Id/-Email blind. Das schuetzt nur, solange
 * ausschliesslich nginx die App erreicht; jeder Prozess auf dem Host oder Container im
 * gemeinsamen Docker-Netz koennte sich sonst als beliebiger Nutzer ausgeben.
 *
 * Ablauf: cgo-auth haelt ein Plattform-Geheimnis (AUTH_SIGNING_SECRET) und leitet daraus je App
 * einen eigenen Schluessel ab (deriveAppKey). Bei /verify signiert es Slug, Nutzer, E-Mail und
 * Zeitstempel mit dem Schluessel der App, zu der die Anfrage geroutet wird. nginx reicht
 * X-Auth-Timestamp und X-Auth-Signature mit durch, die App prueft mit ihrem eigenen Schluessel
 * (PLATFORM_AUTH_KEY). Eine kompromittierte App kennt nur ihren Schluessel und kann sich damit
 * nicht bei anderen Apps als jemand anderes ausgeben.
 */
export declare const SIGNATURE_VERSION = "v1";
export declare const DEFAULT_MAX_SKEW_SECONDS = 300;
export interface SignedIdentity {
    slug: string;
    userId: string;
    email: string;
    /** Unix-Zeit in Sekunden. */
    timestamp: number;
}
/**
 * Schluessel einer App aus dem Plattform-Geheimnis. Gleichwertig zu
 * `printf '%s' "cgo-app-key:v1:<slug>" | openssl dgst -sha256 -hmac "<geheimnis>"`
 * (bin/derive-app-key.sh im CGOPlattform-Repo).
 */
export declare function deriveAppKey(masterSecret: string, slug: string): string;
/** Wert fuer X-Auth-Signature, z. B. "v1=3f0c…". */
export declare function signIdentity(appKey: string, identity: SignedIdentity): string;
export interface VerifyOptions {
    nowSeconds?: number;
    maxSkewSeconds?: number;
}
/** true nur bei passender Signatur und Zeitstempel innerhalb der erlaubten Abweichung. */
export declare function verifyIdentity(appKey: string, identity: SignedIdentity, signature: string, options?: VerifyOptions): boolean;
/** Zeitstempel aus dem Header: nur Ziffern, sonst NaN. */
export declare function parseTimestamp(value: string | null | undefined): number;
