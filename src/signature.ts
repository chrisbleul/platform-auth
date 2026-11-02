import { createHmac, timingSafeEqual } from 'node:crypto';

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
export const SIGNATURE_VERSION = 'v1';
export const DEFAULT_MAX_SKEW_SECONDS = 300;

export interface SignedIdentity {
  slug: string;
  userId: string;
  email: string;
  /** Unix-Zeit in Sekunden. */
  timestamp: number;
}

const hmacHex = (key: string, message: string) =>
  createHmac('sha256', key).update(message).digest('hex');

/**
 * Schluessel einer App aus dem Plattform-Geheimnis. Gleichwertig zu
 * `printf '%s' "cgo-app-key:v1:<slug>" | openssl dgst -sha256 -hmac "<geheimnis>"`
 * (bin/derive-app-key.sh im CGOPlattform-Repo).
 */
export function deriveAppKey(masterSecret: string, slug: string): string {
  return hmacHex(masterSecret, `cgo-app-key:${SIGNATURE_VERSION}:${slug}`);
}

function message(identity: SignedIdentity): string {
  return [
    SIGNATURE_VERSION,
    identity.slug,
    identity.userId,
    identity.email,
    String(identity.timestamp),
  ].join('\n');
}

/** Wert fuer X-Auth-Signature, z. B. "v1=3f0c…". */
export function signIdentity(appKey: string, identity: SignedIdentity): string {
  return `${SIGNATURE_VERSION}=${hmacHex(appKey, message(identity))}`;
}

export interface VerifyOptions {
  nowSeconds?: number;
  maxSkewSeconds?: number;
}

/** true nur bei passender Signatur und Zeitstempel innerhalb der erlaubten Abweichung. */
export function verifyIdentity(
  appKey: string,
  identity: SignedIdentity,
  signature: string,
  options: VerifyOptions = {},
): boolean {
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const skew = options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS;
  if (!Number.isSafeInteger(identity.timestamp) || Math.abs(now - identity.timestamp) > skew)
    return false;
  const expected = Buffer.from(signIdentity(appKey, identity));
  const actual = Buffer.from(signature);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Zeitstempel aus dem Header: nur Ziffern, sonst NaN. */
export function parseTimestamp(value: string | null | undefined): number {
  return typeof value === 'string' && /^\d{1,12}$/.test(value) ? Number(value) : Number.NaN;
}
