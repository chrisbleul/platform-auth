import { describe, expect, it } from 'vitest';
import { deriveAppKey, parseTimestamp, signIdentity, verifyIdentity } from './signature.js';

const MASTER = 'plattform-geheimnis-fuer-tests-0123456789';
const identity = { slug: 'kitchen', userId: 'u1', email: 'a@b.de', timestamp: 1_800_000_000 };

describe('deriveAppKey', () => {
  it('stimmt mit openssl ueberein (bin/derive-app-key.sh)', () => {
    // printf '%s' "cgo-app-key:v1:kitchen" | openssl dgst -sha256 -hmac "$MASTER"
    expect(deriveAppKey(MASTER, 'kitchen')).toBe(
      '9affa6a23546a51e570ea8af7d86bc761a62b651cde134084a553e537c022b9b',
    );
  });

  it('liefert je App einen anderen Schluessel', () => {
    expect(deriveAppKey(MASTER, 'todo')).not.toBe(deriveAppKey(MASTER, 'kitchen'));
  });
});

describe('verifyIdentity', () => {
  const key = deriveAppKey(MASTER, 'kitchen');
  const signature = signIdentity(key, identity);
  const at = { nowSeconds: identity.timestamp + 10 };

  it('akzeptiert die passende Signatur', () => {
    expect(signature).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(verifyIdentity(key, identity, signature, at)).toBe(true);
  });

  it('lehnt veraenderte Nutzer, E-Mail oder App ab', () => {
    expect(verifyIdentity(key, { ...identity, userId: 'u2' }, signature, at)).toBe(false);
    expect(verifyIdentity(key, { ...identity, email: 'x@b.de' }, signature, at)).toBe(false);
    expect(verifyIdentity(key, { ...identity, slug: 'todo' }, signature, at)).toBe(false);
  });

  it('lehnt den Schluessel einer anderen App ab', () => {
    expect(verifyIdentity(deriveAppKey(MASTER, 'todo'), identity, signature, at)).toBe(false);
  });

  it('lehnt zu alte oder zu neue Zeitstempel ab', () => {
    expect(verifyIdentity(key, identity, signature, { nowSeconds: identity.timestamp + 301 })).toBe(
      false,
    );
    expect(verifyIdentity(key, identity, signature, { nowSeconds: identity.timestamp - 301 })).toBe(
      false,
    );
    expect(verifyIdentity(key, { ...identity, timestamp: Number.NaN }, signature, at)).toBe(false);
  });

  it('lehnt kaputte Signaturen ohne Ausnahme ab', () => {
    expect(verifyIdentity(key, identity, 'v1=abc', at)).toBe(false);
    expect(verifyIdentity(key, identity, '', at)).toBe(false);
  });
});

describe('parseTimestamp', () => {
  it('nimmt nur Ziffern', () => {
    expect(parseTimestamp('1800000000')).toBe(1_800_000_000);
    expect(Number.isNaN(parseTimestamp('18e8'))).toBe(true);
    expect(Number.isNaN(parseTimestamp(undefined))).toBe(true);
  });
});
