import { describe, expect, it } from 'vitest';
import { ConfigurationError, currentUser, requireUserOrResponse } from './next.js';
import { deriveAppKey, signIdentity } from './signature.js';

function headersFrom(values: Record<string, string>): { get(name: string): string | null } {
  const lower = new Map(Object.entries(values).map(([k, v]) => [k.toLowerCase(), v]));
  return { get: (name) => lower.get(name.toLowerCase()) ?? null };
}

describe('currentUser', () => {
  it('liefert id+email, wenn beide Header gesetzt sind', () => {
    const result = currentUser(
      headersFrom({ 'x-auth-user-id': 'u1', 'x-auth-user-email': 'a@b.de' }),
    );
    expect(result).toEqual({ id: 'u1', email: 'a@b.de' });
  });

  it('wirft ConfigurationError, wenn beide Header fehlen', () => {
    expect(() => currentUser(headersFrom({}))).toThrow(ConfigurationError);
  });

  it('wirft ConfigurationError, wenn nur die Id fehlt', () => {
    expect(() => currentUser(headersFrom({ 'x-auth-user-email': 'a@b.de' }))).toThrow(
      ConfigurationError,
    );
  });

  it('wirft ConfigurationError, wenn nur die Email fehlt', () => {
    expect(() => currentUser(headersFrom({ 'x-auth-user-id': 'u1' }))).toThrow(ConfigurationError);
  });

  it('wirft ConfigurationError bei einem leeren String (nicht nur bei fehlendem Header)', () => {
    // nginx setzt bei fehlgeschlagener Pruefung ggf. einen leeren Header statt
    // ihn ganz wegzulassen -- ein leerer String darf nicht als "vorhanden"
    // durchgehen.
    expect(() =>
      currentUser(headersFrom({ 'x-auth-user-id': '', 'x-auth-user-email': 'a@b.de' })),
    ).toThrow(ConfigurationError);
  });
});

describe('requireUserOrResponse', () => {
  it('liefert den Nutzer direkt, wenn die Header da sind', () => {
    const result = requireUserOrResponse(
      headersFrom({ 'x-auth-user-id': 'u1', 'x-auth-user-email': 'a@b.de' }),
    );
    expect(result).toEqual({ id: 'u1', email: 'a@b.de' });
  });

  it('liefert eine 500-JSON-Response statt zu werfen, wenn Header fehlen', async () => {
    const result = requireUserOrResponse(headersFrom({}));

    expect(result).toBeInstanceOf(Response);
    const response = result as Response;
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: 'Konfigurationsfehler: keine Identität' });
  });
});

describe('currentUser mit Schluessel', () => {
  const key = deriveAppKey('plattform-geheimnis-fuer-tests-0123456789', 'opp');
  const timestamp = Math.floor(Date.now() / 1000);
  const signed = new Headers({
    'x-auth-user-id': 'u1',
    'x-auth-user-email': 'a@b.de',
    'x-auth-timestamp': String(timestamp),
    'x-auth-signature': signIdentity(key, {
      slug: 'opp',
      userId: 'u1',
      email: 'a@b.de',
      timestamp,
    }),
  });

  it('liefert den Nutzer bei gueltiger Signatur', () => {
    expect(currentUser(signed, { slug: 'opp', key })).toEqual({ id: 'u1', email: 'a@b.de' });
  });

  it('wirft bei fehlender oder fremder Signatur', () => {
    const unsigned = new Headers({ 'x-auth-user-id': 'u1', 'x-auth-user-email': 'a@b.de' });
    expect(() => currentUser(unsigned, { slug: 'opp', key })).toThrow(ConfigurationError);
    expect(() => currentUser(signed, { slug: 'kitchen', key })).toThrow(ConfigurationError);
  });
});
