# @cgo/platform-auth

Gemeinsamer Adapter fuer die Identitaets-Header, die nginx nach einer
erfolgreichen `auth_request`-Pruefung gegen `cgo-auth` setzt
(`X-Auth-User-Id`, `X-Auth-User-Email`) -- siehe
`docs/arbeitsanweisung-app-plattform.md` Abschnitt 3a im
[`chrisbleul/CGOPlattform`](https://github.com/chrisbleul/CGOPlattform)-Repo.

## Herkunft

Sechs Apps auf `cgo-app.de` lasen diese Header bislang selbst aus, mit fast
wortgleichem Kommentarblock -- reagierten bei fehlendem Header aber auf vier
verschiedene Arten (401, 401+Nutzer-Anlage, 500, `throw`). Der eigentliche
Gewinn dieses Pakets ist nicht die gesparte Codemenge, sondern dass die
Frage *"was ist die richtige Antwort auf einen fehlenden Header?"* jetzt
einmal beantwortet ist: **500 "Konfigurationsfehler"**, nie ein anonymer
401 (Plattform-Vertrag Abschnitt 3.3 -- ohne nginx davor waere die Route gar
nicht erreichbar, ein fehlender Header ist also ein Fehler in der
Infrastruktur, kein legitimer unangemeldeter Zugriff).

## Warum ein eigenes, oeffentliches Repo statt eines GHCR-npm-Pakets

GHCR bindet ein veroeffentlichtes Paket an das Repo, das es zuerst pushte --
ein anderes Repo bekommt mit seinem eigenen `GITHUB_TOKEN`
`permission_denied: read_package` (siehe die HERKUNFT.md-Eintraege zum
Design System in `CGOPlattform`/`ToDoCGO` fuer die ausfuehrliche
Begruendung). Als eigenes, **oeffentliches** Repo installiert sich dieses
Paket dagegen ohne jedes Zugriffstoken:

```bash
npm install github:chrisbleul/platform-auth#v1.0.0
```

Der Inhalt ist reine Header-Validierung ohne jedes Geheimnis -- Oeffentlichkeit
kostet hier nichts.

## Nutzung

### Fastify (`@cgo/platform-auth/fastify`)

```ts
import { registerPlatformAuth, requireAuth } from '@cgo/platform-auth/fastify';

registerPlatformAuth(app); // einmal beim Start

app.get('/api/health', async () => ({ ok: true })); // kein requireAuth noetig
app.get('/api/tasks', { preHandler: requireAuth }, async (request) => {
  // request.user ist hier garantiert gesetzt (sonst haette requireAuth
  // schon mit 500 geantwortet)
  return listTasks(request.user!.userId);
});
```

### Next.js (`@cgo/platform-auth/next`)

Framework-agnostisch (kein `next`-Import, keine Versionsbindung) -- braucht
nur ein Objekt mit `.get(name)`, wie es `next/headers`' `headers()` und die
Web-Standard-`Headers`-Klasse beide liefern.

```ts
// Server Component / Server Action: wirft bei fehlendem Header, Next faengt
// es mit dem naechsten error.tsx ab.
import { headers } from 'next/headers';
import { currentUser } from '@cgo/platform-auth/next';

const user = currentUser(await headers());
```

```ts
// app/api/.../route.ts: liefert bei fehlendem Header eine fertige
// 500-JSON-Response statt ungefangen zu werfen (sonst liefert der Handler
// Next's generische HTML-Fehlerseite statt JSON).
import { headers } from 'next/headers';
import { requireUserOrResponse } from '@cgo/platform-auth/next';

export async function DELETE() {
  const userOrResponse = requireUserOrResponse(await headers());
  if (userOrResponse instanceof Response) return userOrResponse;
  const user = userOrResponse;
  // ...
}
```

## App-eigene Logik bleibt app-eigen

Dieses Paket beantwortet nur "wer ist angemeldet, und was, wenn niemand
ist". Alles, was danach kommt -- lokale Nutzer-Tabellen, automatisches
Anlegen eines Kontos beim ersten Zugriff (Haushaltsplaner), Rollen/RBAC
(UiTool) -- bleibt bewusst in der jeweiligen App. Ein gemeinsames Paket, das
auch noch das Datenmodell jeder App kennen muesste, waere keine
Vereinfachung mehr.

## Entwicklung

```bash
npm install
npm test
npm run build   # vor jedem Commit an src/ -- dist/ ist eingecheckt
```

## Versionierung

Konsumenten pinnen einen Git-Tag (`#v1.0.0`), nicht `#main` -- ein Bug hier
wuerde sonst alle sechs Apps gleichzeitig treffen, ohne dass eine App-CI ihn
vorher gefangen haette.

## MCP OAuth (ab 1.1.0)

`@cgo/platform-auth/mcp-oauth` exportiert `createMcpOAuth({slug,name,description?,loginRedirectHeader?})`.
Die Instanz liefert `registerOAuthRoutes(app,pool,config)`, `resolveOAuth`, `oauthChallenge`,
`oauthResource`, `SCOPES`, `CHATGPT_MCP_PATH` und `tokenHash`. `OAuthIdentity` beschreibt
Benutzer, Client, Freigabe und Scopes. `OAUTH_MIGRATION_SQL` liefert ausschließlich die drei
OAuth-Tabellen und Indizes; diese SQL als eigene nummerierte App-Migration übernehmen.
Bestehende Atlas-Tabellen und Tokens bleiben kompatibel. Die Bibliothek verändert keine Fachtabellen.

Config: `PUBLIC_URL`, optional `OAUTH_CLIENT_ID`, `OAUTH_REDIRECT_URIS`, `OAUTH_ALLOWED_USER_IDS`.
Ohne Client-ID ist OAuth aus. Apps müssen bei aktivem OAuth HTTPS, exakte Callback-URLs und
nichtleere Benutzer-Allowlist beim Start validieren. Der Benutzer-Header-Adapter muss vor
OAuth registriert werden. nginx prüft Browseridentität und überschreibt/entfernt Clientheader;
MCP-Aufrufe verwenden ausschließlich die von `resolveOAuth` gelieferte Identität und müssen
Benutzerbegrenzung sowie Tool-Scopes selbst durchsetzen.

Authorization Code mit PKCE/S256, öffentlicher vorregistrierter Client ohne Secret,
gehashte opaque Tokens, Refresh-Rotation, Widerruf, sitzungsgebundene Einwilligung und
Origin-Prüfung. Eine Freigabe läuft maximal 30 Tage, ein Access-Token 15 Minuten.
Die App hält OAuth-Tokens in ihrer eigenen Datenbank. Beim Entzug von CGO-App-Rechten
zusätzlich die OAuth-Allowlist anpassen oder Freigaben widerrufen.
