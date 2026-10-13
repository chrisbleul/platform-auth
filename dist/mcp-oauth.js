import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { requireAuth } from './fastify.js';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
async function withTx(pool, fn) {
    const tx = await pool.connect();
    try {
        await tx.query('begin');
        const result = await fn(tx);
        await tx.query('commit');
        return result;
    }
    catch (error) {
        await tx.query('rollback');
        throw error;
    }
    finally {
        tx.release();
    }
}
export function createMcpOAuth(options) {
    if (!/^[a-z][a-z0-9-]*$/.test(options.slug))
        throw new Error('Ungültiger OAuth-App-Slug');
    const loginHeader = (options.loginRedirectHeader ?? `x-${options.slug}-login-redirect`).toLowerCase();
    const CHATGPT_MCP_PATH = '/api/mcp/chatgpt';
    const SCOPES = [`${options.slug}:read`, `${options.slug}:write`];
    const opaque = () => randomBytes(32).toString('base64url');
    const tokenHash = (value) => createHash('sha256').update(value).digest('hex');
    const challengeFor = (value) => createHash('sha256').update(value).digest('base64url');
    const list = (value) => value?.split(',').map((v) => v.trim()).filter(Boolean) ?? [];
    const allowed = (config, id) => list(config.OAUTH_ALLOWED_USER_IDS).includes(id);
    const oauthResource = (config) => `${config.PUBLIC_URL}${CHATGPT_MCP_PATH}`;
    const issuer = (config) => `${config.PUBLIC_URL}/oauth`;
    const oauthChallenge = (config, error = 'invalid_token', scope = SCOPES[0]) => `Bearer resource_metadata="${config.PUBLIC_URL}/.well-known/oauth-protected-resource", error="${error}", error_description="Authorization required", scope="${scope}"`;
    /** Opaque Tokens: Ressource, Lebensdauer, Widerruf und Identität kommen aus der DB, nicht aus Client-Headern. */
    async function resolveOAuth(pool, config, header) {
        if (!config.OAUTH_CLIENT_ID || !header?.match(/^Bearer [A-Za-z0-9_-]{43}$/i))
            return null;
        const { rows } = await pool.query(`select g.user_id as "userId", g.email, g.client_id as "clientId", g.scopes, g.id as "grantId"
       from oauth_token t join oauth_grant g on g.id=t.grant_id
      where t.hash=$1 and t.kind='access' and t.expires_at>now() and not t.consumed
        and not g.revoked and g.expires_at>now() and g.resource=$2 and g.client_id=$3`, [tokenHash(header.slice(7)), oauthResource(config), config.OAUTH_CLIENT_ID]);
        const identity = rows[0];
        return identity && allowed(config, identity.userId) ? identity : null;
    }
    const noCache = (reply) => reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
    const error = (reply, name, status = 400) => noCache(reply).code(status).send({ error: name });
    const escape = (value) => value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
    const authQuery = z.object({
        response_type: z.literal('code'), client_id: z.string().min(1).max(200),
        redirect_uri: z.string().min(1).max(2048), resource: z.string().min(1).max(2048),
        scope: z.string().max(200).default(SCOPES[0]),
        code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), code_challenge_method: z.literal('S256'),
        state: z.string().max(2048).optional(),
    });
    const tokenInput = z.object({
        grant_type: z.enum(['authorization_code', 'refresh_token']), client_id: z.string().min(1).max(200),
        code: z.string().max(200).optional(), redirect_uri: z.string().max(2048).optional(),
        code_verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/).optional(),
        refresh_token: z.string().max(200).optional(), resource: z.string().max(2048).optional(),
        scope: z.string().max(200).optional(),
    });
    async function issueTokens(tx, grant) {
        const access = opaque();
        const refresh = opaque();
        await tx.query(`insert into oauth_token(hash,grant_id,kind,expires_at) values
      ($1,$3,'access',now()+interval '15 minutes'),
      ($2,$3,'refresh',(select expires_at from oauth_grant where id=$3))`, [tokenHash(access), tokenHash(refresh), grant.id]);
        return { access_token: access, token_type: 'Bearer', expires_in: 900, refresh_token: refresh, scope: grant.scopes.join(' ') };
    }
    async function registerOAuthRoutes(app, pool, config) {
        if (!config.OAUTH_CLIENT_ID)
            return;
        // Eigener Scope: Form-Parser und Rate-Limit verändern keine bestehenden API-Routen.
        await app.register(async (oauth) => {
            await oauth.register(rateLimit, { max: 60, timeWindow: '1 minute' });
            oauth.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string', bodyLimit: 8192 }, (_req, body, done) => {
                const params = new URLSearchParams(String(body));
                const values = {};
                for (const [key, value] of params) {
                    if (Object.hasOwn(values, key))
                        return done(Object.assign(new Error('Doppelte Formularfelder'), { statusCode: 400 }));
                    Object.defineProperty(values, key, { value, enumerable: true });
                }
                done(null, values);
            });
            oauth.get('/.well-known/oauth-protected-resource', async () => ({
                resource: oauthResource(config), authorization_servers: [issuer(config)], scopes_supported: SCOPES,
            }));
            const metadata = async () => ({
                issuer: issuer(config), authorization_endpoint: `${issuer(config)}/authorize`,
                token_endpoint: `${issuer(config)}/token`, revocation_endpoint: `${issuer(config)}/revoke`,
                response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
                token_endpoint_auth_methods_supported: ['none'], revocation_endpoint_auth_methods_supported: ['none'],
                code_challenge_methods_supported: ['S256'], scopes_supported: SCOPES,
                authorization_response_iss_parameter_supported: true,
            });
            // RFC 8414: nginx leitet den domainweiten Pfad mit Issuer-Suffix hierhin weiter.
            oauth.get('/oauth/.well-known/oauth-authorization-server', metadata);
            const browserAuth = async (request, reply) => {
                // no-referrer würde bei Formular-POSTs Origin:null erzeugen und unsere
                // Herkunftsprüfung auslösen. same-origin erhält Origin für eigene Formulare
                // und sendet beim externen OAuth-Callback weiterhin keinen Referrer.
                noCache(reply).header('Referrer-Policy', 'same-origin');
                // nginx schickt fehlgeschlagene CGO-Anmeldungen gezielt hierhin. Query-Werte
                // erneut kodieren, damit URLs in OAuth-Parametern den CGO-safeNext-Check bestehen.
                if (!request.user && request.headers[loginHeader] === '1') {
                    if (request.method !== 'GET')
                        return reply.code(401).send({ error: 'CGO-Anmeldung abgelaufen. Bitte die Verbindung erneut starten.' });
                    const requested = new URL(request.url, config.PUBLIC_URL);
                    const next = `${new URL(config.PUBLIC_URL).pathname.replace(/\/$/, '')}${requested.pathname}?${requested.searchParams.toString()}`;
                    return reply.redirect(`/auth/login?${new URLSearchParams({ next })}`);
                }
                await requireAuth(request, reply);
                if (reply.sent)
                    return;
                if (!allowed(config, request.user.userId))
                    return reply.code(403).send({ error: `${options.name}-Zugang nicht freigegeben` });
            };
            oauth.get('/oauth/authorize', { preHandler: browserAuth, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
                const parsed = authQuery.safeParse(request.query);
                if (!parsed.success)
                    return error(reply, 'invalid_request');
                const q = parsed.data;
                // Vor jeder Weiterleitung: exakte Registrierung prüfen, keine Wildcards oder offene Redirects.
                if (q.client_id !== config.OAUTH_CLIENT_ID || !list(config.OAUTH_REDIRECT_URIS).includes(q.redirect_uri))
                    return error(reply, 'invalid_client');
                if (q.resource !== oauthResource(config))
                    return error(reply, 'invalid_target');
                const scopes = [...new Set(q.scope.split(/\s+/).filter(Boolean))];
                if (!scopes.includes(SCOPES[0]) || scopes.some((s) => !SCOPES.includes(s)))
                    return error(reply, 'invalid_scope');
                const nonce = opaque();
                await pool.query(`delete from oauth_request where expires_at<now()`);
                await pool.query(`insert into oauth_request(hash,user_id,email,client_id,redirect_uri,resource,scopes,challenge,state,expires_at)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '10 minutes')`, [tokenHash(nonce), request.user.userId, request.user.email, q.client_id, q.redirect_uri, q.resource, scopes, q.code_challenge, q.state ?? null]);
                // Chromium prüft form-action auch bei der anschließenden OAuth-Weiterleitung.
                reply.header('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${new URL(q.redirect_uri).origin}; frame-ancestors 'none'; base-uri 'none'`);
                return reply.type('text/html').send(`<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(options.name)} mit ChatGPT verbinden</title>
        <style>body{font:17px/1.5 system-ui;max-width:36rem;margin:3rem auto;padding:1rem}button{font:inherit;padding:.6rem 1rem;margin:.3rem}h1{font-size:1.5rem}</style>
        <h1>${escape(options.name)} mit ChatGPT verbinden</h1><p>Angemeldet als ${escape(request.user.email)}.</p>
        <p>${escape(options.description ?? options.name)} lesen${scopes.includes(SCOPES[1]) ? ' und bearbeiten' : ''}.</p>
        <p>Die Freigabe gilt für 30 Tage. Du kannst sie unter <a href="${issuer(config)}/connections">ChatGPT-Verbindungen</a> jederzeit widerrufen.</p>
        <form method="post" action="${issuer(config)}/authorize"><input type="hidden" name="nonce" value="${nonce}">
        <button name="decision" value="allow">Verbindung erlauben</button><button name="decision" value="deny">Abbrechen</button></form></html>`);
            });
            oauth.post('/oauth/authorize', { preHandler: browserAuth, bodyLimit: 8192 }, async (request, reply) => {
                if (request.headers.origin !== new URL(config.PUBLIC_URL).origin)
                    return error(reply, 'invalid_request', 403);
                const parsed = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), decision: z.enum(['allow', 'deny']) }).safeParse(request.body);
                if (!parsed.success)
                    return error(reply, 'invalid_request');
                const result = await withTx(pool, async (tx) => {
                    const { rows } = await tx.query(`delete from oauth_request where hash=$1 and user_id=$2 and expires_at>now() and not approved returning *`, [tokenHash(parsed.data.nonce), request.user.userId]);
                    const pending = rows[0];
                    if (!pending || pending.client_id !== config.OAUTH_CLIENT_ID || !list(config.OAUTH_REDIRECT_URIS).includes(pending.redirect_uri) || pending.resource !== oauthResource(config))
                        return null;
                    const redirect = new URL(pending.redirect_uri);
                    redirect.searchParams.set('iss', issuer(config));
                    if (pending.state !== null)
                        redirect.searchParams.set('state', pending.state);
                    if (parsed.data.decision === 'deny')
                        redirect.searchParams.set('error', 'access_denied');
                    else {
                        const code = opaque();
                        await tx.query(`insert into oauth_request(hash,user_id,email,client_id,redirect_uri,resource,scopes,challenge,state,expires_at,approved,code_hash,code_expires_at)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '2 minutes',true,$1,now()+interval '2 minutes')`, [tokenHash(code), pending.user_id, pending.email, pending.client_id, pending.redirect_uri, pending.resource, pending.scopes, pending.challenge, pending.state]);
                        redirect.searchParams.set('code', code);
                    }
                    return redirect.toString();
                });
                return result ? reply.redirect(result) : error(reply, 'invalid_request');
            });
            oauth.post('/oauth/token', { bodyLimit: 8192 }, async (request, reply) => {
                const parsed = tokenInput.safeParse(request.body);
                if (!parsed.success)
                    return error(reply, 'invalid_request');
                const b = parsed.data;
                if (b.client_id !== config.OAUTH_CLIENT_ID || request.headers.authorization)
                    return error(reply, 'invalid_client');
                if (b.resource !== undefined && b.resource !== oauthResource(config))
                    return error(reply, 'invalid_target');
                const result = await withTx(pool, async (tx) => {
                    if (b.grant_type === 'authorization_code') {
                        if (!b.code || !b.code_verifier || !b.redirect_uri)
                            return null;
                        const { rows } = await tx.query(`select * from oauth_request where code_hash=$1 and approved and code_expires_at>now() for update`, [tokenHash(b.code)]);
                        const p = rows[0];
                        if (!p || p.client_id !== b.client_id || p.redirect_uri !== b.redirect_uri || !list(config.OAUTH_REDIRECT_URIS).includes(p.redirect_uri)
                            || p.resource !== oauthResource(config) || !allowed(config, p.user_id))
                            return null;
                        const expected = Buffer.from(p.challenge);
                        const actual = Buffer.from(challengeFor(b.code_verifier));
                        if (expected.length !== actual.length || !timingSafeEqual(expected, actual))
                            return null;
                        await tx.query('delete from oauth_request where code_hash=$1', [tokenHash(b.code)]);
                        const grant = await tx.query(`insert into oauth_grant(user_id,email,client_id,resource,scopes) values($1,$2,$3,$4,$5) returning *`, [p.user_id, p.email, p.client_id, p.resource, p.scopes]);
                        return issueTokens(tx, grant.rows[0]);
                    }
                    if (!b.refresh_token)
                        return null;
                    // Familien-Lock serialisiert auch parallele Rotationen/Widerrufe und prüft Wiederverwendung.
                    const grants = await tx.query(`select g.* from oauth_grant g join oauth_token t on t.grant_id=g.id
          where t.hash=$1 and t.kind='refresh' and g.client_id=$2 and not g.revoked and g.expires_at>now() for update of g`, [tokenHash(b.refresh_token), b.client_id]);
                    const g = grants.rows[0];
                    if (!g || g.resource !== oauthResource(config) || !allowed(config, g.user_id))
                        return null;
                    const tokens = await tx.query(`select consumed,expires_at>now() as valid from oauth_token where hash=$1`, [tokenHash(b.refresh_token)]);
                    if (tokens.rows[0]?.consumed) {
                        await tx.query('update oauth_grant set revoked=true where id=$1', [g.id]);
                        return null;
                    }
                    if (!tokens.rows[0]?.valid)
                        return null;
                    // Scopes bleiben identisch; Erweiterung oder Verkleinerung erfordert eine neue Einwilligung.
                    if (b.scope && b.scope.split(/\s+/).filter(Boolean).sort().join(' ') !== [...g.scopes].sort().join(' '))
                        return null;
                    await tx.query('update oauth_token set consumed=true where hash=$1', [tokenHash(b.refresh_token)]);
                    return issueTokens(tx, g);
                });
                return result ? noCache(reply).send(result) : error(reply, 'invalid_grant');
            });
            oauth.post('/oauth/revoke', { bodyLimit: 8192 }, async (request, reply) => {
                const parsed = z.object({ token: z.string().min(1).max(200), client_id: z.string().max(200), token_type_hint: z.string().optional() }).safeParse(request.body);
                if (!parsed.success)
                    return error(reply, 'invalid_request');
                if (parsed.data.client_id !== config.OAUTH_CLIENT_ID)
                    return error(reply, 'invalid_client');
                await pool.query(`update oauth_grant set revoked=true where client_id=$1 and id in (select grant_id from oauth_token where hash=$2)`, [parsed.data.client_id, tokenHash(parsed.data.token)]);
                return noCache(reply).send({});
            });
            // Sitzungsgebundener Widerruf: einmaliger, zufälliger CSRF-Nonce statt ungeschütztem POST.
            oauth.get('/oauth/connections', { preHandler: browserAuth }, async (request, reply) => {
                const nonce = opaque();
                await pool.query('delete from oauth_request where expires_at<now()');
                await pool.query(`insert into oauth_request(hash,user_id,email,client_id,redirect_uri,resource,scopes,challenge,expires_at)
        values($1,$2,$3,$4,'revoke','revoke','{}','revoke',now()+interval '10 minutes')`, [tokenHash(nonce), request.user.userId, request.user.email, config.OAUTH_CLIENT_ID]);
                const { rows } = await pool.query(`select id,created_at::text as created_at,scopes from oauth_grant where user_id=$1 and not revoked and expires_at>now() order by created_at desc`, [request.user.userId]);
                reply.header('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
                return reply.type('text/html').send(`<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ChatGPT-Verbindungen</title>
        <h1>ChatGPT-Verbindungen</h1><p>${escape(request.user.email)}</p>
        <form method="post" action="${issuer(config)}/connections"><input type="hidden" name="nonce" value="${nonce}">
        ${rows.map((g) => `<p>${escape(g.created_at)} · ${escape(g.scopes.join(', '))} <button name="grant" value="${g.id}">Widerrufen</button></p>`).join('') || '<p>Keine aktiven Verbindungen.</p>'}</form></html>`);
            });
            oauth.post('/oauth/connections', { preHandler: browserAuth, bodyLimit: 8192 }, async (request, reply) => {
                if (request.headers.origin !== new URL(config.PUBLIC_URL).origin)
                    return error(reply, 'invalid_request', 403);
                const parsed = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), grant: z.uuid() }).safeParse(request.body);
                if (!parsed.success)
                    return error(reply, 'invalid_request');
                const revoked = await withTx(pool, async (tx) => {
                    const csrf = await tx.query(`delete from oauth_request where hash=$1 and user_id=$2 and resource='revoke' and expires_at>now() returning hash`, [tokenHash(parsed.data.nonce), request.user.userId]);
                    if (!csrf.rowCount)
                        return false;
                    await tx.query('update oauth_grant set revoked=true where id=$1 and user_id=$2', [parsed.data.grant, request.user.userId]);
                    return true;
                });
                return revoked ? reply.redirect(`${issuer(config)}/connections`) : error(reply, 'invalid_request');
            });
        });
    }
    return { CHATGPT_MCP_PATH, SCOPES, tokenHash, oauthResource, oauthChallenge, resolveOAuth, registerOAuthRoutes };
}
export const OAUTH_MIGRATION_SQL = "-- OAuth ist ein separater Zugang; bestehende CGO-Tokens bleiben unver\u00e4ndert.\ncreate table oauth_request (\n  hash text primary key,\n  user_id text not null,\n  email text not null,\n  client_id text not null,\n  redirect_uri text not null,\n  resource text not null,\n  scopes text[] not null,\n  challenge text not null,\n  state text,\n  expires_at timestamptz not null,\n  approved boolean not null default false,\n  code_hash text unique,\n  code_expires_at timestamptz\n);\ncreate table oauth_grant (\n  id uuid primary key default gen_random_uuid(),\n  user_id text not null,\n  email text not null,\n  client_id text not null,\n  resource text not null,\n  scopes text[] not null,\n  created_at timestamptz not null default now(),\n  expires_at timestamptz not null default now() + interval '30 days',\n  revoked boolean not null default false\n);\ncreate table oauth_token (\n  hash text primary key,\n  grant_id uuid not null references oauth_grant(id) on delete cascade,\n  kind text not null check (kind in ('access','refresh')),\n  expires_at timestamptz not null,\n  consumed boolean not null default false\n);\ncreate index oauth_token_grant_idx on oauth_token(grant_id);\ncreate index oauth_request_expiry_idx on oauth_request(expires_at);\n\n";
//# sourceMappingURL=mcp-oauth.js.map