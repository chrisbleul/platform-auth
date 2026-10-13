import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
export interface OAuthConfig {
    PUBLIC_URL: string;
    OAUTH_CLIENT_ID?: string | undefined;
    OAUTH_REDIRECT_URIS?: string | undefined;
    OAUTH_ALLOWED_USER_IDS?: string | undefined;
}
export interface OAuthOptions {
    slug: string;
    name: string;
    loginRedirectHeader?: string;
    description?: string;
}
export interface OAuthIdentity {
    userId: string;
    email: string;
    clientId: string;
    scopes: string[];
    grantId: string;
}
export declare function createMcpOAuth(options: OAuthOptions): {
    CHATGPT_MCP_PATH: string;
    SCOPES: readonly [`${string}:read`, `${string}:write`];
    tokenHash: (value: string) => string;
    oauthResource: (config: OAuthConfig) => string;
    oauthChallenge: (config: OAuthConfig, error?: string, scope?: string) => string;
    resolveOAuth: (pool: Pool, config: OAuthConfig, header: string | undefined) => Promise<OAuthIdentity | null>;
    registerOAuthRoutes: (app: FastifyInstance, pool: Pool, config: OAuthConfig) => Promise<void>;
};
export declare const OAUTH_MIGRATION_SQL = "-- OAuth ist ein separater Zugang; bestehende CGO-Tokens bleiben unver\u00E4ndert.\ncreate table oauth_request (\n  hash text primary key,\n  user_id text not null,\n  email text not null,\n  client_id text not null,\n  redirect_uri text not null,\n  resource text not null,\n  scopes text[] not null,\n  challenge text not null,\n  state text,\n  expires_at timestamptz not null,\n  approved boolean not null default false,\n  code_hash text unique,\n  code_expires_at timestamptz\n);\ncreate table oauth_grant (\n  id uuid primary key default gen_random_uuid(),\n  user_id text not null,\n  email text not null,\n  client_id text not null,\n  resource text not null,\n  scopes text[] not null,\n  created_at timestamptz not null default now(),\n  expires_at timestamptz not null default now() + interval '30 days',\n  revoked boolean not null default false\n);\ncreate table oauth_token (\n  hash text primary key,\n  grant_id uuid not null references oauth_grant(id) on delete cascade,\n  kind text not null check (kind in ('access','refresh')),\n  expires_at timestamptz not null,\n  consumed boolean not null default false\n);\ncreate index oauth_token_grant_idx on oauth_token(grant_id);\ncreate index oauth_request_expiry_idx on oauth_request(expires_at);\n\n";
