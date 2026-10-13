import {describe,it,expect} from 'vitest';
import Fastify from 'fastify';
import type {Pool} from 'pg';
import {createMcpOAuth,OAUTH_MIGRATION_SQL} from './mcp-oauth.js';
const config={PUBLIC_URL:'https://example.org/todo',OAUTH_CLIENT_ID:'todo-chatgpt',OAUTH_REDIRECT_URIS:'https://chatgpt.com/connector_platform_oauth_redirect',OAUTH_ALLOWED_USER_IDS:'owner'};
describe('shared MCP OAuth',()=>{
  it('isolates app scopes, resource, issuer and login marker',async()=>{
    const todo=createMcpOAuth({slug:'todo',name:'ToDo'});const atlas=createMcpOAuth({slug:'atlas',name:'Atlas'});
    expect(todo.SCOPES).toEqual(['todo:read','todo:write']);expect(atlas.SCOPES).toEqual(['atlas:read','atlas:write']);
    const app=Fastify();await todo.registerOAuthRoutes(app,{} as Pool,config);
    expect((await app.inject('/.well-known/oauth-protected-resource')).json().resource).toBe('https://example.org/todo/api/mcp/chatgpt');
    expect((await app.inject('/oauth/.well-known/oauth-authorization-server')).json().issuer).toBe('https://example.org/todo/oauth');
    const redirect=await app.inject({url:'/oauth/authorize?state=a%26b',headers:{'x-todo-login-redirect':'1'}});
    expect(new URL(redirect.headers.location!,'https://example.org').searchParams.get('next')).toBe('/todo/oauth/authorize?state=a%26b');
    await app.close();
  });
  it('disabled OAuth registers no routes and rejects malformed slugs',async()=>{
    expect(()=>createMcpOAuth({slug:'../bad',name:'Bad'})).toThrow();
    const app=Fastify();await createMcpOAuth({slug:'todo',name:'Todo'}).registerOAuthRoutes(app,{} as Pool,{PUBLIC_URL:config.PUBLIC_URL});
    expect((await app.inject('/oauth/token')).statusCode).toBe(404);await app.close();
    expect(OAUTH_MIGRATION_SQL).toContain('create table oauth_token');expect(OAUTH_MIGRATION_SQL).not.toContain('alter table ticket');
  });
});
