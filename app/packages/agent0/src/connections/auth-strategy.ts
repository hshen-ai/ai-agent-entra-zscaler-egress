// auth-strategy.ts — Uniform MCP auth strategy interface.
//
// Wraps the two existing credential handlers so Agent.connect() can iterate
// over multiple MCPs without caring which auth flavor each one uses:
//   - ID-JAG (authorization_server managed connection, same-org Okta custom AS)
//   - OAuth STS (mcp_server managed connection, external AS like GitHub)
//
// The handlers themselves (TokenExchangeHandler, OAuthStsHandler) are NOT
// rewritten — these are thin adapters that normalize their results into an
// AuthTokenResult discriminated union.
import { TokenExchangeHandler, TokenExchangeConfig } from './authorization-server/handler.js';
import { OAuthStsHandler, OAuthStsConfig } from './application/handler.js';
// Entra's On-Behalf-Of exchange. A real import rather than the require() used inside okta-auth.ts,
// because this file needs the CONFIG TYPE at compile time, not just the function at runtime.
import { entraOnBehalfOf, loadEntraOboConfig } from '../auth/entra-obo.js';

// ============================================================================
// Result shape (discriminated union)
// ============================================================================

export type AuthTokenResult =
  | { status: 'success'; accessToken: string; expiresIn: number; scope?: string }
  | { status: 'interaction_required'; interactionUri: string; resource: string; message?: string }
  | { status: 'error'; error: string; errorDescription?: string };

// ============================================================================
// Strategy interface
// ============================================================================

// 'obo' is Entra's equivalent of 'id-jag'. Both turn a login artifact into a resource token; the
// difference is that Entra rejects RFC 8693 token-exchange (AADSTS70003) and starts from an ACCESS
// token rather than an ID token.
export type AuthStrategyKind = 'id-jag' | 'oauth-sts' | 'obo';

export interface AuthStrategy {
  readonly kind: AuthStrategyKind;
  /**
   * Human-oriented resource identifier — OAuth STS Resource Indicator URI for
   * oauth-sts, or the AS issuer URL for id-jag. Surfaced in pending-consent
   * responses and status logs.
   */
  readonly resource: string;

  /**
   * Acquire an access token for the MCP transport. `requestedScopes` is only
   * meaningful for id-jag (scope step-up); oauth-sts ignores it.
   */
  getAccessToken(idToken: string, requestedScopes?: string): Promise<AuthTokenResult>;

  /** Drop any cached token — use when the resource returns 401/403. */
  clearCache(): void;
}

// ============================================================================
// ID-JAG adapter
// ============================================================================

export class IdJagAuthStrategy implements AuthStrategy {
  readonly kind = 'id-jag' as const;
  readonly resource: string;
  private handler: TokenExchangeHandler;

  constructor(config: TokenExchangeConfig) {
    this.handler = new TokenExchangeHandler(config);
    this.resource = config.authorizationServer;
  }

  async getAccessToken(idToken: string, requestedScopes?: string): Promise<AuthTokenResult> {
    try {
      const result = await this.handler.exchangeToken(idToken, requestedScopes);
      if (result.success && result.access_token) {
        return {
          status: 'success',
          accessToken: result.access_token,
          expiresIn: result.expires_in ?? 3600,
          scope: result.scope,
        };
      }
      return {
        status: 'error',
        error: 'token_exchange_failed',
        errorDescription: result.note || 'ID-JAG exchange did not return an access token',
      };
    } catch (err: any) {
      return {
        status: 'error',
        error: 'token_exchange_error',
        errorDescription: err?.message || String(err),
      };
    }
  }

  /** TokenExchangeHandler does not cache today; method kept for interface parity. */
  clearCache(): void { /* no-op */ }

  /** Escape hatch for reconnect flow that still uses TokenExchangeHandler directly. */
  getUnderlyingHandler(): TokenExchangeHandler {
    return this.handler;
  }
}

// ============================================================================
// OAuth STS adapter
// ============================================================================

export class OAuthStsAuthStrategy implements AuthStrategy {
  readonly kind = 'oauth-sts' as const;
  readonly resource: string;
  private handler: OAuthStsHandler;

  constructor(config: OAuthStsConfig) {
    this.handler = new OAuthStsHandler(config);
    this.resource = config.resource;
  }

  async getAccessToken(idToken: string): Promise<AuthTokenResult> {
    const result = await this.handler.exchangeForISVToken(idToken);
    if (result.status === 'success') {
      return {
        status: 'success',
        accessToken: result.access_token,
        expiresIn: result.expires_in,
        scope: result.scope,
      };
    }
    if (result.status === 'interaction_required') {
      return {
        status: 'interaction_required',
        interactionUri: result.interaction_uri,
        resource: this.resource,
        message: result.error_description,
      };
    }
    return {
      status: 'error',
      error: result.error,
      errorDescription: result.error_description,
    };
  }

  clearCache(): void {
    this.handler.clearCachedToken();
  }

  /** Exposed so /api/oauth-sts/status and tool-execution paths can reuse the cache. */
  getUnderlyingHandler(): OAuthStsHandler {
    return this.handler;
  }
}

// ============================================================================
// Entra On-Behalf-Of adapter
// ============================================================================
// Sits with the other two adapters, above the "MCP connection config" banner, because that is
// where a reader looks for it. Anchoring on the banner's own comment and stepping back over it is
// what keeps it here rather than wedged between that banner and the type it introduces.

export interface OboStrategyConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /**
   * Space-delimited scopes for ONE downstream resource. An access token carries exactly one
   * audience, so a second resource is a second connection, not a longer string here.
   */
  scope: string;
}

export class OboAuthStrategy implements AuthStrategy {
  readonly kind = 'obo' as const;
  readonly resource: string;
  private config: OboStrategyConfig;

  constructor(config: OboStrategyConfig) {
    this.config = config;
    // Derived, not configured twice: the scopes already carry `api://<appId>/`, so stripping the
    // last path segment off the first one IS the resource. One source of truth for both.
    this.resource = (config.scope.split(' ')[0] || '').replace(/\/[^/]*$/, '');
  }

  /**
   * Turn an unqualified scope into a fully qualified one. todo0 answers an insufficient-scope
   * failure with SHORT names (`mcp:connect`), and those come back here as requestedScopes for the
   * step-up retry. Okta accepts them bare; Entra requires `api://<appId>/mcp:connect`. Anything
   * already carrying a scheme is passed through untouched.
   */
  private qualify(scopes: string): string {
    return scopes
      .split(' ')
      .filter((s) => s.length > 0)
      .map((s) => (s.includes('://') ? s : `${this.resource}/${s}`))
      .join(' ');
  }

  /**
   * `subjectToken` is the signed-in user's agent0-audience ACCESS token - NOT an ID token. See
   * auth/entra-obo.ts: OBO's assertion has to be audienced at agent0 itself, which is why the login
   * requests api://<agent0>/agent.access. agent.ts selects the right token for this strategy kind.
   */
  async getAccessToken(subjectToken: string, requestedScopes?: string): Promise<AuthTokenResult> {
    try {
      const token = await entraOnBehalfOf(
        this.config,
        subjectToken,
        this.qualify(requestedScopes || this.config.scope),
      );
      return {
        status: 'success',
        accessToken: token.accessToken,
        expiresIn: token.expiresIn,
        scope: token.scope,
      };
    } catch (err: any) {
      // Never 'interaction_required': preAuthorizedApplications removes consent entirely on this
      // tenant, so there is no URI to send the user to and a fabricated one would be a dead link.
      // The AADSTS text in the message is what names the real cause.
      return {
        status: 'error',
        error: 'entra_obo_failed',
        errorDescription: err?.message || String(err),
      };
    }
  }

  /** Nothing is cached, matching the id-jag adapter: every connect mints a fresh token. */
  clearCache(): void { /* no-op */ }
}

// ============================================================================
// MCP connection config (auth strategy + server URL)
// ============================================================================

export type McpAuthStrategyConfig =
  | { kind: 'id-jag'; config: TokenExchangeConfig }
  | { kind: 'oauth-sts'; config: OAuthStsConfig }
  | { kind: 'obo'; config: OboStrategyConfig };

export interface McpConnectionConfig {
  /** Stable id used in logs, tool-dispatch map, and ConnectionStatus details. */
  id: string;
  /** MCP transport URL (passed to StreamableHTTPClientTransport). */
  serverUrl: string;
  /** Human-readable label for UI / ConnectionStatus.details. */
  displayName?: string;
  /** Okta Resource Indicator, if one is advertised (used by oauth-sts flow). */
  resourceIndicator?: string;
  /** Okta's MCP server id (from the Admin Console managed connection), if known. */
  oktaMcpServerId?: string;
  /** Auth strategy bundle (constructor materialises this into an AuthStrategy). */
  auth: McpAuthStrategyConfig;
}

/** Factory — turns a config bundle into a live AuthStrategy instance. */
export function buildAuthStrategy(cfg: McpAuthStrategyConfig): AuthStrategy {
  // FIRST in the function, which is not a style choice. The existing body ends with a bare
  // `return new OAuthStsAuthStrategy(cfg.config);` that relies on narrowing having eliminated every
  // other arm. Adding 'obo' last would not merely be unreachable - that bare return would then
  // receive an OboStrategyConfig and fail to compile. Narrowing it away first is the only placement
  // that type-checks without editing the lines below.
  if (cfg.kind === 'obo') return new OboAuthStrategy(cfg.config);
  if (cfg.kind === 'id-jag') return new IdJagAuthStrategy(cfg.config);
  return new OAuthStsAuthStrategy(cfg.config);
}

// ============================================================================
// Env-driven loader (consumed by agent.ts at construction time)
// ============================================================================

import { isConnectionDisabled } from './config.js';

/**
 * Read env and assemble the list of MCPs this agent should connect to.
 *
 * Two potential entries today:
 *   1. Primary MCP (Todo0-style, ID-JAG auth) — enabled when MCP_SERVER_URL +
 *      MCP_AUTHORIZATION_SERVER_* + AI_AGENT_* are all set and the
 *      `authorization_server` kind isn't disabled.
 *   2. GitHub MCP (OAuth STS auth) — enabled when GITHUB_MCP_SERVER_URL +
 *      OAUTH_STS_RESOURCE_GITHUB_MCP + AI_AGENT_* are all set and the
 *      `mcp_server` kind isn't disabled.
 *
 * The loader returns whichever subset is actually configured; Agent.connect()
 * tolerates an empty list (logs a warning) and any mix of the two.
 */
export function loadMcpConnectionConfigs(): McpConnectionConfig[] {
  const out: McpConnectionConfig[] = [];

  // --- Shared agent identity (required by both strategies) ------------------
  const oktaDomain = process.env.OKTA_DOMAIN;
  const agentId = process.env.AI_AGENT_ID;
  const privateKeyFile = process.env.AI_AGENT_PRIVATE_KEY_FILE;
  const privateKeyKid = process.env.AI_AGENT_PRIVATE_KEY_KID;
  const hasAgentIdentity = !!(oktaDomain && agentId && privateKeyFile && privateKeyKid);

  // --- Entry 1: Primary MCP via ID-JAG --------------------------------------
  // Skipped entirely on Entra. It would already self-exclude for want of AI_AGENT_PRIVATE_KEY_FILE,
  // but that makes the exclusion an accident of which variables the env file omits; this makes it
  // true by construction, and visible here rather than inferable from somewhere else.
  if ((process.env.IDP ?? 'okta') !== 'entra' && !isConnectionDisabled('authorization_server')) {
    const mcpServerUrl = process.env.MCP_SERVER_URL;
    const authServer = process.env.MCP_AUTHORIZATION_SERVER;
    const tokenEndpoint = process.env.MCP_AUTHORIZATION_SERVER_TOKEN_ENDPOINT;
    const scopes = process.env.AI_AGENT_TODO_MCP_SERVER_SCOPES_TO_REQUEST;

    if (mcpServerUrl && authServer && tokenEndpoint && scopes && hasAgentIdentity) {
      out.push({
        id: 'primary',
        serverUrl: mcpServerUrl,
        displayName: 'Todo0 MCP Server',
        resourceIndicator: process.env.MCP_RESOURCE_INDICATOR || mcpServerUrl,
        oktaMcpServerId: process.env.OKTA_MCP_SERVER_ID,
        auth: {
          kind: 'id-jag',
          config: {
            authorizationServer: authServer,
            authorizationServerTokenEndpoint: tokenEndpoint,
            oktaDomain: oktaDomain!,
            clientId: agentId!,
            privateKeyFile: privateKeyFile!,
            privateKeyKid: privateKeyKid!,
            agentScopes: scopes,
          },
        },
      });
    }
  }

  // --- Entry 2: GitHub MCP via OAuth STS ------------------------------------
  if (!isConnectionDisabled('mcp_server')) {
    const githubMcpUrl = process.env.GITHUB_MCP_SERVER_URL;
    const githubMcpResource = process.env.OAUTH_STS_RESOURCE_GITHUB_MCP;

    if (githubMcpUrl && githubMcpResource && hasAgentIdentity) {
      out.push({
        id: 'github',
        serverUrl: githubMcpUrl,
        displayName: 'Github MCP Server',
        resourceIndicator: githubMcpResource,
        oktaMcpServerId: process.env.OKTA_GITHUB_MCP_SERVER_ID,
        auth: {
          kind: 'oauth-sts',
          config: {
            oktaDomain: oktaDomain!,
            clientId: agentId!,
            privateKeyFile: privateKeyFile!,
            privateKeyKid: privateKeyKid!,
            resource: githubMcpResource,
          },
        },
      });
    }
  }

  // --- Entry 3: Primary MCP via Entra On-Behalf-Of ---------------------------
  // The Entra replacement for Entry 1, and deliberately NOT gated on hasAgentIdentity: OBO
  // authenticates agent0 with its client secret, so there is no client assertion, no signing key,
  // and AI_AGENT_PRIVATE_KEY_FILE is meaningless on this path.
  //
  // Keeps id: 'primary' so agent.ts's tool-dispatch map and ConnectionStatus details do not change -
  // the IDP switch stays invisible to every consumer of this list.
  if ((process.env.IDP ?? 'okta') === 'entra' && !isConnectionDisabled('authorization_server')) {
    const entraMcpUrl = process.env.MCP_SERVER_URL;
    const entraMcpScopes = process.env.ENTRA_TODO0_SCOPES;
    const entraOboConfig = loadEntraOboConfig();

    if (entraMcpUrl && entraMcpScopes && entraOboConfig) {
      out.push({
        id: 'primary',
        serverUrl: entraMcpUrl,
        displayName: 'Todo0 MCP Server',
        resourceIndicator: process.env.MCP_RESOURCE_INDICATOR || entraMcpUrl,
        auth: {
          kind: 'obo',
          config: { ...entraOboConfig, scope: entraMcpScopes },
        },
      });
    } else {
      // Said once, at startup, naming the variable. The alternative is an empty tool list and a
      // chat window that just has no tools, with nothing in the log to explain why.
      console.warn('[entra] IDP=entra but MCP_SERVER_URL / ENTRA_TODO0_SCOPES / the OBO config is '
        + 'incomplete - the tool plane will not connect');
    }
  }

  return out;
}
