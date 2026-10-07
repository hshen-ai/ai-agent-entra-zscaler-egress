import { Request, Response, NextFunction } from 'express';
import OktaJwtVerifier from '@okta/jwt-verifier';

export interface McpAuthConfig {
  mcpOktaIssuer: string;
  mcpExpectedAudience: string;
}

// ============================================================================
// Scope Challenge Helper (MCP Authorization Best Practices)
// ============================================================================

/**
 * Build WWW-Authenticate header for scope challenge per MCP spec
 * @param requiredScopes - Scopes required for the operation
 * @param resourceMetadataUrl - URL to the OAuth protected resource metadata
 * @param errorDescription - Human-readable error description
 */
export function buildScopeChallengeHeader(
  requiredScopes: string[],
  resourceMetadataUrl?: string,
  errorDescription?: string
): string {
  let header = `Bearer error="insufficient_scope", scope="${requiredScopes.join(' ')}"`;

  if (resourceMetadataUrl) {
    header += `, resource_metadata="${resourceMetadataUrl}"`;
  }

  if (errorDescription) {
    header += `, error_description="${errorDescription}"`;
  }

  return header;
}

/**
 * Send 403 response with WWW-Authenticate header for scope challenge
 */
export function sendScopeChallengeResponse(
  res: Response,
  requiredScopes: string[],
  resourceMetadataUrl?: string,
  errorDescription?: string
): Response {
  const wwwAuthHeader = buildScopeChallengeHeader(
    requiredScopes,
    resourceMetadataUrl,
    errorDescription
  );

  console.log(`🔐 Sending scope challenge: ${wwwAuthHeader}`);

  return res
    .status(403)
    .set('WWW-Authenticate', wwwAuthHeader)
    .json({
      error: 'insufficient_scope',
      error_description: errorDescription || 'Additional scopes required',
      required_scopes: requiredScopes,
    });
}

export function createRequireMcpAuth(config: McpAuthConfig) {
  const { mcpOktaIssuer, mcpExpectedAudience } = config;

  console.log('🔐 MCP Auth Middleware Configuration:');
  console.log(`   Issuer: ${mcpOktaIssuer}`);
  console.log(`   Expected Audience: ${mcpExpectedAudience}`);

  const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: mcpOktaIssuer,
    assertClaims: {
      aud: mcpExpectedAudience,
    },
  });

  // Which verifier runs. Entra's tokens are ordinary RS256 JWTs, but @okta/jwt-verifier is built
  // around Okta's /oauth2/v1/keys layout and an Okta issuer, so the Entra path uses `jose` against
  // Entra's own JWKS. Defaults to okta, so an unset IDP is the existing behaviour exactly.
  const mcpIdp = process.env.IDP ?? 'okta';

  // createRemoteJWKSet keeps its own key cache, so it is created ONCE and reused: a per-request
  // instance would refetch Entra's keys on every MCP call. Entra rotates its signing `kid`, which is
  // also why the keys are fetched rather than pinned - a pinned key stops working without warning.
  let entraJwks: any = null;

  /**
   * Entra's JWKS sits next to its issuer, so it is derived rather than configured a second time:
   *   https://login.microsoftonline.com/<tenant>/v2.0
   *   -> https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
   * Both forms verified against this tenant's own discovery document. One source of truth means the
   * issuer pin below and the key source can never drift apart.
   */
  function entraJwksUrl(): string {
    return mcpOktaIssuer.replace(/\/v2\.0$/, '') + '/discovery/v2.0/keys';
  }

  /**
   * The single verification point for both IDPs, returning the same `{ claims }` shape either way so
   * that both call sites keep reading `jwt.claims` and nothing else in this file has to change.
   *
   * Placed below the OktaJwtVerifier construction rather than above it: this closes over that const,
   * and leaving the construction exactly where upstream put it is what keeps the Okta path's startup
   * byte-identical.
   */
  async function verifyMcpToken(accessToken: string): Promise<{ claims: any }> {
    if (mcpIdp !== 'entra') {
      const jwt = await oktaJwtVerifier.verifyAccessToken(accessToken, mcpExpectedAudience);
      return { claims: jwt.claims };
    }

    // Required lazily, and only here. `jose` is declared in the workspace ROOT package.json, not in
    // todo0's, so it reaches this package through pnpm hoisting - a phantom dependency. A top-level
    // import would take the OKTA demo down with it the day that hoisting changes; this way only the
    // path that needs it can fail, and it fails saying exactly what to add and where.
    let jose: any;
    try {
      jose = require('jose');
    } catch (err: any) {
      throw new Error('IDP=entra needs the `jose` package, which resolves in todo0 only via pnpm '
        + 'hoisting from the workspace root. Add it to packages/todo0/package.json. Cause: '
        + err.message);
    }

    if (!entraJwks) {
      entraJwks = jose.createRemoteJWKSet(new URL(entraJwksUrl()));
    }

    // Both pins are measured, not guessed. `audience` is Entra's BARE application id - a GUID, not
    // the api://<appId> scope prefix. `issuer` is the v2.0 form; a v1 token carries
    // https://sts.windows.net/<tenant>/ and is meant to be rejected here.
    const { payload } = await jose.jwtVerify(accessToken, entraJwks, {
      issuer: mcpOktaIssuer,
      audience: mcpExpectedAudience,
    });
    return { claims: payload };
  }

  /**
   * Middleware to verify JWT tokens for MCP server connections.
   * Extracts Bearer token from Authorization header and validates it.
   */
  async function requireMcpAuth(req: Request, res: Response, next: NextFunction) {
  // Check for Bearer token authentication
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer (.+)$/);

  if (!match) {
    console.log('✗ No Bearer token found in Authorization header for MCP connection');
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header. MCP connections require a valid Bearer token.'
    });
  }

  const accessToken = match[1];
  console.log('🔍 Verifying MCP access token...');

  try {
    // Verify the access token
    const jwt = await verifyMcpToken(accessToken);

    console.log('✅ MCP token verified successfully');
    console.log('   Subject:', jwt.claims.preferred_username ?? jwt.claims.sub);
    console.log('   User ID:', jwt.claims.uid ?? jwt.claims.oid);
    console.log('   Scopes:', jwt.claims.scp);
    console.log('   Client ID:', jwt.claims.cid ?? jwt.claims.azp);

    if (!verifyScopesClaim(jwt.claims, ['mcp:connect'])) {
      console.log('✗ Missing required scope: mcp:connect');
      return sendScopeChallengeResponse(
        res,
        ['mcp:connect'],
        undefined,
        'mcp:connect scope required for MCP connection'
      );
    }

    // Attach verified claims to request
    (req as any).mcpUser = jwt.claims as McpAuthClaims;
    return next();
  } catch (err: any) {
    console.error('❌ MCP token verification failed:', err.message);
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired token',
      details: err.message
    });
  }
  }

  /**
   * Verify access token and check for required scopes
   * Returns object with success status, user ID (sub claim), and missing scopes if any
   */
  async function verifyAccessTokenWithScopes(
    authorizationHeader: string,
    expectedScopes: string[]
  ): Promise<{ valid: boolean; userId?: string; missingScopes?: string[] }> {
    console.log('🔍 Verifying MCP access token with scopes:', expectedScopes);

    const match = authorizationHeader.match(/^Bearer (.+)$/);

    if (!match) {
      console.log('✗ No Bearer token found in Authorization header for MCP connection');
      return { valid: false };
    }

    const accessToken = match[1];
    console.log('🔍 Verifying MCP access token...');

    try {
      const jwt = await verifyMcpToken(accessToken);

      const missingScopes = findMissingScopes(jwt.claims, expectedScopes);
      if (missingScopes.length > 0) {
        return { valid: false, missingScopes };
      }

      // Return the user's uid claim (Okta user ID) for user-scoped operations
      // Note: Using uid instead of sub because sub contains email in MCP tokens
      // Entra's equivalent of `uid` is `oid`, and its `sub` is worse than Okta's: it is
      // PAIRWISE, so one login produced two different subs for todo0 and zia-egress.
      // `oid` is identical across both.
      return { valid: true, userId: (jwt.claims.uid ?? jwt.claims.oid) as string };
    } catch (error) {
      console.log('✗ Token verification failed');
      console.error('Token verification error details:', error);
      return { valid: false };
    }
  }

  return { requireMcpAuth, verifyAccessTokenWithScopes };
}

/**
 * Normalise the `scp` claim to a list. Okta issues an ARRAY; Entra issues a space-delimited STRING
 * (measured: "mcp:connect mcp:tools:manage mcp:tools:read"). Both support `.includes()`, and that
 * is precisely the hazard: on a string it silently stops being a membership test and becomes a
 * SUBSTRING test, so a token carrying only `mcp:tools:readonly` would satisfy a check for
 * `mcp:tools:read`. None of today's three scope names is a prefix of another, so the substring test
 * happens to give the right answer right now - this makes it right by construction rather than by
 * coincidence, which is what stops the next scope name from opening a hole quietly.
 *
 * Keyed on the VALUE's shape rather than on IDP: it needs no env var, cannot be misconfigured, and
 * the two callers are module-level functions with no access to the middleware closure anyway.
 */
function mcpScopeList(claims: OktaJwtVerifier.JwtClaims): string[] {
  const scp: any = claims.scp;
  if (Array.isArray(scp)) return scp;
  return typeof scp === 'string' ? scp.split(' ').filter((s) => s.length > 0) : [];
}

/**
 * Find missing scopes from claims
 */
function findMissingScopes(claims: OktaJwtVerifier.JwtClaims, expectedScopes: string[]): string[] {
  const missing: string[] = [];
  if (claims.scp) {
    for (const expectedScope of expectedScopes) {
      if (!mcpScopeList(claims).includes(expectedScope)) {
        missing.push(expectedScope);
      }
    }
  } else {
    return expectedScopes; // All scopes are missing
  }
  return missing;
}

function verifyScopesClaim(claims: OktaJwtVerifier.JwtClaims, expectedScopes: string[]): boolean {
  if (claims.scp) {
    for (const expectedScope of expectedScopes) {
      if (!mcpScopeList(claims).includes(expectedScope)) {
        console.log(`✗ Missing required scope: ${expectedScope}`);
        return false;
      }
    }
    return true;
  } else {
    return false;
  }
}

export interface McpAuthClaims {
  sub: string;
  scp?: string[];
  cid?: string;
  [key: string]: any;
}

declare global {
  namespace Express {
    interface Request {
      mcpUser?: McpAuthClaims;
    }
  }
}
