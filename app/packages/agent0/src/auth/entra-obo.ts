// entra-obo.ts — Microsoft Entra ID On-Behalf-Of. The Entra half of the IDP switch.
//
// Okta's Cross App Access chain is ID token -> ID-JAG (token-exchange) -> resource access token
// (jwt-bearer). Entra rejects RFC 8693 token-exchange outright: measured 2026-09-19 on tenant
// cddbxxxx-xxxx-xxxx-xxxx-xxxxxxxxf7c6, `grant_type=...:token-exchange` comes back
// `AADSTS70003 ... unsupported_grant_type`. On-Behalf-Of is the supported equivalent and is
// simpler — one call per downstream audience, no intermediate token, no signing key:
//
//   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//   assertion=<the user's access token whose aud is agent0 ITSELF>
//   requested_token_use=on_behalf_of
//   scope=<one resource's scopes>
//
// The assertion must be an ACCESS token, not an ID token. That is the one structural difference
// from XAA and the reason the Entra login requests `api://<agent0>/agent.access`.
//
// Measured: one inbound token fans out to BOTH todo0 and zia-egress with no second sign-in, each
// downstream token carries its own single `aud`, and all of them keep the user's
// `preferred_username` and `oid` while `azp` records agent0 as the actor.
import axios from 'axios';

export interface EntraOboConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface EntraOboToken {
  accessToken: string;
  expiresIn: number;
  scope?: string;
}

/**
 * Read the OBO configuration from env. Returns null unless IDP=entra AND all three values are
 * present, so an Okta deploy — which sets none of them — cannot accidentally engage any of this.
 *
 * All-or-none rather than partial, matching validateAppServerEnv()'s treatment of the OKTA_* four:
 * a half-configured OBO would otherwise fail at the first chat message with an opaque AADSTS code
 * instead of saying so once, at startup.
 */
export function loadEntraOboConfig(): EntraOboConfig | null {
  if ((process.env.IDP ?? 'okta') !== 'entra') return null;
  const tenantId = process.env.ENTRA_TENANT_ID;
  // agent0 is ONE confidential client on either IDP, so it reuses the OKTA_CLIENT_* slots rather
  // than duplicating app.ts's all-or-none validation for a second set of names. The env FILE is
  // the switch, not a second code path.
  const clientId = process.env.OKTA_CLIENT_ID;
  const clientSecret = process.env.OKTA_CLIENT_SECRET;
  if (!tenantId || !clientId || !clientSecret) {
    console.warn('[entra] IDP=entra but ENTRA_TENANT_ID / OKTA_CLIENT_ID / OKTA_CLIENT_SECRET is '
      + 'incomplete — OBO is disabled and the tool plane will not connect');
    return null;
  }
  return { tenantId, clientId, clientSecret };
}

/** v2.0 endpoint specifically: v1.0 would not honour requestedAccessTokenVersion 2. */
export function entraTokenEndpoint(tenantId: string): string {
  return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
}

/**
 * Exchange the signed-in user's agent0-audience access token for a downstream resource token.
 *
 * `scope` is space-delimited but must name ONE resource: an access token carries exactly one
 * audience, so todo0 and zia-egress are two separate calls. This is the same constraint that made
 * zia-egress a separate app registration in the first place.
 *
 * Throws with the AADSTS text intact. The code is the whole diagnostic value — it distinguishes a
 * wrong assertion audience from a scope the tenant does not expose from a missing
 * pre-authorisation — so callers turn it into a result rather than flattening it.
 */
export async function entraOnBehalfOf(
  config: EntraOboConfig,
  userAccessToken: string,
  scope: string,
): Promise<EntraOboToken> {
  if (!userAccessToken) {
    // Fail closed, and name which half is missing. An empty assertion comes back as a generic
    // invalid_grant, which reads like a tenant problem rather than an empty session.
    throw new Error('no user access token on the session — cannot perform OBO');
  }

  const form = new URLSearchParams();
  form.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  form.append('client_id', config.clientId);
  form.append('client_secret', config.clientSecret);
  form.append('assertion', userAccessToken);
  form.append('scope', scope);
  form.append('requested_token_use', 'on_behalf_of');

  try {
    const response = await axios.post(entraTokenEndpoint(config.tenantId), form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    return {
      accessToken: response.data.access_token,
      expiresIn: response.data.expires_in ?? 3600,
      scope: response.data.scope,
    };
  } catch (err: any) {
    const data = err?.response?.data;
    throw new Error(
      `Entra OBO failed: ${data?.error ?? err?.message ?? 'unknown'} `
      + `${data?.error_description ?? ''}`.trim(),
    );
  }
}

/**
 * Decode a JWT payload without verifying it. For LOGGING ONLY — agent0 received these tokens
 * directly from the tenant over TLS, so there is nothing for a signature check to add here, and
 * todo0 (the party that did not) verifies properly against JWKS.
 *
 * Exists so the ZIA and MCP legs can log `preferred_username` / `aud` / `exp` and prove which
 * identity went on the wire, without ever logging the token itself.
 */
export function entraClaims(token: string): Record<string, any> | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
