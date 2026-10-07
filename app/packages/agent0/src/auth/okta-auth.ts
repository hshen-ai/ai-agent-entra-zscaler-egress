// okta-auth.ts - Okta Authentication and Session Management
import { Request, Response, NextFunction } from 'express';
import { Issuer, generators, Client } from 'openid-client';
import session from 'express-session';

// Extend Express session type
declare module 'express-session' {
  interface SessionData {
    idToken?: string;
    accessToken?: string;
    userInfo?: any;
    pkce?: {
      code_verifier: string;
      state: string;
    };
  }
}

// ============================================================================
// Okta Configuration
// ============================================================================

export interface OktaConfig {
  domain: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

// ============================================================================
// Session Configuration
// ============================================================================

export function createSessionMiddleware(sessionSecret: string) {
  if (!sessionSecret || sessionSecret.trim() === '') {
    throw new Error('SESSION_SECRET is required and cannot be empty');
  }
  return session({
    name: 'agent0.sid', // Unique session name for agent0 app
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset maxAge on every response
    cookie: {
      secure: false, // Set to true in production with HTTPS
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'lax', // Prevent CSRF while allowing normal navigation
    },
  });
}

// ============================================================================
// Okta Auth Helper Class
// ============================================================================

export class OktaAuthHelper {
  private client: Client | null = null;
  private config: OktaConfig;
  private issuerUrl: string;

  constructor(config: OktaConfig) {
    this.config = config;
    this.issuerUrl = `https://${config.domain}`;
    this.initializeClient();
    console.log('🔐 Okta authentication configured');
  }

  private async initializeClient(): Promise<void> {
    try {
      const issuer = await Issuer.discover(this.issuerUrl);
      
      this.client = new issuer.Client({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uris: [this.config.redirectUri],
        response_types: ['code'],
      });
      
      console.log('✅ OpenID Client initialized successfully');
    } catch (error: any) {
      console.error('❌ Failed to initialize OpenID Client:', error.message);
    }
  }

  private async getClient(): Promise<Client> {
    if (!this.client) {
      await this.initializeClient();
      if (!this.client) {
        throw new Error('OpenID client not initialized');
      }
    }
    return this.client;
  }

  // ============================================================================
  // Token Helpers
  // ============================================================================

  getIdToken(req: Request): string | null {
    const session = req.session as any;
    return session.idToken || null;
  }

  getAccessToken(req: Request): string | null {
    const session = req.session as any;
    return session.accessToken || null;
  }

  getUserInfo(req: Request): any | null {
    const session = req.session as any;
    return session.userInfo || null;
  }

  // ============================================================================
  // Authentication Middleware
  // ============================================================================

  requireAuth() {
    return (req: Request, res: Response, next: NextFunction) => {
      const session = req.session as any;

      if (session.idToken) {
        next();
      } else {
        res.status(401).json({ error: 'Unauthorized', message: 'Please login first' });
      }
    };
  }

  // ============================================================================
  // Login Handler
  // ============================================================================

  async handleLogin(req: Request, res: Response): Promise<void> {
    try {
      const client = await this.getClient();

      // Generate PKCE parameters using openid-client generators
      const code_verifier = generators.codeVerifier();
      const code_challenge = generators.codeChallenge(code_verifier);
      const state = generators.state();

      // Store PKCE parameters in session
      req.session.pkce = { code_verifier, state };

      // Build authorization URL with PKCE using openid-client
      const authorizationUrl = client.authorizationUrl({
        // The login scope set is env-driven so ONE code path serves both IDPs, with Okta's current value
        // as the default - an Okta deploy that sets nothing behaves exactly as before.
        //
        // Entra must additionally request `api://<agent0-appId>/agent.access`: On-Behalf-Of's assertion has
        // to be an ACCESS token whose aud is agent0 itself, and without that scope the session's access
        // token is audienced at Microsoft Graph and every OBO call fails. `offline_access` comes with it, so
        // the egress token can be re-minted instead of silently 407ing after 60 minutes.
        scope: process.env.IDP_LOGIN_SCOPES ?? 'openid profile email',
        code_challenge,
        code_challenge_method: 'S256',
        state,
        redirect_uri: this.config.redirectUri,
      });

      console.log('🔐 Redirecting to:', authorizationUrl);
      res.redirect(authorizationUrl);
    } catch (error: any) {
      console.error('Login redirect error:', error);
      res.status(500).json({ error: 'Failed to initiate login' });
    }
  }

  // ============================================================================
  // Callback Handler
  // ============================================================================

  async handleCallback(req: Request, res: Response): Promise<void> {
    const { code, error, error_description } = req.query;
    // --- ZIA egress token mint ------------------------------------------------------------
    // The second half of the prompt=none hop started after the login below. Keyed on our own
    // state prefix, so the normal login path cannot reach it.
    //
    // Why not a token-exchange? Measured 2026-09-16 on real logins: the org-AS access token is
    // rejected by this AS (`400 invalid_request 'subject_token' is invalid.`), and the XAA
    // id-jag chain that works for todo0 is refused at leg 1 (`400 invalid_target`) because the
    // zia-egress AS is not a registered ID-JAG target. authorization_code needs no new Okta
    // object at all.
    if (typeof req.query.state === "string" && req.query.state.startsWith("zia.")) {
      const ziaSession = req.session as any;
      const ziaPkce = ziaSession.ziaPkce;
      ziaSession.ziaPkce = undefined;
      // Exactly one redirect, whatever happens: several of the paths below can race.
      let ziaSent = false;
      const ziaHome = (ziaMsg: any) => {
        if (ziaMsg) console.error("[ZIA] " + ziaMsg);
        if (ziaSent) return;
        ziaSent = true;
        res.redirect("/");
      };
      // req.query values are not strings as far as TypeScript is concerned, so String() rather
      // than `+` - the union includes objects and arrays and `+` is a TS2365.
      if (error) {
        ziaHome("authorize failed: " + String(error) + " " + String(error_description ?? ""));
        return;
      }
      if (!ziaPkce || ziaPkce.state !== req.query.state) {
        ziaHome("authorize state mismatch - dropping the response");
        return;
      }
      if (typeof code !== "string") {
        ziaHome("authorize returned no code");
        return;
      }
      try {
        const ziaIssuer = process.env.ZIA_EGRESS_ISSUER
          ?? `https://${process.env.OKTA_DOMAIN ?? ""}/oauth2/aus1xxxxxxxxxxxxE698`;
        // append(), never an object literal: under "strict": true a literal holding a union with
        // undefined is rejected with TS2345, which is how an earlier attempt failed to build.
        const ziaBody = new URLSearchParams();
        ziaBody.append("grant_type", "authorization_code");
        ziaBody.append("code", code);
        // Must be byte-identical to the authorize request's redirect_uri, so both read it from
        // the same config the login itself uses.
        ziaBody.append("redirect_uri", this.config.redirectUri);
        ziaBody.append("code_verifier", ziaPkce.code_verifier);
        ziaBody.append("client_id", process.env.OKTA_CLIENT_ID ?? "");
        ziaBody.append("client_secret", process.env.OKTA_CLIENT_SECRET ?? "");
        const ziaEncoded = ziaBody.toString();
        const ziaReq = require("https").request(ziaIssuer + "/v1/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(ziaEncoded),
            Accept: "application/json",
          },
        }, (ziaRes: any) => {
          let ziaRaw = "";
          ziaRes.on("data", (ziaChunk: any) => { ziaRaw += ziaChunk; });
          ziaRes.on("end", () => {
            let ziaJson: any = {};
            try { ziaJson = JSON.parse(ziaRaw); } catch { /* non-JSON body: handled below */ }
            if (ziaRes.statusCode !== 200 || !ziaJson.access_token) {
              // Okta's error fields only, never the body: on a partial success it can carry a
              // token.
              ziaHome("egress token exchange failed: HTTP " + ziaRes.statusCode
                + " " + (ziaJson.error ?? "") + " " + (ziaJson.error_description ?? ""));
              return;
            }
            // SESSION level, not a file. The token used to go to ZIA_TOKEN_FILE and agent.ts re-read
            // that file on every CONNECT - so one file meant one identity, and a second concurrent
            // login overwrote the first user's token, making both sessions egress as whoever logged in
            // last. createSessionMiddleware passes no `store:`, so this stays in the default
            // MemoryStore: server-side, and never in the cookie.
            ziaSession.ziaToken = ziaJson.access_token;
            // Claims only - never the token itself.
            const ziaClaims = JSON.parse(
              Buffer.from(ziaJson.access_token.split(".")[1], "base64url").toString());
            // save() before redirecting: otherwise the redirect can outrun the store write and the
            // very next request reads a session with no token, which now means a 407 rather than a
            // stale identity.
            req.session.save((ziaSaveErr: any) => {
              if (ziaSaveErr) {
                ziaHome("egress token could not be saved to the session: " + ziaSaveErr.message);
                return;
              }
              console.log("[ZIA] session egress token: sub=" + ziaClaims.sub + " aud=" + ziaClaims.aud
                + " scp=" + ziaClaims.scp + " exp=" + new Date(ziaClaims.exp * 1000).toISOString());
              ziaHome("");
            });
          });
        });
        ziaReq.on("error", (ziaErr: any) => {
          ziaHome("egress token transport error: " + ziaErr.message);
        });
        // A hung Okta must not hang the browser on a blank page.
        ziaReq.setTimeout(8000, () => { ziaReq.destroy(new Error("timed out after 8s")); });
        ziaReq.end(ziaEncoded);
      } catch (ziaOuterErr: any) {
        ziaHome("egress token mint skipped: " + ziaOuterErr.message);
      }
      return;
    }
    // --- end ZIA egress token mint --------------------------------------------------------

    if (error) {
      console.error('Okta authentication error:', error, error_description);
      res.redirect('/?error=' + encodeURIComponent(error as string));
      return;
    }

    if (!code) {
      res.redirect('/?error=no_code');
      return;
    }

    try {
      const client = await this.getClient();

      // Get PKCE parameters from session
      const { pkce } = req.session as any;

      if (!pkce || !pkce.code_verifier || !pkce.state) {
        console.error('Missing PKCE parameters in session');
        res.redirect('/?error=missing_verifier');
        return;
      }

      // Build callback parameters from the request
      const params = client.callbackParams(req);

      // Exchange authorization code for tokens using openid-client
      const tokenSet = await client.callback(
        this.config.redirectUri,
        params,
        {
          code_verifier: pkce.code_verifier,
          state: pkce.state,
        }
      );

      if (tokenSet.access_token && tokenSet.id_token) {
        const claims = tokenSet.claims();

        // Regenerate session to prevent session fixation attacks
        req.session.regenerate((err) => {
          if (err) {
            console.error('Session regeneration failed:', err);
            res.redirect('/?error=session_error');
            return;
          }

          // Store tokens in the NEW session
          (req.session as any).idToken = tokenSet.id_token;
          (req.session as any).accessToken = tokenSet.access_token;
          (req.session as any).userInfo = claims;

          console.log('✅ User authenticated:', claims.email || claims.sub);
          // --- ZIA egress authorize kick-off ----------------------------------------------------
          // --- Entra egress token via OBO -------------------------------------------------------------
          // The Entra equivalent of the prompt=none hop below, and much less machinery: Entra mints the
          // zia-egress-audience token from the access token we are already holding, server-side, in one
          // call. No second browser round trip, no PKCE, no `zia.` state prefix, nothing to race.
          //
          // Returns early, so the Okta block below is reached only when IDP is not entra and stays
          // byte-identical. Same session property, same save-before-redirect ordering, same one-redirect
          // guarantee, same fail-closed outcome: on ANY error the user lands on `/` with no token, the next
          // CONNECT carries no Proxy-Authorization, and ZIA answers 407. There is no fallback identity.
          if ((process.env.IDP ?? "okta") === "entra") {
            const entraObo = require("./entra-obo.js");
            const entraCfg = entraObo.loadEntraOboConfig();
            const entraScope = process.env.ENTRA_ZIA_EGRESS_SCOPE ?? "";
            let entraSent = false;
            const entraHome = (entraMsg: any) => {
              if (entraMsg) console.error("[ZIA] " + entraMsg);
              if (entraSent) return;
              entraSent = true;
              res.redirect("/");
            };
            if (!entraCfg || !entraScope) {
              entraHome("IDP=entra but the OBO config or ENTRA_ZIA_EGRESS_SCOPE is missing"
                + " - no egress token for this session");
              return;
            }
            // tokenSet.access_token, not id_token: OBO requires an access token audienced at agent0, which
            // is what IDP_LOGIN_SCOPES asks for above.
            entraObo.entraOnBehalfOf(entraCfg, tokenSet.access_token, entraScope)
              .then((entraTok: any) => {
                (req.session as any).ziaToken = entraTok.accessToken;
                // Saved before the redirect, or the browser can come back on a request that races the
                // MemoryStore write and sees no token.
                req.session.save((entraSaveErr: any) => {
                  if (entraSaveErr) {
                    entraHome("egress token could not be saved to the session: " + entraSaveErr.message);
                    return;
                  }
                  // Claims only. This is the line that proves WHICH identity will go on the wire.
                  const entraIdent = entraObo.entraClaims(entraTok.accessToken) ?? {};
                  console.log("[ZIA] session egress token: sub=" + entraIdent.preferred_username
                    + " aud=" + entraIdent.aud + " scp=" + entraIdent.scp + " exp=" + entraIdent.exp);
                  entraHome("");
                });
              })
              .catch((entraErr: any) => entraHome(entraErr.message));
            return;
          }
          // --- end Entra egress token via OBO ---------------------------------------------------------
          // Send the browser through the zia-egress AS to collect a second token for the same user.
          // The Okta session cookie was just established by the login above, so prompt=none makes
          // this hop invisible. redirect_uri is the app's ONE registered URI, reused deliberately so
          // no Okta app object has to be modified; the branch at the top of handleCallback picks the
          // response apart by our own state prefix.
          //
          // If anything here throws, execution falls through to the original res.redirect('/') below
          // and the user still lands on the app - without a token, which is the fail-closed outcome.
          try {
            const ziaCrypto = require("crypto");
            const ziaVerifier = ziaCrypto.randomBytes(32).toString("base64url");
            const ziaState = "zia." + ziaCrypto.randomBytes(16).toString("hex");
            (req.session as any).ziaPkce = { state: ziaState, code_verifier: ziaVerifier };
            const ziaIssuer = process.env.ZIA_EGRESS_ISSUER
              ?? `https://${process.env.OKTA_DOMAIN ?? ""}/oauth2/aus1xxxxxxxxxxxxE698`;
            const ziaQuery = new URLSearchParams();
            ziaQuery.append("client_id", process.env.OKTA_CLIENT_ID ?? "");
            ziaQuery.append("response_type", "code");
            ziaQuery.append("redirect_uri", this.config.redirectUri);
            ziaQuery.append("scope", process.env.ZIA_EGRESS_SCOPE ?? "zia:egress");
            ziaQuery.append("state", ziaState);
            ziaQuery.append("prompt", "none");
            ziaQuery.append("code_challenge_method", "S256");
            ziaQuery.append("code_challenge",
              ziaCrypto.createHash("sha256").update(ziaVerifier).digest("base64url"));
            console.log("[ZIA] requesting the egress token via prompt=none at " + ziaIssuer);
            res.redirect(ziaIssuer + "/v1/authorize?" + ziaQuery.toString());
            return;
          } catch (ziaKickErr: any) {
            console.error("[ZIA] authorize kick-off skipped: " + ziaKickErr.message);
          }
          // --- end ZIA egress authorize kick-off ------------------------------------------------

          // Redirect to main page
          res.redirect('/');
        });
      } else {
        throw new Error('No tokens received from Okta');
      }
    } catch (error: any) {
      console.error('Token exchange error:', error);
      res.redirect('/?error=token_exchange_failed');
    }
  }

  // ============================================================================
  // Logout Handler
  // ============================================================================

  handleLogout(_port: number) {
    return async (req: Request, res: Response) => {
      try {
        const client = await this.getClient();
        const idToken = (req.session as any)?.idToken;

        // Derive post-logout URL from the registered redirect URI's origin so
        // it matches the public-facing origin (e.g., the Vite dev server port),
        // not the backend's internal port.
        const postLogoutRedirectUri = new URL(this.config.redirectUri).origin;

        // Build end session URL using openid-client with client_id parameter
        const logoutUrl = client.endSessionUrl({
          client_id: this.config.clientId,
          id_token_hint: idToken,
          post_logout_redirect_uri: postLogoutRedirectUri,
        });

        req.session.destroy((err) => {
          if (err) {
            console.error('Session destruction error:', err);
          }
          res.redirect(logoutUrl);
        });
      } catch (error: any) {
        console.error('Logout error:', error);
        req.session.destroy((_err) => {
          res.redirect('/');
        });
      }
    };
  }

  // ============================================================================
  // Status Endpoints
  // ============================================================================

  async handleAuthStatus(req: Request, res: Response): Promise<void> {
    const session = req.session as any;

    if (session.idToken && session.userInfo) {
      res.json({
        authenticated: true,
        user: {
          email: session.userInfo.email,
          name: session.userInfo.name,
          sub: session.userInfo.sub,
          given_name: session.userInfo.given_name,
          family_name: session.userInfo.family_name,
        },
        // Don't send the actual token to client, just metadata
        tokenInfo: {
          hasIdToken: !!session.idToken,
          hasAccessToken: !!session.accessToken,
          issuer: session.userInfo.iss,
          issuedAt: session.userInfo.iat,
          expiresAt: session.userInfo.exp,
        },
      });
    } else {
      res.json({ authenticated: false });
    }
  }

  async handleUserInfo(req: Request, res: Response): Promise<void> {
    const session = req.session as any;
    if (session.userInfo) {
      res.json({
        success: true,
        user: session.userInfo,
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User information not found',
      });
    }
  }
}
