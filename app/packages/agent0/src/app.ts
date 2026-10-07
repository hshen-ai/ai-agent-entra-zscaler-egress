// app.ts - Agent0 App Server (Express)
import express, { Request, Response } from 'express';
import * as path from 'path';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { getAgentForSession } from './agent.js';
import { OktaAuthHelper, OktaConfig, createSessionMiddleware } from './auth/okta-auth.js';
import { buildConnectionStatuses } from './connections/registry.js';

// ============================================================================
// App Server Configuration Types
// ============================================================================

/**
 * App server configuration (discriminated union for optional Okta)
 */
type AppServerConfig = {
  port: number;
  sessionSecret: string;
} & (
  | {
      hasOkta: true;
      oktaDomain: string;
      oktaClientId: string;
      oktaClientSecret: string;
      oktaRedirectUri: string;
    }
  | {
      hasOkta: false;
    }
);

/**
 * Internal configuration after processing
 */
interface AppServerInternalConfig {
  port: number;
  sessionSecret: string;
  okta?: OktaConfig;
}

// ============================================================================
// Environment Validation Function
// ============================================================================

/**
 * Validate app server environment variables and return typed configuration
 */
function validateAppServerEnv(): AppServerConfig {
  const missing: string[] = [];
  const invalid: string[] = [];

  // Check required variables
  if (!process.env.PORT || process.env.PORT.trim() === '') {
    missing.push('PORT');
  }
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.trim() === '') {
    missing.push('SESSION_SECRET');
  }

  // Check optional Okta configuration (all or none)
  const oktaDomain = process.env.OKTA_DOMAIN;
  const oktaClientId = process.env.OKTA_CLIENT_ID;
  const oktaClientSecret = process.env.OKTA_CLIENT_SECRET;
  const oktaRedirectUri = process.env.OKTA_REDIRECT_URI;

  const oktaVarsSet = [oktaDomain, oktaClientId, oktaClientSecret, oktaRedirectUri].filter(v => v && v.trim() !== '');
  const hasPartialOkta = oktaVarsSet.length > 0 && oktaVarsSet.length < 4;

  if (hasPartialOkta) {
    if (!oktaDomain || oktaDomain.trim() === '') missing.push('OKTA_DOMAIN');
    if (!oktaClientId || oktaClientId.trim() === '') missing.push('OKTA_CLIENT_ID');
    if (!oktaClientSecret || oktaClientSecret.trim() === '') missing.push('OKTA_CLIENT_SECRET');
    if (!oktaRedirectUri || oktaRedirectUri.trim() === '') missing.push('OKTA_REDIRECT_URI');
  }

  // Report errors and exit if validation fails
  if (missing.length > 0 || invalid.length > 0) {
    console.error('❌ Environment configuration error in .env.app');
    if (missing.length > 0) {
      console.error('   Missing required variables:', missing.join(', '));
    }
    if (invalid.length > 0) {
      console.error('   Invalid variables:', invalid.join(', '));
    }
    console.error('   Check packages/agent0/.env.app file');
    console.error('   Note: Okta variables must be all present or all absent');
    process.exit(1);
  }

  console.log('✅ App server environment variables validated');

  const baseConfig = {
    port: parseInt(process.env.PORT!, 10),
    sessionSecret: process.env.SESSION_SECRET!,
  };

  // Return discriminated union based on Okta configuration
  if (oktaVarsSet.length === 4) {
    return {
      ...baseConfig,
      hasOkta: true,
      oktaDomain: oktaDomain!,
      oktaClientId: oktaClientId!,
      oktaClientSecret: oktaClientSecret!,
      oktaRedirectUri: oktaRedirectUri!,
    };
  } else {
    return {
      ...baseConfig,
      hasOkta: false,
    };
  }
}

// ============================================================================
// App Server Class
// ============================================================================

export class AppServer {
  private app: express.Application;
  private config: AppServerInternalConfig;
  private oktaAuthHelper: OktaAuthHelper | null = null;

  constructor() {
    // Validate environment and get typed config
    const envConfig = validateAppServerEnv();

    this.config = {
      port: envConfig.port,
      sessionSecret: envConfig.sessionSecret,
    };

    this.app = express();

    // Initialize Okta Auth if configured
    if (envConfig.hasOkta) {
      this.config.okta = {
        domain: envConfig.oktaDomain,
        clientId: envConfig.oktaClientId,
        clientSecret: envConfig.oktaClientSecret,
        redirectUri: envConfig.oktaRedirectUri,
      };
      this.oktaAuthHelper = new OktaAuthHelper(this.config.okta);
    }

    this.setupMiddleware();
    this.setupRoutes();
  }

  public getPort(): number {
    return this.config.port;
  }

  // ============================================================================
  // Middleware Setup
  // ============================================================================

  private setupMiddleware(): void {
    // Security headers via helmet (uses secure defaults, we only override CSP)
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
          // api.iconify.design: runtime SVG fetch for the <iconify-icon> web
          //   component used in the Managed Connections panel.
          // cdn.jsdelivr.net: DevTools sourcemap fetches for the CDN scripts
          //   already allowed in scriptSrc (dompurify, marked, iconify).
          connectSrc: ["'self'", 'https://api.iconify.design', 'https://cdn.jsdelivr.net'],
          imgSrc: ["'self'", 'data:', 'https:'],
          // This origin is HTTP on purpose (every Okta redirect URI here is http://), and helmet's
          // DEFAULT set includes upgrade-insecure-requests, which rewrites every fetch from this page
          // to https://<host>:<same port>. Nothing serves TLS on that port, so the browser reports
          // `Failed to fetch` and the UI hangs on "Connecting to server...". Invisible on localhost,
          // which is exempt from the upgrade as a potentially-trustworthy origin - so it only breaks
          // off-host, e.g. through ZPA. Measured 2026-09-16.
          upgradeInsecureRequests: null,
        },
      },
      // Also a helmet default. A browser ignores an STS header received over plain HTTP, so it is
      // inert today - but it would pin these hostnames to HTTPS for a year the moment anything
      // serves them over TLS. Removed here rather than left as a trap for the next person.
      hsts: false,
    }));

    this.app.use(express.json());
    this.app.use(cookieParser());
    this.app.use(createSessionMiddleware(this.config.sessionSecret));

    // CORS middleware
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });

    // Serve static files from public directory
    this.app.use(express.static(path.join(__dirname, '..', 'public')));
  }

  // ============================================================================
  // Routes Setup
  // ============================================================================

  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', this.handleHealth.bind(this));

    // Setup authentication routes
    this.setupAuthRoutes();

    // Setup chat routes
    this.setupChatRoutes();

    // Setup OAuth STS routes
    this.setupOAuthStsRoutes();
  }

  // ============================================================================
  // Authentication Routes
  // ============================================================================

  private setupAuthRoutes(): void {
    if (!this.oktaAuthHelper) {
      console.log('⚠️  Okta authentication not configured - auth endpoints disabled');
      return;
    }

    // Login endpoint - redirects to Okta
    this.app.get('/login', (req, res) => {
      this.oktaAuthHelper!.handleLogin(req, res);
    });

    // Callback endpoint - handles Okta redirect
    this.app.get('/callback', (req, res) => {
      this.oktaAuthHelper!.handleCallback(req, res);
    });

    // Logout endpoint
    this.app.get('/logout', this.oktaAuthHelper.handleLogout(this.config.port));

    // Auth status endpoint
    this.app.get('/auth/status', (req, res) => {
      this.oktaAuthHelper!.handleAuthStatus(req, res);
    });

    // Get current user's ID token claims
    this.app.get('/auth/user', this.oktaAuthHelper.requireAuth(), (req, res) => {
      this.oktaAuthHelper!.handleUserInfo(req, res);
    });
  }

  // ============================================================================
  // Chat Routes
  // ============================================================================

  private setupChatRoutes(): void {
    const authMiddleware = this.oktaAuthHelper
      ? this.oktaAuthHelper.requireAuth()
      : (_req: Request, _res: Response, next: any) => next();

    // Chat endpoint with LLM support
    this.app.post('/api/chat', authMiddleware, async (req, res) => {
      try {
        const { message } = req.body;

        if (!message) {
          return res.status(400).json({
            success: false,
            error: 'Bad Request',
            message: 'message is required',
          });
        }

        const agent = await getAgentForSession(req);

        if (!agent || !agent.isLLMEnabled()) {
          return res.status(503).json({
            success: false,
            error: 'Service Unavailable',
            message: 'LLM is not configured. Please set ANTHROPIC_API_KEY environment variable.',
          });
        }

        // Process message with agent. If connect() produced pending OAuth-STS
        // consents (e.g. GitHub MCP first-use), surface them so the frontend
        // can open consent popups; the LLM still runs with whichever MCP
        // tools did connect successfully.
        const result = await agent.processUserInput(message);
        const pendingConsents = agent.consumePendingConsents();
        if (pendingConsents.length > 0) {
          const data = { ...(result.data || {}), pending_consents: pendingConsents };
          res.json({ ...result, data });
        } else {
          res.json(result);
        }
      } catch (error: any) {
        console.error('Chat API error:', error);
        res.status(500).json({
          success: false,
          error: 'Internal Server Error',
          message: error.message,
        });
      }
    });
  }

  // ============================================================================
  // OAuth STS Brokered Consent Routes
  // ============================================================================

  private setupOAuthStsRoutes(): void {
    const authMiddleware = this.oktaAuthHelper
      ? this.oktaAuthHelper.requireAuth()
      : (_req: Request, _res: Response, next: any) => next();

    // Trigger OAuth STS exchange (called after user completes consent).
    // Optional body field `resource` lets callers target a specific
    // OAuth-STS handler (OIN GitHub, GitHub MCP, ...). Absent `resource`
    // falls back to the legacy OIN handler for backward compatibility.
    this.app.post('/api/oauth-sts/exchange', authMiddleware, async (req, res) => {
      try {
        const agent = await getAgentForSession(req);
        if (!agent) {
          return res.status(503).json({ status: 'error', error: 'Agent not available' });
        }

        const resource: string | undefined = req.body?.resource;
        const stsHandler = resource
          ? agent.getOAuthStsHandlerByResource(resource)
          : agent.getOAuthStsHandler();

        if (!stsHandler) {
          return res.status(404).json({
            status: 'error',
            error: resource
              ? `No OAuth STS handler registered for resource="${resource}"`
              : 'OAuth STS not configured',
          });
        }

        const idToken = agent.getIdToken();
        const result = await stsHandler.exchangeForISVToken(idToken);

        // If this exchange just unblocked an MCP, reconnect it so its tools
        // join the union. We can't rely on getPendingConsents() here — /api/chat
        // already drained it via consumePendingConsents(). Instead match by
        // resource against the live MCP list.
        if (resource && result.status === 'success') {
          const owner = agent
            .listOAuthStsResources()
            .find(r => r.scope === 'mcp' && r.resource === resource);
          if (owner?.mcpId) {
            const outcome = await agent.retryPendingMcp(owner.mcpId);
            console.log(`   retryPendingMcp[${owner.mcpId}] -> ${outcome}`);
          }
        }

        res.json(result);
      } catch (error: any) {
        console.error('OAuth STS exchange error:', error);
        res.status(500).json({ status: 'error', error: error.message });
      }
    });

    // Check OAuth STS connection status. Optional `?resource=` query
    // targets a specific handler; default = legacy OIN handler.
    this.app.get('/api/oauth-sts/status', authMiddleware, async (req, res) => {
      try {
        const agent = await getAgentForSession(req);
        if (!agent) {
          return res.json({ configured: false, connected: false });
        }

        const resource = typeof req.query.resource === 'string' ? req.query.resource : undefined;
        const stsHandler = resource
          ? agent.getOAuthStsHandlerByResource(resource)
          : agent.getOAuthStsHandler();

        if (!stsHandler) {
          return res.json({ configured: false, connected: false });
        }

        const hasToken = stsHandler.getCachedToken() !== null;
        res.json({ configured: true, connected: hasToken, resource });
      } catch (error: any) {
        console.error('OAuth STS status error:', error);
        res.status(500).json({ configured: false, connected: false, error: error.message });
      }
    });

    // Unified connections status: reports the Okta managed-connection
    // slots this sample supports (authorization_server, application,
    // mcp_server) so the UI "Connections" panel can render them uniformly.
    //
    // Returns env-derived state for the anonymous/logged-out case, and
    // enriches "connected" flags with per-user runtime state when the
    // caller has an active session.
    // How the two levels of ZIA egress identity are read back, without guessing from log lines.
    // DECODED CLAIMS ONLY - never a token. `session` is this caller's own token, minted by their
    // login; `process` is the container's own. `session: null` is the fail-closed state and means
    // the next Bedrock call from this session gets a 407, which is intended, not a bug.
    this.app.get('/api/zia/status', (req, res) => {
      const ziaShow = (jwt: any) => {
        try {
          const c = JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url").toString());
          return { sub: c.sub, exp: new Date(c.exp * 1000).toISOString() };
        } catch {
          return null;
        }
      };
      const ziaSessionJwt = (req.session as any).ziaToken;
      res.json({
        session: ziaSessionJwt ? ziaShow(ziaSessionJwt) : null,
        process: ziaProcessClaims
          ? { sub: ziaProcessClaims.sub, exp: new Date(ziaProcessClaims.exp * 1000).toISOString() }
          : null,
      });
    });
    this.app.get('/api/connections/status', async (req, res) => {
      try {
        const agent = await getAgentForSession(req).catch(() => null);
        const connections = buildConnectionStatuses(agent);
        res.json({ connections });
      } catch (error: any) {
        console.error('Connections status error:', error);
        res.status(500).json({ error: error.message });
      }
    });
  }

  // ============================================================================
  // Health Check
  // ============================================================================

  private handleHealth(_req: Request, res: Response): void {
    res.json({
      status: 'ok',
      service: 'agent0 App Server',
      oktaEnabled: this.oktaAuthHelper ? true : false,
      llmEnabled: true,
      timestamp: new Date().toISOString(),
    });
  }

  // ============================================================================
  // Start Server
  // ============================================================================

  async start(): Promise<void> {
    // The container's own egress identity. No-ops with one log line when .env.zia is absent, and
    // never awaited: minting is three Okta round trips and must not delay app.listen().
    ziaStartProcessToken();
    return new Promise<void>((resolve) => {
      this.app.listen(this.config.port, () => {
        console.log('='.repeat(60));
        console.log('🚀 Agent0 App Server');
        console.log('='.repeat(60));
        console.log(`✓ Server running on http://localhost:${this.config.port}`);
        console.log(`✓ Health check: http://localhost:${this.config.port}/health`);
        console.log(`✓ Web UI: http://localhost:${this.config.port}`);
        console.log(`✓ Chat endpoint: http://localhost:${this.config.port}/api/chat`);
        console.log('='.repeat(60));
        console.log('Configuration:');
        console.log(`  - Port: ${this.config.port}`);
        console.log(`  - Okta Auth: ${this.oktaAuthHelper ? '✅ Enabled' : '❌ Disabled'}`);
        if (this.oktaAuthHelper && this.config.okta) {
          console.log(`  - Okta Domain: ${this.config.okta.domain}`);
          console.log(`  - Login URL: http://localhost:${this.config.port}/login`);
        }
        console.log('='.repeat(60));
        console.log('Ready! 🎉');
        console.log('');
        resolve();
      });
    });
  }
}
// --- ZIA process-level egress token ------------------------------------------------------------
// The container's OWN egress identity, as a*************d@o**a.h***n.de, obtained with no human in
// the loop. The per-login session token is handled elsewhere (patch_agent0_zia_token.py ->
// patch_agent0_session_token.py -> patch_bedrock_zia_proxy.py) and these two levels never fall back
// to each other: a user session without a token gets a 407 rather than quietly egressing as the
// workload, because per-user attribution is the whole point of the JWT path.
//
// The leg order below is the one probe_zia_process_token.js measured inside this container on
// 2026-09-16, not a guess:
//   1  POST /api/v1/authn                                 -> status=SUCCESS + one-time sessionToken
//   2  GET <AS>/v1/authorize?prompt=none&sessionToken=...  -> 302 carrying code=
//   3  POST <AS>/v1/token grant_type=authorization_code    -> sub=a*************d@o**a.h***n.de
// and a CONNECT with the result returned 200 while the same CONNECT without it returned 407.
// Whether a CUSTOM authorization server consumes `sessionToken` at all was the one open question in
// the design - it does, so the cookie-jar route through /login/sessionCookieRedirect is not needed.
// A sessionToken is ONE-TIME and leg 2 consumes it even on failure, so every retry restarts at leg 1.
const ziaProcFs = require("fs");
const ziaProcCrypto = require("crypto");
// This package compiles with lib ES2020 and no DOM lib, so tsc does not necessarily declare the
// global fetch even though Node v20.20.2 in this image always has it - and it honours
// NODE_EXTRA_CA_CERTS, which is required here because ZIA re-signs every TLS connection. Reaching it
// through globalThis keeps the build independent of which @types/node happens to be installed.
const ziaProcFetch: any = (globalThis as any).fetch;

// Bind-mounted read-only from a mode-600 file on the VM, exactly like .env.app. NOT the environment:
// `-e` puts the password in the `docker run` argv, and both `-e` and `--env-file` put it in
// Config.Env, which `docker inspect` prints for the container's whole lifetime.
const ziaProcEnvFile = process.env.ZIA_WORKLOAD_ENV_FILE ?? "/app/packages/agent0/.env.zia";
// Deliberately a DIFFERENT file from ZIA_TOKEN_FILE, so a process-level token can never be picked up
// as a stand-in for a missing session token.
const ziaProcTokenFile = process.env.ZIA_PROCESS_TOKEN_FILE
  ?? "/app/packages/agent0/.zia-process-token.jwt";

let ziaProcessClaims: { sub: string; exp: number } | null = null;

function ziaProcCredentials(): { user: string; password: string } | null {
  try {
    const ziaVals: Record<string, string> = {};
    for (const line of ziaProcFs.readFileSync(ziaProcEnvFile, "utf8").split("\n")) {
      const m = /^([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line.trim());
      if (m) ziaVals[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
    if (!ziaVals.ZIA_WORKLOAD_USER || !ziaVals.ZIA_WORKLOAD_PASSWORD) return null;
    return { user: ziaVals.ZIA_WORKLOAD_USER, password: ziaVals.ZIA_WORKLOAD_PASSWORD };
  } catch {
    // Missing file, or a directory where docker created one because the mount source did not
    // exist. Both mean "not configured", which the caller reports as such.
    return null;
  }
}

async function ziaProcMint(cred: any): Promise<string> {
  const ziaDomain = process.env.OKTA_DOMAIN ?? "";
  const ziaIssuer = process.env.ZIA_EGRESS_ISSUER
    ?? "https://" + ziaDomain + "/oauth2/aus1xxxxxxxxxxxxE698";

  // Leg 1. The password never leaves this function and is never logged.
  const ziaAuthnRes = await ziaProcFetch("https://" + ziaDomain + "/api/v1/authn", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      username: cred.user,
      password: cred.password,
      options: { multiOptionalFactorEnroll: false, warnBeforePasswordExpired: false },
    }),
  });
  const ziaAuthn: any = await ziaAuthnRes.json().catch(() => ({}));
  if (ziaAuthn.status !== "SUCCESS" || !ziaAuthn.sessionToken) {
    // Name the state, because each one needs a different fix and two of them are Console work:
    // MFA_REQUIRED / MFA_ENROLL means this user still matches a 2FA authentication policy,
    // 401 E0000004 means a wrong password or a user that was never activated.
    throw new Error("authn " + (ziaAuthn.status ?? "HTTP " + ziaAuthnRes.status)
      + " " + (ziaAuthn.errorCode ?? ""));
  }

  // Leg 2. Same app, same single registered redirect_uri, same prompt=none as the browser flow -
  // no Okta app object has to be modified. redirect: "manual" so the 302 is read rather than
  // followed: the code must not be delivered to our own callback, which belongs to user sessions.
  const ziaVerifier = ziaProcCrypto.randomBytes(32).toString("base64url");
  const ziaQuery = new URLSearchParams();
  ziaQuery.append("client_id", process.env.OKTA_CLIENT_ID ?? "");
  ziaQuery.append("response_type", "code");
  ziaQuery.append("redirect_uri", process.env.OKTA_REDIRECT_URI ?? "");
  ziaQuery.append("scope", process.env.ZIA_EGRESS_SCOPE ?? "zia:egress");
  ziaQuery.append("state", "ziaproc." + ziaProcCrypto.randomBytes(16).toString("hex"));
  ziaQuery.append("prompt", "none");
  ziaQuery.append("code_challenge_method", "S256");
  ziaQuery.append("code_challenge",
    ziaProcCrypto.createHash("sha256").update(ziaVerifier).digest("base64url"));
  ziaQuery.append("sessionToken", ziaAuthn.sessionToken);
  const ziaAuthzRes = await ziaProcFetch(ziaIssuer + "/v1/authorize?" + ziaQuery.toString(),
    { redirect: "manual" });
  const ziaLoc = ziaAuthzRes.headers.get("location");
  const ziaCode = ziaLoc ? new URL(ziaLoc, "http://localhost").searchParams.get("code") : null;
  if (!ziaCode) {
    // HTTP 200 here means the Sign-In widget, i.e. the sessionToken was not accepted; a 302 with
    // error=login_required means prompt=none found no usable session.
    throw new Error("authorize?sessionToken produced no code: HTTP " + ziaAuthzRes.status);
  }

  // Leg 3. append(), never an object literal: under "strict": true a literal holding a union with
  // undefined is a TS2345, which is how an earlier attempt at the session-level patch failed.
  const ziaBody = new URLSearchParams();
  ziaBody.append("grant_type", "authorization_code");
  ziaBody.append("code", ziaCode);
  ziaBody.append("redirect_uri", process.env.OKTA_REDIRECT_URI ?? "");
  ziaBody.append("code_verifier", ziaVerifier);
  ziaBody.append("client_id", process.env.OKTA_CLIENT_ID ?? "");
  ziaBody.append("client_secret", process.env.OKTA_CLIENT_SECRET ?? "");
  const ziaTokRes = await ziaProcFetch(ziaIssuer + "/v1/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: ziaBody.toString(),
  });
  const ziaTok: any = await ziaTokRes.json().catch(() => ({}));
  if (ziaTokRes.status !== 200 || !ziaTok.access_token) {
    // Okta's error fields only, never the body: a partial success can carry a token.
    throw new Error("token endpoint HTTP " + ziaTokRes.status + " " + (ziaTok.error ?? "")
      + " " + (ziaTok.error_description ?? ""));
  }
  return ziaTok.access_token;
}

function ziaStartProcessToken(): void {
  const ziaCred = ziaProcCredentials();
  if (!ziaCred) {
    console.log("[ZIA] no process-level egress identity: " + ziaProcEnvFile
      + " has no ZIA_WORKLOAD_USER/ZIA_WORKLOAD_PASSWORD."
      + " The container's own egress stays unauthenticated; user sessions are unaffected.");
    return;
  }
  const ziaRun = async () => {
    try {
      const ziaJwt = await ziaProcMint(ziaCred);
      const ziaClaims = JSON.parse(
        Buffer.from(ziaJwt.split(".")[1], "base64url").toString());
      ziaProcessClaims = { sub: ziaClaims.sub, exp: ziaClaims.exp };
      // Truncated in place. Never write-then-mv: a new inode would leave anything holding the old
      // path - including a bind mount - reading the previous token forever.
      ziaProcFs.writeFileSync(ziaProcTokenFile, ziaJwt + "\n", { mode: 0o600 });
      // Claims only, never the token.
      console.log("[ZIA] process egress token: sub=" + ziaClaims.sub + " aud=" + ziaClaims.aud
        + " scp=" + ziaClaims.scp + " exp=" + new Date(ziaClaims.exp * 1000).toISOString());
      // Tokens live 60 minutes; re-mint 10 minutes early. The floor keeps a clock skew or an
      // unexpectedly short lifetime from turning this into a hot loop.
      const ziaNext = Math.max(60000, ziaClaims.exp * 1000 - Date.now() - 600000);
      setTimeout(ziaRun, ziaNext).unref();
    } catch (ziaErr: any) {
      // Degraded, not fatal: the container's own egress is simply unauthenticated until this
      // succeeds, and no user session is affected either way.
      console.error("[ZIA] process egress token mint failed: " + ziaErr.message
        + " - retrying in 60s");
      setTimeout(ziaRun, 60000).unref();
    }
  };
  void ziaRun();
}
// --- end ZIA process-level egress token --------------------------------------------------------
