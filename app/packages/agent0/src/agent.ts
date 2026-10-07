// agent.ts - Agent Identity: MCP Client + LLM Integration
import path from 'path';
import { Request } from 'express';
import * as dotenv from 'dotenv';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import Anthropic from '@anthropic-ai/sdk';
import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { TokenExchangeHandler, TokenExchangeConfig, parseScopeChallenge } from './connections/authorization-server/handler.js';
import { OAuthStsHandler, OAuthStsConfig } from './connections/application/handler.js';
import { GitHubService } from './connections/application/tools/github.js';
import { isConnectionDisabled } from './connections/config.js';
import {
  AuthStrategy,
  IdJagAuthStrategy,
  McpConnectionConfig,
  buildAuthStrategy,
  loadMcpConnectionConfigs,
} from './connections/auth-strategy.js';

// ============================================================================
// Scope Challenge Types
// ============================================================================

interface ScopeChallenge {
  error: string;
  scope: string[];
  errorDescription?: string;
}

/**
 * Extract scope challenge from any source (HTTP error, MCP response, or error message)
 * Returns null if no scope challenge found
 */
function extractScopeChallenge(source: any): ScopeChallenge | null {
  if (!source) return null;

  // Source 1: MCP tool response with isError
  if (source.isError && source.content) {
    for (const block of source.content) {
      if (block.type === 'text' && block.text) {
        try {
          const parsed = JSON.parse(block.text);
          if (parsed.error === 'insufficient_scope') {
            if (parsed.www_authenticate) {
              return parseScopeChallenge(parsed.www_authenticate);
            }
            if (parsed.required_scopes?.length) {
              return {
                error: 'insufficient_scope',
                scope: parsed.required_scopes,
                errorDescription: parsed.error_description,
              };
            }
          }
        } catch { /* not JSON */ }
      }
    }
  }

  // Source 2: WWW-Authenticate header (various locations)
  const wwwAuth =
    source.response?.headers?.get?.('www-authenticate') ||
    source.response?.headers?.['www-authenticate'] ||
    source.headers?.get?.('www-authenticate') ||
    source.headers?.['www-authenticate'] ||
    source.data?.headers?.['www-authenticate'];

  if (wwwAuth) {
    return parseScopeChallenge(wwwAuth);
  }

  // Source 3: Error message containing WWW-Authenticate
  if (source.message) {
    const match = source.message.match(/WWW-Authenticate:\s*(Bearer[^\n]+)/i);
    if (match) {
      return parseScopeChallenge(match[1]);
    }
  }

  return null;
}

// Load environment variables for agent
dotenv.config({ path: path.resolve(__dirname, '../.env.agent') });

// ============================================================================
// Agent LLM Configuration Types
// ============================================================================

/**
 * Agent LLM configuration (discriminated union for Anthropic vs Bedrock)
 */
type AgentLLMConfig = {
  mcpServerUrl: string;
} & (
  | {
      llmProvider: 'anthropic';
      anthropicApiKey: string;
      anthropicModel: string;
    }
  | {
      llmProvider: 'bedrock';
      awsRegion: string;
      awsAccessKeyId: string;
      awsSecretAccessKey: string;
      awsSessionToken?: string; // Optional
      bedrockModelId: string;
    }
);

// ============================================================================
// Environment Validation Function
// ============================================================================

/**
 * Validate agent LLM environment variables and return typed configuration
 */
function validateAgentLLMEnv(): AgentLLMConfig {
  const missing: string[] = [];
  const invalid: string[] = [];

  // Check MCP_SERVER_URL
  if (!process.env.MCP_SERVER_URL || process.env.MCP_SERVER_URL.trim() === '') {
    missing.push('MCP_SERVER_URL');
  } else {
    try {
      new URL(process.env.MCP_SERVER_URL);
    } catch {
      invalid.push('MCP_SERVER_URL (invalid URL format)');
    }
  }

  // Detect which LLM provider is being configured
  const hasAnthropicKey = process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY.trim() !== '';
  const hasBedrockVars = (process.env.AWS_REGION && process.env.AWS_REGION.trim() !== '') ||
                          (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_ACCESS_KEY_ID.trim() !== '');

  // Error if both providers are configured
  if (hasAnthropicKey && hasBedrockVars) {
    console.error('❌ Environment configuration error in .env.agent');
    console.error('   Cannot configure both Anthropic and AWS Bedrock providers');
    console.error('   Please choose one LLM provider:');
    console.error('   - For Anthropic: Set ANTHROPIC_API_KEY and ANTHROPIC_MODEL');
    console.error('   - For Bedrock: Set AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, BEDROCK_MODEL_ID');
    process.exit(1);
  }

  // Error if neither provider is configured
  if (!hasAnthropicKey && !hasBedrockVars) {
    console.error('❌ No LLM credentials configured\n');
    console.error('   Configure one of the following in .env.agent:\n');
    console.error('   ─────────────────────────────────────────────────────────');
    console.error('   For Anthropic:');
    console.error('     ANTHROPIC_API_KEY=sk-ant-...');
    console.error('     ANTHROPIC_MODEL=claude-sonnet-4-20250514\n');
    console.error('   For AWS Bedrock:');
    console.error('     AWS_REGION=us-east-1');
    console.error('     AWS_ACCESS_KEY_ID=AKIA...');
    console.error('     AWS_SECRET_ACCESS_KEY=...');
    console.error('     BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0\n');
    process.exit(1);
  }

  // Validate Anthropic configuration
  if (hasAnthropicKey) {
    if (!process.env.ANTHROPIC_MODEL || process.env.ANTHROPIC_MODEL.trim() === '') {
      missing.push('ANTHROPIC_MODEL');
    }
  }

  // Validate Bedrock configuration
  if (hasBedrockVars) {
    if (!process.env.AWS_REGION || process.env.AWS_REGION.trim() === '') {
      missing.push('AWS_REGION');
    }
    if (!process.env.AWS_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID.trim() === '') {
      missing.push('AWS_ACCESS_KEY_ID');
    }
    if (!process.env.AWS_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY.trim() === '') {
      missing.push('AWS_SECRET_ACCESS_KEY');
    }
    if (!process.env.BEDROCK_MODEL_ID || process.env.BEDROCK_MODEL_ID.trim() === '') {
      missing.push('BEDROCK_MODEL_ID');
    }
    // AWS_SESSION_TOKEN is optional, don't validate
  }

  // Report errors and exit if validation fails
  if (missing.length > 0 || invalid.length > 0) {
    console.error('❌ Environment configuration error in .env.agent');
    if (missing.length > 0) {
      console.error('   Missing required variables:', missing.join(', '));
    }
    if (invalid.length > 0) {
      console.error('   Invalid variables:', invalid.join(', '));
    }
    console.error('   Check packages/agent0/.env.agent file');
    process.exit(1);
  }

  console.log('✅ Agent LLM environment variables validated');

  // Return properly typed discriminated union
  if (hasAnthropicKey) {
    return {
      mcpServerUrl: process.env.MCP_SERVER_URL!,
      llmProvider: 'anthropic',
      anthropicApiKey: process.env.ANTHROPIC_API_KEY!,
      anthropicModel: process.env.ANTHROPIC_MODEL!,
    };
  } else {
    return {
      mcpServerUrl: process.env.MCP_SERVER_URL!,
      llmProvider: 'bedrock',
      awsRegion: process.env.AWS_REGION!,
      awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID!,
      awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
      awsSessionToken: process.env.AWS_SESSION_TOKEN,
      bedrockModelId: process.env.BEDROCK_MODEL_ID!,
    };
  }
}

// ============================================================================
// LLM Configuration Initialization
// ============================================================================

// Module-level state for LLM configuration
let llmConfig: AgentLLMConfig | null = null;
let llmConfigInitialized = false;
let llmConfigSource: 'env' | 'none' = 'none';

/**
 * Initialize LLM configuration from environment variables.
 */
export async function initializeLLMConfig(): Promise<void> {
  if (llmConfigInitialized) {
    return;
  }

  console.log('\n Initializing LLM configuration from environment variables...');

  try {
    llmConfig = validateAgentLLMEnv();
    llmConfigSource = 'env';
    llmConfigInitialized = true;
    console.log(' LLM credentials loaded from environment variables');
  } catch (error) {
    llmConfigInitialized = true;
    llmConfigSource = 'none';
    console.error(' No LLM credentials available');
    throw error;
  }
}

/**
 * Get the current LLM configuration source
 */
export function getLLMConfigSource(): 'env' | 'none' {
  return llmConfigSource;
}

/**
 * Check if LLM configuration has been initialized
 */
export function isLLMConfigInitialized(): boolean {
  return llmConfigInitialized;
}

// Initialize LLM configuration at module load from environment variables.
llmConfig = validateAgentLLMEnv();
llmConfigSource = 'env';
llmConfigInitialized = true;

// ============================================================================
// Agent Configuration
// ============================================================================

export interface AgentConfig {
  mcpServerUrl: string;
  name: string;
  version: string;

  // This instance is bound to a particular user and id token
  userContext: UserContext;
  idToken: string;

  // Token Exchange Config
  tokenExchange?: TokenExchangeConfig;

  // OAuth STS Brokered Consent Config
  oauthSts?: OAuthStsConfig;

  // Anthropic Direct
  anthropicApiKey?: string;
  anthropicModel?: string;
  // AWS Bedrock
  awsRegion?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  bedrockModelId?: string;
  enableLLM?: boolean;
}

export interface UserContext {
  email: string;
  name: string;
  sub: string;
}

// Build TokenExchangeConfig from environment variables
const buildTokenExchangeConfig = (): TokenExchangeConfig | undefined => {
  if (isConnectionDisabled('authorization_server')) return undefined;
  const mcpAuthServer = process.env.MCP_AUTHORIZATION_SERVER;
  const mcpAuthServerTokenEndpoint = process.env.MCP_AUTHORIZATION_SERVER_TOKEN_ENDPOINT;
  const oktaDomain = process.env.OKTA_DOMAIN;
  const agentId = process.env.AI_AGENT_ID;
  const privateKeyFile = process.env.AI_AGENT_PRIVATE_KEY_FILE;
  const privateKeyKid = process.env.AI_AGENT_PRIVATE_KEY_KID;
  const agentScopes = process.env.AI_AGENT_TODO_MCP_SERVER_SCOPES_TO_REQUEST;

  if (mcpAuthServer && mcpAuthServerTokenEndpoint && oktaDomain && agentId && privateKeyFile && privateKeyKid && agentScopes) {
    return {
      authorizationServer: mcpAuthServer,
      authorizationServerTokenEndpoint: mcpAuthServerTokenEndpoint,
      oktaDomain,
      clientId: agentId,
      privateKeyFile,
      privateKeyKid,
      agentScopes,
    };
  }
  return undefined;
};

// Build OAuthStsConfig from environment variables
const buildOAuthStsConfig = (): OAuthStsConfig | undefined => {
  if (isConnectionDisabled('application')) return undefined;
  const oktaDomain = process.env.OKTA_DOMAIN;
  const agentId = process.env.AI_AGENT_ID;
  const privateKeyFile = process.env.AI_AGENT_PRIVATE_KEY_FILE;
  const privateKeyKid = process.env.AI_AGENT_PRIVATE_KEY_KID;
  const resource = process.env.OAUTH_STS_RESOURCE;

  if (oktaDomain && agentId && privateKeyFile && privateKeyKid && resource) {
    console.log('✅ OAuth STS brokered consent configured');
    console.log(`   Resource: ${resource}`);
    return {
      oktaDomain,
      clientId: agentId,
      privateKeyFile,
      privateKeyKid,
      resource,
    };
  }
  if (resource) {
    console.warn('⚠️  OAUTH_STS_RESOURCE set but missing required agent identity vars (OKTA_DOMAIN, AI_AGENT_ID, AI_AGENT_PRIVATE_KEY_FILE, AI_AGENT_PRIVATE_KEY_KID)');
  }
  return undefined;
};

// Build agentConfig dynamically from the current LLM configuration loaded
// from environment variables at module load.
function buildAgentConfig(): Omit<AgentConfig, 'idToken' | 'userContext'> | null {
  if (!llmConfig) {
    return null;
  }

  const oauthStsConfig = buildOAuthStsConfig();

  if (llmConfig.llmProvider === 'anthropic') {
    return {
      mcpServerUrl: llmConfig.mcpServerUrl,
      name: 'agent0',
      version: '1.0.0',
      tokenExchange: buildTokenExchangeConfig(),
      oauthSts: oauthStsConfig,
      anthropicApiKey: llmConfig.anthropicApiKey,
      anthropicModel: llmConfig.anthropicModel,
      enableLLM: true,
    };
  } else {
    return {
      mcpServerUrl: llmConfig.mcpServerUrl,
      name: 'agent0',
      version: '1.0.0',
      tokenExchange: buildTokenExchangeConfig(),
      oauthSts: oauthStsConfig,
      awsRegion: llmConfig.awsRegion,
      awsAccessKeyId: llmConfig.awsAccessKeyId,
      awsSecretAccessKey: llmConfig.awsSecretAccessKey,
      awsSessionToken: llmConfig.awsSessionToken,
      bedrockModelId: llmConfig.bedrockModelId,
      enableLLM: true,
    };
  }
}

export async function getAgentForUserContext(idToken: string, userContext: UserContext): Promise<Agent> {
  await initializeLLMConfig();

  const agentConfig = buildAgentConfig();
  if (!agentConfig) {
    throw new Error('LLM configuration not available. Cannot create agent.');
  }

  return new Agent({
    ...agentConfig,
    idToken,
    userContext,
  });
}

const subjectToAgent = new Map<string, Agent>();

export async function getAgentForSession (req: Request): Promise<Agent | null> {
  const ziaInner = await getAgentForSessionInner(req);
  // Hand this session's OWN ZIA egress token to this session's Agent. subjectToAgent below already
  // keys one Agent per Okta subject, so bedrockClient and its ziaAgent closure are already
  // per-user; createConnection reads this property off `this` on every CONNECT.
  //
  // Copied on EVERY request, not at Agent creation: the Agent is cached for the process lifetime,
  // so a one-time copy would pin the first login's identity onto every later request. `?? null`
  // is the fail-closed half - a session with no token CLEARS the property, so the next CONNECT
  // goes out with no Proxy-Authorization and ZIA answers 407, rather than reusing a stale
  // identity. There is no fallback to the process-level workload token by design.
  if (ziaInner) (ziaInner as any).ziaSessionToken = (req.session as any).ziaToken ?? null;
  // The same carry for the tool plane, and deliberately a SECOND property rather than a reuse of the
  // one above: ziaToken is audienced at zia-egress and goes into Proxy-Authorization, while this one
  // is audienced at agent0 and is the OBO subject. Swapping them yields an opaque AADSTS or a 407.
  //
  // Per request for the same reason as ziaSessionToken: the Agent is cached for the process lifetime,
  // so a one-time copy would pin the first login's token onto every later request. `?? null` is the
  // fail-closed half - OboAuthStrategy turns an empty subject into status:'error' rather than calling
  // Entra with nothing. Okta deploys never read this property.
  if (ziaInner) (ziaInner as any).entraUserToken = (req.session as any).accessToken ?? null;
  return ziaInner;
}

async function getAgentForSessionInner (req: Request): Promise<Agent | null> {
  const userInfo = req.session.userInfo;
  const idToken = req.session.idToken;
  if (!userInfo || !userInfo.sub || !idToken) {
    console.warn('⚠️  Cannot get agent: missing user info or id token in session');
    console.info(userInfo);
    console.info(idToken);
    return null;
  }
  const subject = userInfo.sub;

  const existingAgent = subjectToAgent.get(subject);

  if (existingAgent) {
    return existingAgent;
  }

  const agent = await getAgentForUserContext(
    idToken, userInfo
  );

  subjectToAgent.set(subject, agent);

  // connect() below performs the OBO exchange, so the subject token has to be on the Agent BEFORE it
  // runs. getAgentForSession assigns entraUserToken after this function RETURNS, which is right for
  // every later tool call and too late for this one: the Agent is then cached in subjectToAgent and
  // MCP connect is once-per-process, so the failure is permanent for that login. Without this line a
  // browser login ends in `entra_obo_failed no user access token on the session` and an empty tool
  // list, while the headless probe - which POSTs to /mcp itself - passes.
  // ziaSessionToken needs no equivalent: it is read at CONNECT time, always later than this.
  // Okta reads neither property; IdJagAuthStrategy takes its subject from the id token.
  (agent as any).entraUserToken = (req.session as any).accessToken ?? null;
  await agent.connect();

  return agent;
};

export async function disconnectAll(): Promise<void> {
  for (const agent of subjectToAgent.values()) {
    await agent.disconnect();
  }
  subjectToAgent.clear();
}

// ============================================================================
// Agent Class - MCP Client + LLM Integration
// ============================================================================

// Maximum number of step-up authorization retries per tool call
const MAX_STEPUP_RETRIES = 2;

/**
 * A live per-MCP connection: config + SDK client/transport + strategy + tools.
 * Lifecycle owned by the Agent; one instance per entry in McpConnectionConfig[].
 */
interface McpConnection {
  config: McpConnectionConfig;
  strategy: AuthStrategy;
  client: Client;
  transport: StreamableHTTPClientTransport | null;
  connected: boolean;
  tools: any[];
  /** Scopes last granted by the auth strategy (only meaningful for id-jag). */
  grantedScopes: string[];
}

/**
 * Returned from Agent.connect() when an MCP reports `interaction_required`
 * (OAuth STS consent flow). Surfaced via /api/chat -> data.pending_consents.
 */
export interface PendingConsent {
  mcpId: string;
  resource: string;
  interactionUri: string;
  message?: string;
}

export class Agent {
  private mcps: McpConnection[] = [];
  /** tool-name -> owning mcpId for dispatch in callTool(). */
  private toolToMcpId: Map<string, string> = new Map();
  private config: AgentConfig;
  private availableTools: any[] = [];
  private anthropic: Anthropic | null = null;
  private bedrockClient: BedrockRuntimeClient | null = null;
  private conversationHistory: Array<{
    role: 'user' | 'assistant';
    content: string | Array<any>;
  }> = [];
  private oauthStsHandler: OAuthStsHandler | null = null;
  /** Pending OAuth-STS consents from the last connect() call. Drained by /api/chat. */
  private pendingConsents: PendingConsent[] = [];

  constructor(config: AgentConfig) {
    this.config = config;

    // Build the MCP connection list from the env-driven loader.
    // Each entry gets its own SDK Client + AuthStrategy — they stay
    // independent so one MCP's consent flow / scope step-up does not
    // disturb another's live session.
    const mcpConfigs = loadMcpConnectionConfigs();
    for (const mcpConfig of mcpConfigs) {
      this.mcps.push({
        config: mcpConfig,
        strategy: buildAuthStrategy(mcpConfig.auth),
        client: new Client(
          { name: config.name, version: config.version },
          { capabilities: {} },
        ),
        transport: null,
        connected: false,
        tools: [],
        grantedScopes: [],
      });
    }

    // Initialize OAuth STS Handler for the legacy GitHub OIN integration
    // (separate from any GitHub MCP OAuth-STS MCP connection — different
    // resource indicator, different managed connection in Okta).
    if (config.oauthSts) {
      this.oauthStsHandler = new OAuthStsHandler(config.oauthSts);
    }

    // Initialize LLM client - Priority: Anthropic Direct > AWS Bedrock
    if (config.anthropicApiKey && config.enableLLM !== false) {
      this.anthropic = new Anthropic({
        apiKey: config.anthropicApiKey,
      });
      console.log('🤖 LLM integration enabled (Anthropic Direct)');
    } else if (
      config.awsRegion &&
      config.awsAccessKeyId &&
      config.awsSecretAccessKey &&
      config.enableLLM !== false
    ) {
      // ZIA SSL inspection does not negotiate ALPN (measured 2026-09-15: offering
      // h2,http/1.1 through the tunnel yields alpnProtocol === false). The AWS SDK installs
      // NodeHttp2Handler for bedrock-runtime by default, so every call dies at the transport
      // layer with "Protocol error", which surfaces to the user as
      // "LLM processing failed: Protocol error". Certificates are fine - NODE_EXTRA_CA_CERTS
      // fixes validation, not ALPN. HTTP/1.1 through the inspected tunnel works.
      //
      // @smithy/node-http-handler is a transitive dep of @aws-sdk/client-bedrock-runtime and
      // NOT a direct dependency of this package, so under pnpm's strict node_modules layout a
      // plain import would fail to resolve. Resolve it through the bedrock client's own
      // resolution root instead of adding a dependency.
      const { createRequire } = require("module");
      const bedrockRequire = createRequire(require.resolve("@aws-sdk/client-bedrock-runtime"));
      const { NodeHttpHandler } = bedrockRequire("@smithy/node-http-handler");
      // --- ZIA Workload JWT Authentication ---------------------------------------------------
      // Bedrock must not use the default route. Default-route traffic is inspected by ZIA but never
      // authenticated - measured 2026-09-16 from inside this container, direct TLS to
      // bedrock-runtime.eu-central-1.amazonaws.com succeeds with authorized=true and no challenge.
      // Only an explicit proxy CONNECT is authenticated, and the credential must ride the CONNECT
      // itself as `Proxy-Authorization: Bearer <jwt>` - not as an HTTP request header.
      //
      // ZIA_PROXY is your ZIA explicit proxy as host:port (lab example: 185.46.xxx.xxx:80). There is
      // deliberately no default: the Service Edge differs per Zscaler cloud and region, and a wrong
      // default fails as a confusing 407. Unset, every Bedrock call fails with an error naming it.
      // Measured from inside this container: no token -> "HTTP/1.1 407 Unauthorized";
      // valid token -> "HTTP/1.1 200 Connection Established".
      const ziaNet = require("net");
      const ziaTls = require("tls");
      const ziaFs = require("fs");
      const [ziaHost, ziaPort] = (process.env.ZIA_PROXY ?? "").split(":");
      // OPT-IN ONLY, and deliberately without a default path. The token normally arrives on the
      // session (see below); this is just the hand-injection escape hatch that keeps
      // probe_zia_connect_live_token.js usable. A default would be actively harmful:
      // /app/packages/agent0/.zia-token.jwt still holds a stale token from an earlier login, so every
      // session without one of its own would silently egress as THAT user instead of being refused.
      const ziaTokenFile = process.env.ZIA_TOKEN_FILE;

      // keepAlive is REQUIRED, and not for performance. With it off, Node puts `Connection: close` on
      // the inner request and ZIA's proxy resets the tunnel: measured 2026-09-16 at n=20 against
      // bedrock-runtime through the ZIA explicit proxy, `Connection: close` -> 2/20, `Connection: keep-alive`
      // -> 20/20, over identical CONNECTs. That is the whole reason curl looked reliable while the SDK
      // was flaky - curl never sends `Connection: close`. The failure is an ECONNRESET after a
      // successful handshake, with the request written and zero bytes read back.
      // keepSocketAlive then returns false so the socket is still destroyed after each response, which
      // keeps what the plain no-keepAlive agent was for: one authenticated CONNECT per Bedrock call
      // (measured CONNECTs=20 for 20 calls), a fresh token read every time, and one line per call in
      // ZIA Web Insights. Plain keepAlive:true reuses one tunnel for every call (CONNECTs=1), which
      // would authenticate once at startup and then ride that session indefinitely.
      const ziaAgent = new (require("https").Agent)({ keepAlive: true });
      ziaAgent.keepSocketAlive = () => false;
      ziaAgent.createConnection = (opts: any, cb: any) => {
        const target = `${opts.host}:${opts.port ?? 443}`;
        if (!ziaHost || !ziaPort) {
          return cb(new Error("ZIA_PROXY is not set - expected host:port of the ZIA explicit proxy"));
        }
        const sock = ziaNet.connect(Number(ziaPort), ziaHost);
        sock.once("error", cb);
        sock.once("connect", () => {
          // Resolve the token on EVERY CONNECT, never in a closure at client-construction time: a ZIA
          // JWT lives 60 minutes and a re-minted one has to take effect immediately. Order:
          //
          //   1. THIS SESSION'S OWN TOKEN. `this` is the Agent instance - subjectToAgent in agent.ts
          //      already keys one Agent per Okta subject, and getAgentForSession copies that session's
          //      req.session.ziaToken onto it on every request, so two concurrent logins egress as two
          //      different identities rather than as whoever logged in last. createConnection is an
          //      arrow function inside an Agent method, which is what lets `this` reach in here.
          //   2. ZIA_TOKEN_FILE, and only if the variable is actually set.
          //   3. Nothing - FAIL CLOSED. The CONNECT still goes out, without a credential, so ZIA
          //      answers 407 and the error reads "the proxy refused us". There is deliberately NO
          //      fallback to the process-level workload token: a user session quietly egressing as
          //      agent0-workload would destroy the per-user attribution this whole path exists for.
          let ziaToken = (this as any).ziaSessionToken ?? null;
          if (!ziaToken && ziaTokenFile) {
            try {
              ziaToken = ziaFs.readFileSync(ziaTokenFile, "utf8").trim();
            } catch {
              // An opt-in path that cannot be read is a misconfiguration, not a normal state, so say
              // so - the path only, never the contents.
              console.error("[ZIA] ZIA_TOKEN_FILE is set but unreadable: " + ziaTokenFile);
            }
          }
          const auth = ziaToken ? `Proxy-Authorization: Bearer ${ziaToken}\r\n` : "";
          sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
        });
        // Read the CONNECT response with once("readable") + read(), never with on("data"). A "data"
        // listener puts the socket in flowing mode permanently - removeListener does not pause it - so
        // bytes arriving between the 200 and tls.connect() taking over get read off the socket and
        // dropped. ZIA sends 0 trailing bytes today, so this is latent rather than active, but a proxy
        // is allowed to put the first payload in the same segment as the 200 and those bytes belong to
        // TLS. https-proxy-agent avoids flowing mode for exactly this reason.
        let buf = "";
        const onReadable = () => {
          let chunk: Buffer | null;
          while ((chunk = sock.read()) !== null) buf += chunk.toString("latin1");
          const end = buf.indexOf("\r\n\r\n");
          if (end < 0) {
            sock.once("readable", onReadable);   // header split across segments: `buf` keeps the prefix
            return;
          }
          const status = buf.slice(0, buf.indexOf("\r\n"));
          if (!/^HTTP\/1\.[01] 200\b/.test(status)) {
            sock.destroy();
            // Deliberately does not include the request - `auth` carries the token.
            return cb(new Error(`ZIA proxy refused CONNECT ${target}: ${status}`));
          }
          // Measured 0 bytes here, but a proxy is allowed to send the first payload in the same
          // segment as the 200, and those bytes belong to TLS.
          const rest = buf.slice(end + 4);
          if (rest.length) sock.unshift(Buffer.from(rest, "latin1"));
          sock.removeListener("error", cb);
          // Carry the caller's own TLS options through - `ca`, `rejectUnauthorized`, `minVersion`,
          // `checkServerIdentity` and anything else the SDK set. Only the dialing fields are dropped,
          // because we already have the socket. Passing just {socket, servername} silently discards
          // them, which shows up as a bogus "self-signed certificate" from a perfectly good chain.
          const tlsOpts = Object.assign({}, opts);
          delete tlsOpts.host;
          delete tlsOpts.port;
          delete tlsOpts.path;
          tlsOpts.socket = sock;
          tlsOpts.servername = opts.servername ?? opts.host;
          // ZIA's inspection negotiates no ALPN on this path (measured alpn=false), so ask for
          // http/1.1 only. HTTP/2 through the inspected proxy dies as a bare "Protocol error".
          tlsOpts.ALPNProtocols = ["http/1.1"];
          cb(null, ziaTls.connect(tlsOpts));
        };
        sock.once("readable", onReadable);
      };

      this.bedrockClient = new BedrockRuntimeClient({
        region: config.awsRegion,
        credentials: {
          accessKeyId: config.awsAccessKeyId,
          secretAccessKey: config.awsSecretAccessKey,
          sessionToken: config.awsSessionToken,
        },
        requestHandler: new NodeHttpHandler({ httpsAgent: ziaAgent }),
      });
      console.log('🤖 LLM integration enabled (AWS Bedrock)');
    } else {
      console.log('🤖 ❌ LLM integration not enabled');
    }
  }

  // ============================================================================
  // MCP Connection Methods
  // ============================================================================

  /**
   * Connect to every configured MCP server in parallel-ish order, each with
   * its own auth strategy. Returns:
   *   - ok: the MCPs that connected successfully
   *   - pending: MCPs that reported `interaction_required` (OAuth STS consent)
   * MCPs that hard-errored are logged and omitted from both lists.
   *
   * After this runs, fetchAvailableTools() has populated `availableTools` +
   * `toolToMcpId` with the union across successful MCPs.
   */
  async connect(): Promise<{ ok: McpConnection[]; pending: PendingConsent[] }> {
    const ok: McpConnection[] = [];
    const pending: PendingConsent[] = [];

    if (!this.isLLMEnabled()) {
      console.warn('⚠️ LLM integration not enabled. Cannot connect agent to MCP.');
      return { ok, pending };
    }

    if (this.mcps.length === 0) {
      console.warn('⚠️  No MCP connections configured. Agent will run with no tools.');
      return { ok, pending };
    }

    for (const mcp of this.mcps) {
      const result = await this.connectSingleMcp(mcp);
      if (result === 'ok') {
        ok.push(mcp);
      } else if (result.status === 'interaction_required') {
        pending.push({
          mcpId: mcp.config.id,
          resource: result.resource,
          interactionUri: result.interactionUri,
          message: result.message,
        });
      }
      // hard errors: logged inside connectSingleMcp; neither ok nor pending
    }

    // Union tool list + populate dispatch map
    this.rebuildUnifiedToolList();
    this.pendingConsents = pending;
    return { ok, pending };
  }

  /** Returns and clears the pending-consent list from the last connect(). */
  consumePendingConsents(): PendingConsent[] {
    const out = this.pendingConsents;
    this.pendingConsents = [];
    return out;
  }

  /** Non-destructive read of the current pending-consent list. */
  getPendingConsents(): PendingConsent[] {
    return [...this.pendingConsents];
  }

  /**
   * Retry a previously pending MCP's connect (e.g. after user completed
   * OAuth-STS consent). If it succeeds, the MCP's tools join the union.
   */
  async retryPendingMcp(mcpId: string): Promise<'ok' | 'still_pending' | 'error'> {
    const mcp = this.mcps.find(m => m.config.id === mcpId);
    if (!mcp) return 'error';
    if (mcp.connected) return 'ok';
    const result = await this.connectSingleMcp(mcp);
    this.rebuildUnifiedToolList();
    if (result === 'ok') {
      // Drop any stale pending entry for this MCP
      this.pendingConsents = this.pendingConsents.filter(p => p.mcpId !== mcpId);
      return 'ok';
    }
    if (typeof result === 'object' && result.status === 'interaction_required') {
      return 'still_pending';
    }
    return 'error';
  }

  /**
   * Connect a single MCP. Returns:
   *   'ok' on success,
   *   a pending-consent shape when the strategy reported interaction_required,
   *   an 'error' shape otherwise (also logged).
   */
  private async connectSingleMcp(
    mcp: McpConnection,
    requestedScopes?: string,
  ): Promise<
    | 'ok'
    | { status: 'interaction_required'; resource: string; interactionUri: string; message?: string }
    | { status: 'error'; error: string }
  > {
    const label = mcp.config.displayName || mcp.config.id;
    try {
      console.log(`🔌 Connecting MCP [${mcp.config.id}] (${label})...`);
      console.log(`   Server: ${mcp.config.serverUrl}`);
      console.log(`   Auth strategy: ${mcp.strategy.kind}`);

      // The subject differs by IDP: id-jag exchanges the ID token, OBO requires the user's ACCESS token
      // audienced at agent0 (an ID token is rejected outright). Selected here because only this scope
      // holds both, and on `kind` because that discriminator already exists - it is logged one line up.
      // The else branch is the original expression verbatim, so the Okta path is unchanged.
      const subjectToken = mcp.strategy.kind === 'obo'
        ? ((this as any).entraUserToken ?? '')
        : this.config.idToken;
      const tokenResult = await mcp.strategy.getAccessToken(subjectToken, requestedScopes);

      if (tokenResult.status === 'interaction_required') {
        console.log(`🔐 MCP [${mcp.config.id}] reports interaction_required — consent pending.`);
        return {
          status: 'interaction_required',
          resource: tokenResult.resource,
          interactionUri: tokenResult.interactionUri,
          message: tokenResult.message,
        };
      }
      if (tokenResult.status === 'error') {
        console.error(`❌ MCP [${mcp.config.id}] auth failed: ${tokenResult.error} ${tokenResult.errorDescription || ''}`);
        return { status: 'error', error: tokenResult.error };
      }

      console.log(`✅ MCP [${mcp.config.id}] token acquired (expires in ${tokenResult.expiresIn}s)`);

      mcp.grantedScopes = tokenResult.scope?.split(' ') || [];
      if (mcp.grantedScopes.length) {
        console.log(`🎯 MCP [${mcp.config.id}] scopes: ${mcp.grantedScopes.join(' ')}`);
      }

      mcp.transport = new StreamableHTTPClientTransport(
        new URL(mcp.config.serverUrl),
        {
          requestInit: {
            headers: { 'Authorization': `Bearer ${tokenResult.accessToken}` },
          },
        },
      );

      await mcp.client.connect(mcp.transport);
      mcp.connected = true;

      // Per-MCP tool list
      const toolsResp = await mcp.client.listTools();
      mcp.tools = toolsResp.tools || [];

      console.log(`✅ MCP [${mcp.config.id}] connected with ${mcp.tools.length} tool(s)`);
      return 'ok';
    } catch (err: any) {
      console.error(`❌ MCP [${mcp.config.id}] connect failed:`, err?.message || err);
      mcp.connected = false;
      return { status: 'error', error: err?.message || String(err) };
    }
  }

  /**
   * Reconnect one MCP with additional scopes (step-up). Only that MCP is
   * disconnected/reconnected — others stay live.
   */
  private async reconnectMcpWithScopes(mcpId: string, requiredScopes: string[]): Promise<boolean> {
    const mcp = this.mcps.find(m => m.config.id === mcpId);
    if (!mcp) {
      console.error(`❌ Step-up: unknown mcpId=${mcpId}`);
      return false;
    }
    // Only id-jag supports scope step-up — oauth-sts ignores requestedScopes
    const allScopes = [...new Set([...mcp.grantedScopes, ...requiredScopes])];
    console.log(`🔄 Step-up authorization for MCP [${mcpId}]...`);
    console.log(`   Current: ${mcp.grantedScopes.join(' ') || '(none)'}`);
    console.log(`   Requesting: ${allScopes.join(' ')}`);

    if (mcp.connected) {
      await this.disconnectSingleMcp(mcp);
    }

    const result = await this.connectSingleMcp(mcp, allScopes.join(' '));
    this.rebuildUnifiedToolList();
    return result === 'ok';
  }

  async disconnect(): Promise<void> {
    for (const mcp of this.mcps) {
      await this.disconnectSingleMcp(mcp);
    }
    console.log('\n👋 Disconnected from all MCP servers');
  }

  private async disconnectSingleMcp(mcp: McpConnection): Promise<void> {
    if (mcp.transport && mcp.connected) {
      try {
        await mcp.client.close();
      } catch (err: any) {
        console.warn(`   (close warning for [${mcp.config.id}]): ${err?.message || err}`);
      }
      mcp.connected = false;
      mcp.transport = null;
    }
  }

  /** Agent is "up" if at least one MCP connected — partial is OK. */
  isAgentConnected(): boolean {
    return this.mcps.some(m => m.connected);
  }

  /** Per-MCP connection view for /api/connections/status. */
  getMcpConnectionStatuses(): Array<{
    id: string;
    displayName?: string;
    serverUrl: string;
    resourceIndicator?: string;
    oktaMcpServerId?: string;
    strategy: string;
    connected: boolean;
  }> {
    return this.mcps.map(m => ({
      id: m.config.id,
      displayName: m.config.displayName,
      serverUrl: m.config.serverUrl,
      resourceIndicator: m.config.resourceIndicator,
      oktaMcpServerId: m.config.oktaMcpServerId,
      strategy: m.strategy.kind,
      connected: m.connected,
    }));
  }

  // ============================================================================
  // Tool Discovery and Execution
  // ============================================================================

  /**
   * Build the union of tools across every connected MCP, and populate the
   * toolName -> mcpId dispatch map. On name collision, the later MCP's tool
   * is renamed `<mcpId>__<name>` and logged — the LLM still sees both.
   */
  private rebuildUnifiedToolList(): void {
    this.availableTools = [];
    this.toolToMcpId.clear();

    for (const mcp of this.mcps) {
      if (!mcp.connected) continue;
      for (const tool of mcp.tools) {
        let exposedName = tool.name;
        if (this.toolToMcpId.has(exposedName)) {
          const renamed = `${mcp.config.id}__${tool.name}`;
          console.warn(`⚠️  Tool name collision on "${tool.name}" — exposing [${mcp.config.id}] as "${renamed}"`);
          exposedName = renamed;
        }
        this.toolToMcpId.set(exposedName, mcp.config.id);
        this.availableTools.push({
          ...tool,
          name: exposedName,
          // Keep the underlying MCP name so callTool can forward it untouched.
          _originalName: tool.name,
          _mcpId: mcp.config.id,
        });
      }
    }

    console.log('🔧 Available Tools (union across MCPs):');
    console.log('='.repeat(60));
    this.availableTools.forEach((tool, index) => {
      console.log(`${index + 1}. [${tool._mcpId}] ${tool.name}`);
      console.log(`   📝 ${tool.description}`);
      if (tool.inputSchema?.properties) {
        const params = Object.keys(tool.inputSchema.properties);
        if (params.length > 0) {
          console.log(`   📋 Parameters: ${params.join(', ')}`);
        }
      }
      console.log('');
    });
    console.log('='.repeat(60));
  }

  /** Legacy entry point kept for compatibility; just rebuilds the union. */
  async fetchAvailableTools(): Promise<void> {
    this.rebuildUnifiedToolList();
  }

  /**
   * Call an MCP tool with automatic scope challenge handling.
   * Dispatches through toolToMcpId to the owning MCP's client. Step-up
   * authorization only reconnects the offending MCP.
   */
  async callTool(toolName: string, args: any = {}, _retryCount: number = 0): Promise<any> {
    console.log(`\n🔄 Executing tool: ${toolName}`);
    console.log(`   Arguments: ${JSON.stringify(args, null, 2)}`);

    const mcpId = this.toolToMcpId.get(toolName);
    if (!mcpId) {
      throw new Error(`No MCP owns tool "${toolName}"`);
    }
    const mcp = this.mcps.find(m => m.config.id === mcpId);
    if (!mcp) {
      throw new Error(`MCP [${mcpId}] not found for tool "${toolName}"`);
    }

    // Find the original tool name (un-renamed) for the underlying MCP call.
    const exposed = this.availableTools.find(t => t.name === toolName);
    const underlyingName = exposed?._originalName || toolName;

    try {
      const response = await mcp.client.callTool({ name: underlyingName, arguments: args });

      const challenge = extractScopeChallenge(response);
      if (challenge && _retryCount < MAX_STEPUP_RETRIES) {
        return this.retryWithStepUp(toolName, args, mcp, challenge, _retryCount);
      }

      return response;
    } catch (error: any) {
      const challenge = extractScopeChallenge(error);
      if (challenge && _retryCount < MAX_STEPUP_RETRIES) {
        return this.retryWithStepUp(toolName, args, mcp, challenge, _retryCount);
      }

      // Non-scope 401/403 on an oauth-sts MCP: bearer likely revoked. Clear
      // the cached token on the owning strategy and retry once.
      if (
        mcp.strategy.kind === 'oauth-sts' &&
        _retryCount < MAX_STEPUP_RETRIES &&
        /40[13]/.test(String(error?.message || ''))
      ) {
        console.log(`⚠️  MCP [${mcp.config.id}] returned 401/403 — clearing cached token and reconnecting.`);
        mcp.strategy.clearCache();
        if (mcp.connected) await this.disconnectSingleMcp(mcp);
        const result = await this.connectSingleMcp(mcp);
        this.rebuildUnifiedToolList();
        if (result === 'ok') {
          return this.callTool(toolName, args, _retryCount + 1);
        }
      }

      console.error('❌ Tool execution failed:', error);
      throw error;
    }
  }

  /**
   * Retry tool call after step-up authorization — reconnects only the
   * owning MCP, leaving other MCP sessions untouched.
   */
  private async retryWithStepUp(
    toolName: string,
    args: any,
    mcp: McpConnection,
    challenge: ScopeChallenge,
    retryCount: number
  ): Promise<any> {
    console.log(`\n⚠️  Scope challenge for: ${toolName} on MCP [${mcp.config.id}]`);
    console.log(`   Required: ${challenge.scope.join(' ')}`);

    if (mcp.strategy.kind !== 'id-jag') {
      // Scope step-up is an ID-JAG concept; oauth-sts MCPs surface missing
      // permissions as interaction_required, not insufficient_scope.
      console.warn(`   Step-up only supported on id-jag MCPs; [${mcp.config.id}] is ${mcp.strategy.kind}. Bubbling up.`);
      throw new Error(`insufficient_scope on non-id-jag MCP [${mcp.config.id}]: ${challenge.scope.join(' ')}`);
    }

    if (await this.reconnectMcpWithScopes(mcp.config.id, challenge.scope)) {
      console.log('✅ Retrying tool call...');
      return this.callTool(toolName, args, retryCount + 1);
    }

    throw new Error(`Step-up authorization failed for: ${challenge.scope.join(' ')}`);
  }

  /** Expose the underlying ID-JAG handler for legacy callers. */
  getTokenExchangeHandler(): TokenExchangeHandler | null {
    const idJag = this.mcps.find(m => m.strategy.kind === 'id-jag');
    return idJag ? (idJag.strategy as IdJagAuthStrategy).getUnderlyingHandler() : null;
  }

  // ============================================================================
  // Auth Provider Management
  // ============================================================================

  /**
   * Update the ID token (useful when session is refreshed)
   * Note: Will need to reconnect to MCP server with new token
   */
  updateIdToken(newIdToken: string): void {
    this.config.idToken = newIdToken;
    console.log('🔑 ID token updated - reconnect to MCP server for new access token');
  }

  getAvailableTools(): any[] {
    return this.availableTools;
  }

  // ============================================================================
  // LLM Integration - Process User Input
  // ============================================================================

  async processUserInput(
    input: string,
    userContext?: UserContext | null
  ): Promise<{ success: boolean; message: string; data?: any; toolResults?: any[] }> {
    if (!this.anthropic && !this.bedrockClient) {
      throw new Error('LLM client not initialized');
    }
    try {
      return await this.processWithLLM(input, userContext);
    } catch (error: any) {
      return {
        success: false,
        message: error.message || 'Error processing input',
      };
    }
  }

  private async processWithLLM(
    userMessage: string,
    userContext?: UserContext | null
  ): Promise<{ success: boolean; message: string; data?: any; toolResults?: any[] }> {
    try {
      // Add user message to conversation history
      this.conversationHistory.push({
        role: 'user',
        content: userMessage,
      });

      // Convert MCP tools (union across all connected MCPs) to Anthropic tool format
      const tools: any[] = this.availableTools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema: tool.inputSchema || {
          type: 'object',
          properties: {},
        },
      }));

      // Create system message with context.
      // Tool list is fully derived from connected MCPs' list_tools responses —
      // no hardcoded tool descriptors. GitHub MCP, Todo0 MCP, etc. all register
      // through the same `availableTools` path.
      let systemMessage = `You are a helpful AI assistant with access to the following MCP tools: ${this.availableTools.map(t => t.name).join(', ') || '(none connected)'}.

When the user asks to do something, analyze their request and call the appropriate tool with the correct parameters. If a tool you would need isn't in the list, explain that capability isn't currently available. Always be helpful and conversational; ask for clarification when needed.`;

      // Add user context if available
      if (userContext) {
        systemMessage += `\n\nCurrent user context:
- User: ${userContext.name} (${userContext.email})
- User ID: ${userContext.sub}

When the user asks "who am I" or "who is the owner", you can refer to this information.
The todos you manage belong to this user.`;
      }

      // ----------------------------------------------------------------
      // Tool-use loop (aka "agentic loop"):
      //   1. Call the LLM.
      //   2. If the response has any `tool_use` blocks, execute ALL of them,
      //      emit matching `tool_result` blocks, append to history, loop.
      //   3. Stop when the response is text-only (or the safety cap is hit).
      // This replaces the earlier single-shot "final response" call, which
      // broke whenever the LLM wanted to chain calls (e.g. get_me → list_repos).
      // Anthropic's API requires every tool_use be followed by a matching
      // tool_result IN THE NEXT MESSAGE — so we must never push an assistant
      // turn with tool_use without also pushing its tool_results.
      // ----------------------------------------------------------------
      const MAX_TOOL_ITERATIONS = 8;
      const toolResults: any[] = [];
      let responseMessage = '';

      let response = this.anthropic
        ? await this.callAnthropicAPI(systemMessage, tools)
        : await this.callBedrockAPI(systemMessage, tools);

      for (let iter = 0; iter < MAX_TOOL_ITERATIONS; iter++) {
        const toolUseBlocks = response.content.filter((b: any) => b.type === 'tool_use');

        if (toolUseBlocks.length === 0) {
          // Terminal turn: text-only. Extract message, record history, done.
          const textBlocks = response.content.filter((b: any) => b.type === 'text');
          if (textBlocks.length > 0) {
            responseMessage = textBlocks.map((b: any) => b.text).join('\n');
          }
          this.conversationHistory.push({ role: 'assistant', content: response.content });
          break;
        }

        // There are tool_use blocks. Execute every one and build the
        // tool_result blocks IN THE SAME ORDER. Anthropic allows any order
        // for tool_result, but we pair by tool_use_id anyway.
        const toolResultBlocks: any[] = [];

        // Early-return sentinel: if any GitHub OIN tool reports
        // interaction_required, we bail out BEFORE pushing the assistant
        // turn — otherwise history would have an orphan tool_use.
        let pendingConsentReturn: { name: string; input: any; uri: string; msg?: string } | null = null;

        for (const block of toolUseBlocks) {
          // GitHub OIN (non-MCP) path
          if ((block.name === 'github_comment_on_pr' || block.name === 'github_list_repos') && this.oauthStsHandler) {
            const githubResult = await this.handleGitHubTool(block.name, block.input);

            if (githubResult.interaction_required) {
              pendingConsentReturn = {
                name: block.name,
                input: block.input,
                uri: githubResult.interaction_uri!,
                msg: githubResult.message,
              };
              break;
            }

            toolResults.push({ tool: block.name, arguments: block.input, result: githubResult.result });
            toolResultBlocks.push({
              type: 'tool_result',
              tool_use_id: block.id,
              content: JSON.stringify(githubResult.result),
            });
            continue;
          }

          // MCP tool path (Todo0, GitHub MCP, ...)
          let result: any;
          try {
            result = await this.callTool(block.name, block.input);
          } catch (err: any) {
            // Feed the error back to the LLM as a tool_result so the model
            // can recover or apologize — avoids leaving an orphan tool_use.
            result = {
              isError: true,
              content: [{ type: 'text', text: `Tool "${block.name}" failed: ${err?.message || String(err)}` }],
            };
          }

          let parsedResult: any = {};
          if (result?.content?.[0]) {
            try { parsedResult = JSON.parse(result.content[0].text); }
            catch { parsedResult = result; }
          } else {
            parsedResult = result;
          }

          toolResults.push({ tool: block.name, arguments: block.input, result: parsedResult });
          toolResultBlocks.push({
            type: 'tool_result',
            tool_use_id: block.id,
            content: JSON.stringify(result),
          });
        }

        if (pendingConsentReturn) {
          // Do NOT push the assistant turn — its tool_use would be orphaned.
          // Return the interaction_required payload; frontend will replay.
          return {
            success: true,
            message: pendingConsentReturn.msg || 'GitHub authorization required.',
            data: {
              interaction_required: true,
              interaction_uri: pendingConsentReturn.uri,
              pendingToolCall: { name: pendingConsentReturn.name, input: pendingConsentReturn.input },
            },
          };
        }

        // Record this round of assistant(tool_use) + user(tool_result) and iterate.
        this.conversationHistory.push({ role: 'assistant', content: response.content });
        this.conversationHistory.push({ role: 'user', content: toolResultBlocks });

        // Capture any text the assistant emitted alongside the tool_use — the
        // LLM sometimes narrates before calling tools ("Let me search...").
        const interstitialText = response.content
          .filter((b: any) => b.type === 'text' && b.text)
          .map((b: any) => b.text)
          .join('\n');
        if (interstitialText) {
          responseMessage = responseMessage
            ? `${responseMessage}\n${interstitialText}`
            : interstitialText;
        }

        // Next round.
        response = this.anthropic
          ? await this.callAnthropicAPI(systemMessage, tools)
          : await this.callBedrockAPI(systemMessage, tools);

        if (iter === MAX_TOOL_ITERATIONS - 1) {
          // Safety cap: record the final response even if it still has tool_use.
          // We DON'T push it with tool_use to history (would corrupt future
          // turns); instead we extract any text and warn.
          const textBlocks = response.content.filter((b: any) => b.type === 'text');
          if (textBlocks.length > 0) {
            responseMessage = textBlocks.map((b: any) => b.text).join('\n');
          }
          console.warn(`⚠️  Tool-use loop hit cap (${MAX_TOOL_ITERATIONS}); stopping.`);
          // Not pushing to history — safer to truncate this turn than corrupt it.
          break;
        }
      }

      // Keep conversation history manageable
      // Keep messages in groups of 3 (user question, assistant with tools, user with tool_results + assistant final)
      // Minimum 2 messages (latest user + assistant), maximum ~12 messages
      if (this.conversationHistory.length > 12) {
        // Always keep the latest exchanges intact
        // Try to remove complete conversation turns (groups of 2-4 messages)
        const messagesToRemove = this.conversationHistory.length - 12;
        this.conversationHistory = this.conversationHistory.slice(messagesToRemove);
      }

      return {
        success: true,
        message: responseMessage || 'Task completed',
        toolResults,
      };
    } catch (error: any) {
      console.error('❌ LLM processing failed:', error.message);
      return {
        success: false,
        message: error.message || 'LLM processing failed',
      };
    }
  }

  // ============================================================================
  // GitHub Tool Execution (via OAuth STS)
  // ============================================================================

  private async handleGitHubTool(
    toolName: string,
    input: any
  ): Promise<{
    interaction_required?: boolean;
    interaction_uri?: string;
    message?: string;
    result?: any;
  }> {
    if (!this.oauthStsHandler) {
      return { result: { success: false, error: 'OAuth STS not configured' } };
    }

    // Check for cached token first, otherwise exchange
    let accessToken = this.oauthStsHandler.getCachedToken();
    if (!accessToken) {
      const stsResult = await this.oauthStsHandler.exchangeForISVToken(this.config.idToken);

      if (stsResult.status === 'interaction_required') {
        return {
          interaction_required: true,
          interaction_uri: stsResult.interaction_uri,
          message: stsResult.error_description || 'GitHub authorization required. Please authorize access, then click Retry.',
        };
      }

      if (stsResult.status === 'error') {
        return { result: { success: false, error: stsResult.error_description || stsResult.error } };
      }

      accessToken = stsResult.access_token;
    }

    // Execute the GitHub tool
    const result = await this.executeGitHubAction(toolName, input, accessToken);

    // If GitHub returned 401/403, the token may be revoked — clear cache and retry once
    if (!result.success && result.error && /\(40[13]\)/.test(result.error)) {
      console.log('⚠️  GitHub token rejected (possibly revoked). Clearing cache and re-exchanging...');
      this.oauthStsHandler.clearCachedToken();

      const stsRetry = await this.oauthStsHandler.exchangeForISVToken(this.config.idToken);
      if (stsRetry.status === 'interaction_required') {
        return {
          interaction_required: true,
          interaction_uri: stsRetry.interaction_uri,
          message: 'GitHub access was revoked. Please re-authorize access.',
        };
      }
      if (stsRetry.status === 'error') {
        return { result: { success: false, error: stsRetry.error_description || stsRetry.error } };
      }

      // Retry the GitHub call with the fresh token
      const retryResult = await this.executeGitHubAction(toolName, input, stsRetry.access_token);
      return { result: retryResult };
    }

    return { result };
  }

  private async executeGitHubAction(
    toolName: string,
    input: any,
    accessToken: string
  ): Promise<{ success: boolean; [key: string]: any }> {
    if (toolName === 'github_comment_on_pr') {
      const { owner, repo, pr_number, body } = input;
      return GitHubService.commentOnPR(accessToken, owner, repo, pr_number, body);
    }
    if (toolName === 'github_list_repos') {
      return GitHubService.listRepos(accessToken);
    }
    return { success: false, error: `Unknown GitHub tool: ${toolName}` };
  }

  // ============================================================================
  // Anthropic Direct API Call
  // ============================================================================

  private async callAnthropicAPI(systemMessage: string, tools: any[]): Promise<any> {
    if (!this.anthropic) {
      throw new Error('Anthropic client not initialized');
    }

    return await this.anthropic.messages.create({
      model: this.config.anthropicModel || 'claude-3-5-sonnet-20241022',
      max_tokens: 4096,
      system: systemMessage,
      messages: this.conversationHistory,
      tools: tools.length > 0 ? tools : undefined,
    });
  }

  // ============================================================================
  // AWS Bedrock API Call
  // ============================================================================

  private async callBedrockAPI(systemMessage: string, tools: any[]): Promise<any> {
    if (!this.bedrockClient) {
      throw new Error('Bedrock client not initialized');
    }

    // Construct Anthropic Messages API request body
    const requestBody: any = {
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: 4096,
      system: systemMessage,
      messages: this.conversationHistory,
    };

    if (tools.length > 0) {
      requestBody.tools = tools;
    }

    // Call Bedrock InvokeModel API
    const command = new InvokeModelCommand({
      modelId: this.config.bedrockModelId || 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify(requestBody),
    });

    const response = await this.bedrockClient.send(command);

    // Parse response
    const responseBody = JSON.parse(new TextDecoder().decode(response.body));
    return responseBody;
  }

  // ============================================================================
  // Conversation Management
  // ============================================================================

  resetConversation(): void {
    this.conversationHistory = [];
  }

  getConversationHistory() {
    return this.conversationHistory;
  }

  isLLMEnabled(): boolean {
    return this.anthropic !== null || this.bedrockClient !== null;
  }

  // ============================================================================
  // OAuth STS (Brokered Consent) Accessors
  // ============================================================================

  isOAuthStsConfigured(): boolean {
    return this.oauthStsHandler !== null;
  }

  getOAuthStsHandler(): OAuthStsHandler | null {
    return this.oauthStsHandler;
  }

  /**
   * Find an OAuth-STS handler by Resource Indicator. Searches both the
   * legacy OIN handler (OAUTH_STS_RESOURCE) and any oauth-sts MCP
   * connections (e.g. GitHub MCP at OAUTH_STS_RESOURCE_GITHUB_MCP).
   * Returns null if no handler owns that resource.
   */
  getOAuthStsHandlerByResource(resource: string): OAuthStsHandler | null {
    if (this.oauthStsHandler && this.config.oauthSts?.resource === resource) {
      return this.oauthStsHandler;
    }
    for (const mcp of this.mcps) {
      if (mcp.strategy.kind === 'oauth-sts' && mcp.strategy.resource === resource) {
        // OAuthStsAuthStrategy wraps OAuthStsHandler — reach the underlying handler.
        const underlying = (mcp.strategy as any).getUnderlyingHandler?.();
        if (underlying) return underlying as OAuthStsHandler;
      }
    }
    return null;
  }

  /** List every OAuth-STS resource currently registered (OIN + MCP). */
  listOAuthStsResources(): Array<{ resource: string; scope: 'oin' | 'mcp'; mcpId?: string }> {
    const out: Array<{ resource: string; scope: 'oin' | 'mcp'; mcpId?: string }> = [];
    if (this.oauthStsHandler && this.config.oauthSts?.resource) {
      out.push({ resource: this.config.oauthSts.resource, scope: 'oin' });
    }
    for (const mcp of this.mcps) {
      if (mcp.strategy.kind === 'oauth-sts') {
        out.push({ resource: mcp.strategy.resource, scope: 'mcp', mcpId: mcp.config.id });
      }
    }
    return out;
  }

  getIdToken(): string {
    return this.config.idToken;
  }
}
