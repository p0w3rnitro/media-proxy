/**
 * DLHD Proxy - Cloudflare-Only Authentication
 *
 * Proxies daddyhd.com live streams through Cloudflare Workers.
 * NO RPI PROXY NEEDED - handles all auth directly!
 *
 * Authentication Flow (Dec 2024):
 *   1. Fetch player page → Get AUTH_TOKEN, CHANNEL_KEY, AUTH_COUNTRY, AUTH_TS
 *   2. Call heartbeat endpoint → Establish session
 *   3. Fetch key with session → Use Authorization + X-Channel-Key + X-Client-Token
 *
 * Key Discovery:
 *   The heartbeat and key endpoints work from CF Workers when proper headers are sent.
 *   The session is NOT IP-bound - it's token-bound via the Authorization header.
 *
 * Routes:
 *   GET /?channel=<id>           - Get proxied M3U8 playlist
 *   GET /key?url=<encoded_url>   - Proxy encryption key (handles auth)
 *   GET /segment?url=<encoded_url> - Proxy video segment
 *   GET /schedule                - Fetch live events schedule
 *   GET /health                  - Health check
 */

import { createLogger, type LogLevel } from './logger';

export interface Env {
  LOG_LEVEL?: string;
  // RPI proxy for key fetches (key server blocks CF IPs)
  RPI_PROXY_URL?: string;
  RPI_PROXY_KEY?: string;
}

// Player domain for referer
const PLAYER_DOMAIN = 'epicplayplay.cfd';
const PARENT_DOMAIN = 'daddyhd.com';

// URL path variants on daddyhd.com that embed the player
// Format: https://daddyhd.com/{path}/stream-{channel}.php
const DADDYHD_PATH_VARIANTS = ['stream', 'cast', 'watch', 'plus', 'casting', 'player'];

// Standard user agent
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// ALL known server keys - try them all before giving up
const ALL_SERVER_KEYS = ['zeko', 'wind', 'nfs', 'ddy6', 'chevy', 'top1/cdn'];

// Both CDN domains to try
const CDN_DOMAINS = ['kiko2.ru', 'giokko.ru'];

// In-memory cache for server keys (30 min TTL)
const serverKeyCache = new Map<
  string,
  { serverKey: string; fetchedAt: number }
>();
const SERVER_KEY_CACHE_TTL_MS = 30 * 60 * 1000;

// Token pool per channel - rotate between multiple tokens to handle more concurrent users
// DLHD limits ~4 concurrent channels per token, so we maintain a pool
const TOKEN_POOL_SIZE = 5; // 5 tokens × 4 channels = ~20 concurrent streams per channel
const SESSION_CACHE_TTL_MS = 4 * 60 * 1000; // 4 min TTL (shorter to refresh more often)

interface SessionData {
  token: string;
  channelKey: string;
  country: string;
  timestamp: string;
  fetchedAt: number;
  useCount: number; // Track usage to rotate
}

// Map of channel -> array of session tokens
const sessionPool = new Map<string, SessionData[]>();

// Round-robin index per channel
const sessionIndex = new Map<string, number>();

/**
 * Get a session from the pool, rotating between available tokens
 */
function getSessionFromPool(channel: string): SessionData | null {
  const pool = sessionPool.get(channel);
  if (!pool || pool.length === 0) return null;

  // Filter out expired sessions
  const now = Date.now();
  const validSessions = pool.filter(
    (s) => now - s.fetchedAt < SESSION_CACHE_TTL_MS
  );

  if (validSessions.length === 0) {
    sessionPool.delete(channel);
    return null;
  }

  // Update pool with only valid sessions
  sessionPool.set(channel, validSessions);

  // Round-robin selection
  let idx = sessionIndex.get(channel) || 0;
  idx = idx % validSessions.length;
  sessionIndex.set(channel, idx + 1);

  const session = validSessions[idx];
  session.useCount++;

  return session;
}

/**
 * Add a new session to the pool
 */
function addSessionToPool(channel: string, session: SessionData): void {
  let pool = sessionPool.get(channel);
  if (!pool) {
    pool = [];
    sessionPool.set(channel, pool);
  }

  // Remove expired sessions
  const now = Date.now();
  pool = pool.filter((s) => now - s.fetchedAt < SESSION_CACHE_TTL_MS);

  // Check if we already have this token
  const existingIdx = pool.findIndex((s) => s.token === session.token);
  if (existingIdx >= 0) {
    pool[existingIdx] = session; // Update existing
  } else if (pool.length < TOKEN_POOL_SIZE) {
    pool.push(session); // Add new
  } else {
    // Replace oldest/most used
    pool.sort((a, b) => b.useCount - a.useCount || a.fetchedAt - b.fetchedAt);
    pool[pool.length - 1] = session;
  }

  sessionPool.set(channel, pool);
}

/**
 * Generate CLIENT_TOKEN for heartbeat/key authentication
 * Format: base64(channelKey|country|timestamp|userAgent|fingerprint)
 */
function generateClientToken(
  channelKey: string,
  country: string,
  timestamp: string,
  userAgent: string
): string {
  const screen = '1920x1080';
  const tz = 'America/New_York';
  const lang = 'en-US';
  const fingerprint = `${userAgent}|${screen}|${tz}|${lang}`;
  const signData = `${channelKey}|${country}|${timestamp}|${userAgent}|${fingerprint}`;
  return btoa(signData);
}

declare function btoa(str: string): string;

/**
 * Get auth session for a channel
 * Uses token pool with rotation for better scalability
 */
async function getSession(
  channel: string,
  logger: any,
  forceNew: boolean = false
): Promise<{
  token: string;
  channelKey: string;
  country: string;
  timestamp: string;
} | null> {
  // Try to get from pool first (unless forcing new)
  if (!forceNew) {
    const pooled = getSessionFromPool(channel);
    if (pooled) {
      logger.debug('Session from pool', { channel, useCount: pooled.useCount });
      return pooled;
    }
  }

  logger.info('Fetching fresh session', { channel });

  // Try different referer paths
  const refererPaths = DADDYHD_PATH_VARIANTS.map(
    (path) => `https://${PARENT_DOMAIN}/${path}/stream-${channel}.php`
  );
  refererPaths.unshift(`https://${PARENT_DOMAIN}/watch.php?id=${channel}`);

  for (const referer of refererPaths) {
    try {
      const playerUrl = `https://${PLAYER_DOMAIN}/premiumtv/daddyhd.php?id=${channel}`;
      const response = await fetch(playerUrl, {
        headers: {
          'User-Agent': USER_AGENT,
          Referer: referer,
          Accept: 'text/html,application/xhtml+xml',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });

      if (!response.ok) {
        logger.debug('Player page fetch failed', { status: response.status, referer });
        continue;
      }

      const html = await response.text();

      // Extract auth variables (xx.html redirect is client-side, we ignore it)
      const tokenMatch = html.match(/AUTH_TOKEN\s*=\s*["']([^"']+)["']/);
      const channelKeyMatch = html.match(/CHANNEL_KEY\s*=\s*["']([^"']+)["']/);
      const countryMatch = html.match(/AUTH_COUNTRY\s*=\s*["']([^"']+)["']/);
      const tsMatch = html.match(/AUTH_TS\s*=\s*["']([^"']+)["']/);

      if (!tokenMatch) {
        logger.debug('No AUTH_TOKEN found', { referer });
        continue;
      }

      const session: SessionData = {
        token: tokenMatch[1],
        channelKey: channelKeyMatch?.[1] || `premium${channel}`,
        country: countryMatch?.[1] || 'US',
        timestamp: tsMatch?.[1] || String(Math.floor(Date.now() / 1000)),
        fetchedAt: Date.now(),
        useCount: 0,
      };

      // Add to pool
      addSessionToPool(channel, session);

      const poolSize = sessionPool.get(channel)?.length || 0;
      logger.info('Session fetched and pooled', {
        channel,
        channelKey: session.channelKey,
        poolSize,
        referer,
      });

      return session;
    } catch (error) {
      logger.debug('Session fetch error', { referer, error: (error as Error).message });
      continue;
    }
  }

  logger.warn('All referer paths failed', { channel });
  return null;
}

/**
 * Call heartbeat to establish/extend session
 */
async function callHeartbeat(
  session: { token: string; channelKey: string; country: string; timestamp: string },
  logger: any
): Promise<boolean> {
  const clientToken = generateClientToken(
    session.channelKey,
    session.country,
    session.timestamp,
    USER_AGENT
  );

  // Always use chevy for heartbeat - it's the only server with working heartbeat
  const heartbeatUrl = 'https://chevy.kiko2.ru/heartbeat';

  try {
    const response = await fetch(heartbeatUrl, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: '*/*',
        Origin: `https://${PLAYER_DOMAIN}`,
        Referer: `https://${PLAYER_DOMAIN}/`,
        Authorization: `Bearer ${session.token}`,
        'X-Channel-Key': session.channelKey,
        'X-Client-Token': clientToken,
      },
    });

    const text = await response.text();
    logger.info('Heartbeat response', {
      status: response.status,
      body: text.substring(0, 100),
    });

    // Success responses: "Session created", "Session extended"
    return (
      response.ok &&
      (text.includes('Session created') ||
        text.includes('Session extended') ||
        text.includes('"status":"ok"'))
    );
  } catch (error) {
    logger.warn('Heartbeat failed', { error: (error as Error).message });
    return false;
  }
}

/**
 * Fetch encryption key - tries direct first, falls back to RPI proxy
 * The key server (chevy.kiko2.ru) blocks Cloudflare IPs, so RPI is needed
 */
async function fetchKeyDirect(
  keyUrl: string,
  session: { token: string; channelKey: string; country: string; timestamp: string },
  logger: any,
  env?: Env
): Promise<{ data: ArrayBuffer; success: boolean; error?: string }> {
  const clientToken = generateClientToken(
    session.channelKey,
    session.country,
    session.timestamp,
    USER_AGENT
  );

  const authHeaders = {
    'User-Agent': USER_AGENT,
    Accept: '*/*',
    Origin: `https://${PLAYER_DOMAIN}`,
    Referer: `https://${PLAYER_DOMAIN}/`,
    Authorization: `Bearer ${session.token}`,
    'X-Channel-Key': session.channelKey,
    'X-Client-Token': clientToken,
  };

  // Try direct fetch first (works from residential IPs, not CF)
  try {
    const response = await fetch(keyUrl, { headers: authHeaders });
    const data = await response.arrayBuffer();
    const text = new TextDecoder().decode(data);

    // Check for errors
    if (text.includes('"E2"') || text.includes('Session must be created')) {
      return { data, success: false, error: 'E2: Session not established' };
    }
    if (text.includes('"E3"') || text.includes('Token expired')) {
      return { data, success: false, error: 'E3: Token expired' };
    }

    // Valid key is exactly 16 bytes and not JSON
    if (data.byteLength === 16 && !text.startsWith('{') && !text.startsWith('[')) {
      return { data, success: true };
    }

    // If we got HTML or weird response, key server is blocking CF IPs
    if (text.includes('fetchpoolctx') || text.includes('<!doctype') || data.byteLength > 100) {
      logger.info('Key server blocking CF IP, trying RPI proxy');
      
      // Fall back to RPI proxy if configured
      if (env?.RPI_PROXY_URL && env?.RPI_PROXY_KEY) {
        return await fetchKeyViaRpi(keyUrl, authHeaders, env, logger);
      }
      
      return {
        data,
        success: false,
        error: 'Key server blocking CF IP, RPI proxy not configured',
      };
    }

    return {
      data,
      success: false,
      error: `Invalid key: ${data.byteLength} bytes, content: ${text.substring(0, 50)}`,
    };
  } catch (error) {
    // On network error, try RPI proxy
    if (env?.RPI_PROXY_URL && env?.RPI_PROXY_KEY) {
      logger.info('Direct fetch failed, trying RPI proxy', { error: (error as Error).message });
      return await fetchKeyViaRpi(keyUrl, authHeaders, env, logger);
    }
    
    return {
      data: new ArrayBuffer(0),
      success: false,
      error: (error as Error).message,
    };
  }
}

/**
 * Fetch key via RPI residential proxy
 * Uses the /proxy endpoint which handles DLHD key auth internally
 */
async function fetchKeyViaRpi(
  keyUrl: string,
  headers: Record<string, string>,
  env: Env,
  logger: any
): Promise<{ data: ArrayBuffer; success: boolean; error?: string }> {
  try {
    let rpiBaseUrl = env.RPI_PROXY_URL!;
    if (!rpiBaseUrl.startsWith('http://') && !rpiBaseUrl.startsWith('https://')) {
      rpiBaseUrl = `https://${rpiBaseUrl}`;
    }

    // Use the /proxy endpoint - RPI handles DLHD key auth internally
    // The RPI proxy detects key URLs and fetches auth tokens automatically
    const rpiParams = new URLSearchParams({
      url: keyUrl,
      key: env.RPI_PROXY_KEY!,
    });

    const rpiUrl = `${rpiBaseUrl}/proxy?${rpiParams.toString()}`;
    logger.debug('Fetching key via RPI /proxy', { rpiUrl: rpiUrl.substring(0, 80) });

    const response = await fetch(rpiUrl, {
      signal: AbortSignal.timeout(15000),
    });

    const data = await response.arrayBuffer();
    const text = new TextDecoder().decode(data);

    logger.info('RPI proxy response', { 
      status: response.status, 
      size: data.byteLength,
      preview: text.substring(0, 100)
    });

    // Check HTTP status first - RPI returns 502 on errors
    if (!response.ok) {
      // Try to parse error message from JSON response
      try {
        const errorJson = JSON.parse(text);
        return { 
          data, 
          success: false, 
          error: `RPI error ${response.status}: ${errorJson.error || errorJson.message || text.substring(0, 100)}` 
        };
      } catch {
        return { data, success: false, error: `RPI error ${response.status}: ${text.substring(0, 100)}` };
      }
    }

    // Check for auth errors in response body
    if (text.includes('"E2"') || text.includes('"E3"')) {
      return { data, success: false, error: `Auth error via RPI: ${text}` };
    }

    // Valid key is exactly 16 bytes
    if (data.byteLength === 16 && !text.startsWith('{') && !text.startsWith('[')) {
      logger.info('Key fetched via RPI successfully');
      return { data, success: true };
    }

    return {
      data,
      success: false,
      error: `Invalid key via RPI: ${data.byteLength} bytes, content: ${text.substring(0, 50)}`,
    };
  } catch (error) {
    return {
      data: new ArrayBuffer(0),
      success: false,
      error: `RPI proxy error: ${(error as Error).message}`,
    };
  }
}

/**
 * Extract channel from key URL
 */
function extractChannelFromKeyUrl(keyUrl: string): string | null {
  const match = keyUrl.match(/premium(\d+)/);
  return match ? match[1] : null;
}

/**
 * Get server key from lookup endpoint
 */
async function getServerKey(
  channelKey: string,
  logger: any
): Promise<string> {
  const cached = serverKeyCache.get(channelKey);
  if (cached && Date.now() - cached.fetchedAt < SERVER_KEY_CACHE_TTL_MS) {
    return cached.serverKey;
  }

  const lookupUrl = `https://chevy.giokko.ru/server_lookup?channel_id=${channelKey}`;

  try {
    const response = await fetch(lookupUrl, {
      headers: {
        'User-Agent': USER_AGENT,
        Referer: `https://${PLAYER_DOMAIN}/`,
      },
    });

    if (response.ok) {
      const text = await response.text();
      if (!text.startsWith('<')) {
        const data = JSON.parse(text) as { server_key?: string };
        if (data.server_key) {
          serverKeyCache.set(channelKey, {
            serverKey: data.server_key,
            fetchedAt: Date.now(),
          });
          logger.info('Server lookup success', {
            channelKey,
            serverKey: data.server_key,
          });
          return data.server_key;
        }
      }
    }
  } catch (err) {
    logger.warn('Server lookup failed', { error: (err as Error).message });
  }

  // Fallback to zeko
  return 'zeko';
}

function constructM3U8Url(
  serverKey: string,
  channelKey: string,
  domain: string
): string {
  if (serverKey === 'top1/cdn') {
    return `https://top1.${domain}/top1/cdn/${channelKey}/mono.css`;
  }
  return `https://${serverKey}new.${domain}/${serverKey}/${channelKey}/mono.css`;
}

// ============================================================================
// REQUEST HANDLERS
// ============================================================================

export async function handleDLHDRequest(
  request: Request,
  env: Env
): Promise<Response> {
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/dlhd/, '') || '/';
  const origin = request.headers.get('origin');

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders(origin) });
  }

  if (request.method !== 'GET') {
    return jsonResponse({ error: 'Method not allowed' }, 405, origin);
  }

  try {
    if (path === '/health') {
      // Calculate pool stats
      let totalTokens = 0;
      let totalChannels = 0;
      const channelStats: Record<string, number> = {};

      for (const [ch, pool] of sessionPool.entries()) {
        const validCount = pool.filter(
          (s) => Date.now() - s.fetchedAt < SESSION_CACHE_TTL_MS
        ).length;
        if (validCount > 0) {
          totalChannels++;
          totalTokens += validCount;
          channelStats[ch] = validCount;
        }
      }

      const hasRpi = !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY);

      return jsonResponse(
        {
          status: 'healthy',
          method: hasRpi ? 'cloudflare-with-rpi-fallback' : 'cloudflare-direct',
          description: 'DLHD proxy with token pool rotation',
          rpiProxy: {
            configured: hasRpi,
            note: hasRpi
              ? 'RPI proxy available for key fetches (key server blocks CF IPs)'
              : 'RPI proxy NOT configured - key fetches may fail from CF',
          },
          tokenPool: {
            maxTokensPerChannel: TOKEN_POOL_SIZE,
            activeChannels: totalChannels,
            totalActiveTokens: totalTokens,
            estimatedCapacity: `~${totalTokens * 4} concurrent streams`,
            channels: channelStats,
          },
          timestamp: new Date().toISOString(),
        },
        200,
        origin
      );
    }

    if (path === '/key') {
      return handleKeyProxy(url, logger, origin, env);
    }

    if (path === '/segment') {
      return handleSegmentProxy(url, logger, origin);
    }

    if (path === '/schedule') {
      return handleScheduleRequest(url, logger, origin);
    }

    // Main playlist request
    const channel = url.searchParams.get('channel');
    if (!channel) {
      return jsonResponse(
        {
          error: 'Missing channel parameter',
          usage: 'GET /dlhd?channel=51',
        },
        400,
        origin
      );
    }

    return handlePlaylistRequest(channel, url.origin, logger, origin);
  } catch (error) {
    logger.error('DLHD Proxy error', error as Error);
    return jsonResponse(
      {
        error: 'Proxy error',
        message: error instanceof Error ? error.message : String(error),
      },
      500,
      origin
    );
  }
}

async function handlePlaylistRequest(
  channel: string,
  proxyOrigin: string,
  logger: any,
  origin: string | null
): Promise<Response> {
  const channelKey = `premium${channel}`;

  // Get server key
  const initialServerKey = await getServerKey(channelKey, logger);
  const serverKeysToTry = [
    initialServerKey,
    ...ALL_SERVER_KEYS.filter((k) => k !== initialServerKey),
  ];

  logger.info('Trying servers', { servers: serverKeysToTry });

  const triedCombinations: string[] = [];
  let lastError = '';

  for (const serverKey of serverKeysToTry) {
    for (const domain of CDN_DOMAINS) {
      const combo = `${serverKey}@${domain}`;
      triedCombinations.push(combo);

      try {
        const m3u8Url = constructM3U8Url(serverKey, channelKey, domain);
        logger.info('Trying M3U8', { serverKey, domain, url: m3u8Url });

        const response = await fetch(`${m3u8Url}?_t=${Date.now()}`, {
          headers: {
            'User-Agent': USER_AGENT,
            Referer: `https://${PLAYER_DOMAIN}/`,
          },
        });

        const content = await response.text();

        if (content.includes('#EXTM3U') || content.includes('#EXT-X-')) {
          // Cache this server
          serverKeyCache.set(channelKey, {
            serverKey,
            fetchedAt: Date.now(),
          });

          logger.info('Found working server', { serverKey, domain });

          // Rewrite M3U8 to proxy keys and segments
          const proxiedM3U8 = rewriteM3U8(content, proxyOrigin, m3u8Url);

          return new Response(proxiedM3U8, {
            status: 200,
            headers: {
              'Content-Type': 'application/vnd.apple.mpegurl',
              ...corsHeaders(origin),
              'Cache-Control': 'no-store, no-cache, must-revalidate',
              'X-DLHD-Channel': channel,
              'X-DLHD-Server': serverKey,
              'X-DLHD-Domain': domain,
            },
          });
        }

        lastError = `Invalid M3U8 from ${combo}`;
      } catch (err) {
        lastError = `Error from ${combo}: ${(err as Error).message}`;
      }
    }
  }

  return jsonResponse(
    {
      error: 'Failed to fetch M3U8',
      details: lastError,
      triedCombinations,
    },
    502,
    origin
  );
}

async function handleKeyProxy(
  url: URL,
  logger: any,
  origin: string | null,
  env: Env
): Promise<Response> {
  const keyUrlParam = url.searchParams.get('url');
  if (!keyUrlParam) {
    return jsonResponse({ error: 'Missing url parameter' }, 400, origin);
  }

  let keyUrl = keyUrlParam;
  try {
    keyUrl = decodeURIComponent(keyUrl);
  } catch {}

  logger.info('Key proxy request', { keyUrl: keyUrl.substring(0, 80) });

  const channel = extractChannelFromKeyUrl(keyUrl);
  if (!channel) {
    return jsonResponse({ error: 'Could not extract channel from key URL' }, 400, origin);
  }

  // DLHD key server blocks Cloudflare IPs, so we MUST use RPI proxy
  // The RPI proxy handles auth token fetching, heartbeat, and key fetching internally
  if (env?.RPI_PROXY_URL && env?.RPI_PROXY_KEY) {
    logger.info('Using RPI proxy for key fetch (CF IPs blocked by DLHD)');
    
    const result = await fetchKeyViaRpi(keyUrl, {}, env, logger);
    
    if (result.success) {
      logger.info('Key fetched via RPI successfully', { size: result.data.byteLength });
      return new Response(result.data, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': '16',
          ...corsHeaders(origin),
          'Cache-Control': 'private, max-age=30',
          'X-Fetched-By': 'rpi-proxy',
        },
      });
    }
    
    // RPI proxy failed - return error
    return jsonResponse(
      {
        error: 'Key fetch failed via RPI proxy',
        details: result.error,
        hint: 'Check RPI proxy logs for details',
      },
      502,
      origin
    );
  }

  // No RPI proxy configured - try direct fetch (will likely fail from CF IPs)
  logger.warn('RPI proxy not configured, attempting direct fetch (may fail)');
  
  // Get session from pool
  const session = await getSession(channel, logger);
  if (!session) {
    return jsonResponse({ error: 'Failed to get auth session' }, 502, origin);
  }

  // Call heartbeat (will likely fail from CF IPs)
  await callHeartbeat(session, logger);

  // Fetch key directly (will likely fail without valid session)
  const result = await fetchKeyDirect(keyUrl, session, logger, env);

  if (result.success) {
    logger.info('Key fetched successfully', { size: result.data.byteLength });
    return new Response(result.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': '16',
        ...corsHeaders(origin),
        'Cache-Control': 'private, max-age=30',
        'X-Fetched-By': 'cloudflare-direct',
      },
    });
  }

  return jsonResponse(
    {
      error: 'Key fetch failed',
      details: result.error,
      hint: 'Configure RPI_PROXY_URL and RPI_PROXY_KEY for reliable DLHD streaming',
    },
    502,
    origin
  );
}

async function handleSegmentProxy(
  url: URL,
  logger: any,
  origin: string | null
): Promise<Response> {
  const segmentUrl = url.searchParams.get('url');
  if (!segmentUrl) {
    return jsonResponse({ error: 'Missing url parameter' }, 400, origin);
  }

  const decodedUrl = decodeURIComponent(segmentUrl);

  try {
    const response = await fetch(decodedUrl, {
      headers: {
        'User-Agent': USER_AGENT,
        Referer: `https://${PLAYER_DOMAIN}/`,
      },
    });

    const data = await response.arrayBuffer();

    return new Response(data, {
      status: 200,
      headers: {
        'Content-Type': 'video/mp2t',
        ...corsHeaders(origin),
        'Cache-Control': 'public, max-age=300',
        'Content-Length': data.byteLength.toString(),
      },
    });
  } catch (error) {
    logger.error('Segment fetch failed', error as Error);
    return jsonResponse({ error: 'Segment fetch failed' }, 502, origin);
  }
}

async function handleScheduleRequest(
  url: URL,
  logger: any,
  origin: string | null
): Promise<Response> {
  const source = url.searchParams.get('source');

  try {
    const dlhdUrl = source
      ? `https://${PARENT_DOMAIN}/schedule-api.php?source=${source}`
      : `https://${PARENT_DOMAIN}/`;

    const response = await fetch(dlhdUrl, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/json',
        Referer: `https://${PARENT_DOMAIN}/`,
      },
    });

    const content = await response.text();

    // If JSON response, extract HTML
    if (source) {
      try {
        const json = JSON.parse(content);
        if (json.success && json.html) {
          return new Response(json.html, {
            status: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              ...corsHeaders(origin),
              'Cache-Control': 'public, max-age=60',
            },
          });
        }
      } catch {}
    }

    return new Response(content, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        ...corsHeaders(origin),
        'Cache-Control': 'public, max-age=60',
      },
    });
  } catch (error) {
    logger.error('Schedule fetch failed', error as Error);
    return jsonResponse({ error: 'Schedule fetch failed' }, 502, origin);
  }
}

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Rewrite M3U8 to proxy keys and segments through our worker
 */
function rewriteM3U8(
  content: string,
  proxyOrigin: string,
  m3u8BaseUrl: string
): string {
  let modified = content;

  // Rewrite ALL key URLs to use chevy.kiko2.ru and proxy through us
  modified = modified.replace(/URI="([^"]+)"/g, (_, originalKeyUrl) => {
    let absoluteKeyUrl = originalKeyUrl;

    // Resolve relative URLs
    if (!absoluteKeyUrl.startsWith('http')) {
      try {
        const base = new URL(m3u8BaseUrl);
        absoluteKeyUrl = new URL(
          absoluteKeyUrl,
          base.origin + base.pathname.replace(/\/[^/]*$/, '/')
        ).toString();
      } catch {
        const baseWithoutFile = m3u8BaseUrl.replace(/\/[^/]*$/, '/');
        absoluteKeyUrl = baseWithoutFile + absoluteKeyUrl;
      }
    }

    // Rewrite to use chevy.kiko2.ru (only server with working heartbeat)
    const keyPathMatch = absoluteKeyUrl.match(/\/key\/premium\d+\/\d+/);
    if (keyPathMatch) {
      absoluteKeyUrl = `https://chevy.kiko2.ru${keyPathMatch[0]}`;
    }

    return `URI="${proxyOrigin}/dlhd/key?url=${encodeURIComponent(absoluteKeyUrl)}"`;
  });

  // Remove ENDLIST for live streams
  modified = modified.replace(/\n?#EXT-X-ENDLIST\s*$/m, '');

  // Proxy segment URLs
  const lines = modified.split('\n');
  const processedLines = lines.map((line) => {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) return line;
    if (trimmed.includes('/dlhd/segment?')) return line;

    const isAbsoluteUrl =
      trimmed.startsWith('http://') || trimmed.startsWith('https://');
    const isDlhdSegment =
      trimmed.includes('.giokko.ru/') || trimmed.includes('.kiko2.ru/');

    if (isAbsoluteUrl && isDlhdSegment && !trimmed.includes('mono.css')) {
      return `${proxyOrigin}/dlhd/segment?url=${encodeURIComponent(trimmed)}`;
    }

    return line;
  });

  return processedLines.join('\n');
}

function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
  };
}

function jsonResponse(
  data: object,
  status: number,
  origin?: string | null
): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

export default {
  fetch: handleDLHDRequest,
};
