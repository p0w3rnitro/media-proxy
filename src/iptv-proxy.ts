/**
 * IPTV Stream Proxy for Cloudflare Workers
 * 
 * Proxies IPTV Stalker portal streams to bypass CORS and SSL issues.
 * 
 * Routes:
 *   POST /iptv/token - Create a stream token (hides real URL)
 *   GET /iptv/stream?t=<token> - Stream using token (preferred, URL hidden)
 *   GET /iptv/stream?url=<encoded_url>&mac=<mac> - Legacy direct URL (deprecated)
 * 
 * If RPI_PROXY_URL is configured, streams are routed through the residential
 * IP proxy to bypass datacenter IP blocking by IPTV providers.
 */

import { createLogger, type LogLevel } from './logger';

export interface Env {
  LOG_LEVEL?: string;
  // KV namespace for stream tokens (URL hiding)
  STREAM_TOKENS?: KVNamespace;
  // Secret key for signing tokens
  TOKEN_SECRET?: string;
  // RPi proxy (residential IP)
  RPI_PROXY_URL?: string;
  RPI_PROXY_KEY?: string;
  // Hetzner VPS proxy (datacenter but different IP range)
  HETZNER_PROXY_URL?: string;
  HETZNER_PROXY_KEY?: string;
  // Oxylabs residential proxy (paid, reliable)
  OXYLABS_USERNAME?: string;
  OXYLABS_PASSWORD?: string;
  OXYLABS_COUNTRY?: string;
}

// Stream token data stored in KV
// NOTE: We store portal credentials + channel ID, NOT the stream URL
// This is because the portal's play_token expires quickly and is single-use
interface StreamTokenData {
  // Old format (deprecated - stream URL expires too quickly)
  url?: string;
  // New format - store credentials to fetch fresh stream URL on demand
  portal?: string;
  stalkerChannelId?: string;
  // Common fields
  mac: string;
  channelId?: string;
  channelName?: string;
  createdAt: number;
  expiresAt: number;
  // IP binding to prevent restreaming - token only works from this IP
  boundIp?: string;
}

// Token expiration time (60 seconds - stream URL must be used immediately)
// Portal play_tokens typically last 60-120 seconds, so we store the URL directly
// for faster streaming (no need to re-fetch on every stream request)
const TOKEN_TTL_SECONDS = 60;

// Generate a random token
function generateToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// STB Device Headers - Required for Stalker Portal authentication
const STB_USER_AGENT = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';

function buildStreamHeaders(macAddress: string, token?: string, referer?: string): Record<string, string> {
  const encodedMac = encodeURIComponent(macAddress);
  const headers: Record<string, string> = {
    'User-Agent': STB_USER_AGENT,
    'X-User-Agent': 'Model: MAG250; Link: WiFi',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Cookie': `mac=${encodedMac}; stb_lang=en; timezone=GMT`,
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  if (referer) {
    headers['Referer'] = referer;
  }
  
  return headers;
}

function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
  };
}

/**
 * Create a stream token - stores the real URL in KV and returns an opaque token
 * This hides the actual stream URL from the client
 */
async function handleCreateToken(
  request: Request,
  env: Env,
  logger: any,
  origin: string | null
): Promise<Response> {
  try {
    const body = await request.json() as { url: string; mac: string; channelId?: string; channelName?: string };
    
    if (!body.url || !body.mac) {
      return new Response(JSON.stringify({ error: 'Missing url or mac' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    // Check if KV is configured
    if (!env.STREAM_TOKENS) {
      // Fallback: return legacy URL format if KV not configured
      logger.warn('STREAM_TOKENS KV not configured, using legacy URL format');
      const legacyUrl = `/iptv/stream?url=${encodeURIComponent(body.url)}&mac=${encodeURIComponent(body.mac)}`;
      return new Response(JSON.stringify({ 
        success: true, 
        streamUrl: legacyUrl,
        legacy: true,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    // Generate token and store data
    const token = generateToken();
    const now = Date.now();
    const tokenData: StreamTokenData = {
      url: body.url,
      mac: body.mac,
      channelId: body.channelId,
      channelName: body.channelName,
      createdAt: now,
      expiresAt: now + (TOKEN_TTL_SECONDS * 1000),
    };

    // Store in KV with TTL
    await env.STREAM_TOKENS.put(`stream:${token}`, JSON.stringify(tokenData), {
      expirationTtl: TOKEN_TTL_SECONDS,
    });

    logger.info('Created stream token', { 
      token: token.substring(0, 8) + '...', 
      channelId: body.channelId,
      expiresIn: TOKEN_TTL_SECONDS,
    });

    // Return the token-based URL (no sensitive data exposed)
    return new Response(JSON.stringify({ 
      success: true, 
      streamUrl: `/iptv/stream?t=${token}`,
      expiresIn: TOKEN_TTL_SECONDS,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });

  } catch (error) {
    logger.error('Failed to create stream token', error as Error);
    return new Response(JSON.stringify({ error: 'Failed to create token' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
}

/**
 * Single endpoint for LiveTV channel requests
 * Does handshake + create_link + token creation all in one call
 * Returns a tokenized stream URL that hides the real IPTV URL
 */
async function handleChannelRequest(
  request: Request,
  env: Env,
  logger: any,
  origin: string | null
): Promise<Response> {
  try {
    const body = await request.json() as {
      portal: string;
      mac: string;
      stalkerChannelId: string;
      channelId?: string;
      channelName?: string;
      clientIp?: string; // Real client IP passed from Vercel/caller
    };

    if (!body.portal || !body.mac || !body.stalkerChannelId) {
      return new Response(JSON.stringify({ error: 'Missing portal, mac, or stalkerChannelId' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const { portal, mac, stalkerChannelId, channelId, channelName } = body;
    const portalBase = portal.replace(/\/c\/?$/, '').replace(/\/+$/, '');

    // Get client IP for token binding (prevents restreaming)
    // PRIORITY: Use clientIp from request body (passed by Vercel with real user IP)
    // Fallback to headers only for direct CF worker calls
    const clientIp = body.clientIp || 
                     request.headers.get('CF-Connecting-IP') || 
                     request.headers.get('X-Real-IP') ||
                     request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
                     'unknown';

    logger.info('Channel request', { 
      portal: portalBase, 
      mac: mac.substring(0, 14) + '...', 
      stalkerChannelId,
      clientIp: clientIp.substring(0, 20) + '...',
      clientIpSource: body.clientIp ? 'request-body' : 'headers',
    });

    // Step 1: Handshake to get portal token
    const handshakeUrl = `${portalBase}/portal.php?type=stb&action=handshake&token=&JsHttpRequest=1-xml`;
    const handshakeHeaders = buildStreamHeaders(mac);
    
    const handshakeRes = await fetch(handshakeUrl, { headers: handshakeHeaders });
    const handshakeText = await handshakeRes.text();
    const handshakeClean = handshakeText.replace(/^\/\*-secure-\s*/, '').replace(/\s*\*\/$/, '');
    
    let portalToken: string;
    try {
      const handshakeData = JSON.parse(handshakeClean);
      portalToken = handshakeData?.js?.token;
      if (!portalToken) throw new Error('No token in response');
    } catch (e) {
      logger.error('Handshake failed', { error: String(e), response: handshakeClean.substring(0, 200) });
      return new Response(JSON.stringify({ success: false, error: 'Handshake failed' }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    logger.info('Handshake succeeded', { token: portalToken.substring(0, 20) + '...' });

    // Step 2: Create link to get stream URL
    const cmd = `ffrt http://localhost/ch/${stalkerChannelId}`;
    const createLinkUrl = new URL(`${portalBase}/portal.php`);
    createLinkUrl.searchParams.set('type', 'itv');
    createLinkUrl.searchParams.set('action', 'create_link');
    createLinkUrl.searchParams.set('cmd', cmd);
    createLinkUrl.searchParams.set('series', '');
    createLinkUrl.searchParams.set('forced_storage', 'undefined');
    createLinkUrl.searchParams.set('disable_ad', '0');
    createLinkUrl.searchParams.set('download', '0');
    createLinkUrl.searchParams.set('JsHttpRequest', '1-xml');

    const createLinkHeaders = buildStreamHeaders(mac, portalToken);
    const createLinkRes = await fetch(createLinkUrl.toString(), { headers: createLinkHeaders });
    const createLinkText = await createLinkRes.text();
    const createLinkClean = createLinkText.replace(/^\/\*-secure-\s*/, '').replace(/\s*\*\/$/, '');

    let streamUrl: string;
    try {
      const createLinkData = JSON.parse(createLinkClean);
      streamUrl = createLinkData?.js?.cmd;
      if (!streamUrl) throw new Error('No stream URL in response');
      
      // Extract URL from ffmpeg command format
      const prefixes = ['ffmpeg ', 'ffrt ', 'ffrt2 ', 'ffrt3 ', 'ffrt4 '];
      for (const prefix of prefixes) {
        if (streamUrl.startsWith(prefix)) {
          streamUrl = streamUrl.substring(prefix.length);
          break;
        }
      }
      streamUrl = streamUrl.trim();
    } catch (e) {
      logger.error('Create link failed', { error: String(e), response: createLinkClean.substring(0, 200) });
      return new Response(JSON.stringify({ success: false, error: 'Failed to get stream URL' }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    logger.info('Got stream URL', { url: streamUrl.substring(0, 60) + '...' });

    // Step 3: Create token and store the STREAM URL directly for fast access
    // We use a short TTL (60s) since portal play_tokens expire quickly
    // This avoids re-doing handshake+create_link on every stream request!
    if (env.STREAM_TOKENS) {
      const token = generateToken();
      const now = Date.now();
      const tokenData: StreamTokenData = {
        // Store stream URL directly for instant streaming (no re-fetch needed)
        url: streamUrl,
        mac: mac,
        channelId: channelId,
        channelName: channelName,
        createdAt: now,
        expiresAt: now + (TOKEN_TTL_SECONDS * 1000),
        // Bind token to client IP to prevent restreaming
        boundIp: clientIp,
      };

      await env.STREAM_TOKENS.put(`stream:${token}`, JSON.stringify(tokenData), {
        expirationTtl: TOKEN_TTL_SECONDS,
      });

      logger.info('Created stream token (IP-bound, URL stored)', { 
        token: token.substring(0, 8) + '...',
        urlPreview: streamUrl.substring(0, 60) + '...',
        boundIp: clientIp.substring(0, 20) + '...',
        ttl: TOKEN_TTL_SECONDS,
      });

      const workerUrl = new URL(request.url);
      const fullStreamUrl = `${workerUrl.protocol}//${workerUrl.host}/iptv/stream?t=${token}`;

      return new Response(JSON.stringify({
        success: true,
        streamUrl: fullStreamUrl,
        // Debug info - remove in production
        debug: {
          boundIp: clientIp,
          clientIpSource: body.clientIp ? 'request-body' : 'headers',
          bodyClientIp: body.clientIp || null,
          cfConnectingIp: request.headers.get('CF-Connecting-IP'),
        },
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    // Fallback: base64 encode the URL (legacy, may not work due to token expiry)
    const encodedUrl = btoa(streamUrl);
    const workerUrl = new URL(request.url);
    const fallbackUrl = `${workerUrl.protocol}//${workerUrl.host}/iptv/stream?u=${encodeURIComponent(encodedUrl)}&m=${encodeURIComponent(mac)}`;

    return new Response(JSON.stringify({
      success: true,
      streamUrl: fallbackUrl,
      legacy: true,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });

  } catch (error) {
    logger.error('Channel request failed', error as Error);
    return new Response(JSON.stringify({ success: false, error: 'Channel request failed' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
}

/**
 * Fetch via Oxylabs residential proxy
 * This gives us residential IPs directly from CF worker - bypasses datacenter IP blocking!
 */
async function fetchViaOxylabs(
  url: string, 
  headers: Record<string, string>,
  env: Env, 
  logger: any
): Promise<Response> {
  if (!env.OXYLABS_USERNAME || !env.OXYLABS_PASSWORD) {
    throw new Error('Oxylabs not configured');
  }

  // Oxylabs Web Unblocker endpoint
  const oxylabsEndpoint = 'https://realtime.oxylabs.io/v1/queries';
  
  logger.info('Fetching via Oxylabs residential proxy', { url: url.substring(0, 80) });

  const payload = {
    source: 'universal',
    url: url,
    geo_location: env.OXYLABS_COUNTRY || 'United States',
    render: 'html', // Some portals need JS rendering
    // Pass through our STB headers
    context: [
      { key: 'http_method', value: 'GET' },
      { key: 'headers', value: headers },
    ],
  };

  const response = await fetch(oxylabsEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + btoa(`${env.OXYLABS_USERNAME}:${env.OXYLABS_PASSWORD}`),
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text();
    logger.error('Oxylabs request failed', { status: response.status, error: errorText.substring(0, 200) });
    throw new Error(`Oxylabs error: ${response.status}`);
  }

  const result = await response.json() as { results?: Array<{ content?: string; status_code?: number }> };
  
  if (!result.results?.[0]?.content) {
    throw new Error('Oxylabs returned empty content');
  }

  const content = result.results[0].content;
  const statusCode = result.results[0].status_code || 200;
  
  logger.info('Oxylabs succeeded', { statusCode, contentLength: content.length });

  // Return as a Response object
  return new Response(content, {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function handleIPTVRequest(request: Request, env: Env): Promise<Response> {
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);
  
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = request.headers.get('origin');

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { 
      status: 200, 
      headers: corsHeaders(origin) 
    });
  }

  // Route: POST /iptv/channel - Single endpoint: handshake + create_link + token creation
  // This is the main endpoint for LiveTV - does everything in one call
  if ((path === '/iptv/channel' || path === '/iptv/channel/') && request.method === 'POST') {
    return handleChannelRequest(request, env, logger, origin);
  }

  // Route: POST /iptv/token - Create a stream token (hides real URL from client)
  if ((path === '/iptv/token' || path === '/iptv/token/') && request.method === 'POST') {
    return handleCreateToken(request, env, logger, origin);
  }

  // Route: /iptv/api - Proxy Stalker portal API calls
  if (path === '/iptv/api' || path === '/iptv/api/') {
    return handleApiProxy(url, env, logger, origin, request);
  }

  // Route: /iptv/stream - Proxy IPTV stream (supports both token and legacy URL params)
  if (path === '/iptv/stream' || path === '/iptv/stream/') {
    return handleStreamProxy(request, url, env, logger, origin);
  }

  return new Response(JSON.stringify({
    error: 'Not found',
    routes: {
      api: '/iptv/api?url=<encoded_url>&mac=<mac>&token=<token>',
      stream: '/iptv/stream?url=<encoded_url>&mac=<mac>&token=<token>',
    },
  }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

async function handleApiProxy(url: URL, env: Env, logger: any, origin: string | null, request?: Request): Promise<Response> {
  const apiUrl = url.searchParams.get('url');
  const mac = url.searchParams.get('mac');
  const token = url.searchParams.get('token');
  // Allow forcing direct fetch even if proxies are configured
  const forceDirect = url.searchParams.get('direct') === 'true';
  // Allow client IP forwarding mode - token bound to user's IP!
  const forwardClientIp = url.searchParams.get('forward_ip') === 'true';

  if (!apiUrl) {
    return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  try {
    const decodedUrl = decodeURIComponent(apiUrl);
    logger.info('IPTV API proxy request', { url: decodedUrl.substring(0, 100), forceDirect, forwardClientIp });

    // Build STB headers
    const headers = buildStreamHeaders(mac || '', token || undefined);
    
    // Extract referer from URL
    try {
      const urlObj = new URL(decodedUrl);
      headers['Referer'] = `${urlObj.protocol}//${urlObj.host}/`;
      headers['Origin'] = `${urlObj.protocol}//${urlObj.host}`;
    } catch {}
    
    // Forward client IP if requested - this makes the portal bind the token to the USER's IP!
    // The user can then stream directly without needing a proxy!
    if (forwardClientIp && request) {
      const clientIp = request.headers.get('CF-Connecting-IP') || 
                       request.headers.get('X-Real-IP') ||
                       request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim();
      if (clientIp) {
        headers['X-Forwarded-For'] = clientIp;
        headers['X-Real-IP'] = clientIp;
        headers['CF-Connecting-IP'] = clientIp;
        logger.info('Forwarding client IP to portal', { clientIp });
      }
    }

    let response: Response;
    let usedMethod = 'direct';

    // Priority order for IPTV API calls (UPDATED - direct first!):
    // 1. Direct from CF worker (now that free tier limits are resolved)
    // 2. RPi proxy (residential IP - backup)
    // 3. Hetzner VPS proxy (datacenter IP - last resort)
    // 4. Oxylabs (residential IP - paid, expensive)

    const hasHetzner = env.HETZNER_PROXY_URL && env.HETZNER_PROXY_KEY;
    const hasRpi = env.RPI_PROXY_URL && env.RPI_PROXY_KEY;
    const hasOxylabs = env.OXYLABS_USERNAME && env.OXYLABS_PASSWORD;

    // Helper to try Hetzner proxy
    const tryHetzner = async (): Promise<Response> => {
      const hetznerParams = new URLSearchParams({ url: decodedUrl, key: env.HETZNER_PROXY_KEY! });
      if (mac) hetznerParams.set('mac', mac);
      if (token) hetznerParams.set('token', token);
      const hetznerUrl = `${env.HETZNER_PROXY_URL}/iptv/api?${hetznerParams.toString()}`;
      logger.info('Trying Hetzner proxy', { url: hetznerUrl.substring(0, 80) });
      return fetch(hetznerUrl, { signal: AbortSignal.timeout(15000) });
    };

    // Helper to try RPi proxy
    const tryRpi = async (): Promise<Response> => {
      const rpiParams = new URLSearchParams({ url: decodedUrl, key: env.RPI_PROXY_KEY! });
      if (mac) rpiParams.set('mac', mac);
      if (token) rpiParams.set('token', token);
      const rpiUrl = `${env.RPI_PROXY_URL}/iptv/api?${rpiParams.toString()}`;
      logger.info('Trying RPi proxy', { url: rpiUrl.substring(0, 80) });
      return fetch(rpiUrl, { signal: AbortSignal.timeout(15000) });
    };

    // Helper to try direct fetch
    const tryDirect = async (): Promise<Response> => {
      logger.info('Trying direct fetch from Cloudflare Worker');
      return fetch(decodedUrl, { headers, signal: AbortSignal.timeout(10000) });
    };

    // NEW STRATEGY: Try direct FIRST, then fall back to proxies if blocked
    logger.info('Attempting direct fetch first (free tier limits resolved)');
    
    try {
      response = await tryDirect();
      usedMethod = 'direct';
      
      // Check if we got blocked (403) or rate-limited (429)
      if (response.status === 403 || response.status === 429) {
        logger.warn('Direct fetch blocked/rate-limited', { status: response.status });
        throw new Error(`Direct blocked with ${response.status}`);
      }
      
      // Check for empty or error response that might indicate blocking
      const contentType = response.headers.get('content-type') || '';
      if (response.ok && contentType.includes('json')) {
        // Clone to check content without consuming
        const cloned = response.clone();
        const text = await cloned.text();
        
        // Check for portal error responses
        if (text.includes('"error"') || text.includes('"status":"ERROR"')) {
          logger.warn('Direct fetch returned error in body', { preview: text.substring(0, 100) });
          // Don't throw - some errors are legitimate (e.g., invalid channel)
        }
        
        // Recreate response with the text we already read
        response = new Response(text, {
          status: response.status,
          headers: response.headers,
        });
      }
      
      logger.info('Direct fetch succeeded', { status: response.status });
      
    } catch (directError) {
      logger.warn('Direct fetch failed', { error: String(directError) });
      
      // Fallback chain: RPi (residential) > Hetzner (datacenter) > Oxylabs (paid)
      if (!forceDirect && hasRpi) {
        try {
          logger.info('Falling back to RPi proxy (residential IP)');
          response = await tryRpi();
          usedMethod = 'rpi';
          if (!response.ok) throw new Error(`RPi returned ${response.status}`);
          logger.info('RPi proxy succeeded');
        } catch (rpiError) {
          logger.warn('RPi proxy failed', { error: String(rpiError) });
          
          if (hasHetzner) {
            try {
              logger.info('Falling back to Hetzner proxy');
              response = await tryHetzner();
              usedMethod = 'hetzner';
              if (!response.ok) throw new Error(`Hetzner returned ${response.status}`);
              logger.info('Hetzner proxy succeeded');
            } catch (hetznerError) {
              logger.warn('Hetzner proxy failed', { error: String(hetznerError) });
              
              if (hasOxylabs) {
                try {
                  response = await fetchViaOxylabs(decodedUrl, headers, env, logger);
                  usedMethod = 'oxylabs';
                } catch (oxError) {
                  // All failed - return the last error
                  throw new Error('All proxy methods failed');
                }
              } else {
                throw new Error('All proxy methods failed');
              }
            }
          } else if (hasOxylabs) {
            try {
              response = await fetchViaOxylabs(decodedUrl, headers, env, logger);
              usedMethod = 'oxylabs';
            } catch (oxError) {
              throw new Error('All proxy methods failed');
            }
          } else {
            throw new Error('Direct failed and no proxies available');
          }
        }
      } else if (!forceDirect && hasHetzner) {
        try {
          logger.info('Falling back to Hetzner proxy (no RPi configured)');
          response = await tryHetzner();
          usedMethod = 'hetzner';
          if (!response.ok) throw new Error(`Hetzner returned ${response.status}`);
        } catch (hetznerError) {
          logger.warn('Hetzner proxy failed', { error: String(hetznerError) });
          
          if (hasOxylabs) {
            try {
              response = await fetchViaOxylabs(decodedUrl, headers, env, logger);
              usedMethod = 'oxylabs';
            } catch (oxError) {
              throw new Error('All proxy methods failed');
            }
          } else {
            throw new Error('Direct and Hetzner failed');
          }
        }
      } else if (!forceDirect && hasOxylabs) {
        try {
          logger.info('Falling back to Oxylabs (no RPi/Hetzner configured)');
          response = await fetchViaOxylabs(decodedUrl, headers, env, logger);
          usedMethod = 'oxylabs';
        } catch (oxError) {
          throw new Error('Direct and Oxylabs failed');
        }
      } else {
        // No fallbacks available
        throw directError;
      }
    }

    const contentType = response.headers.get('content-type') || 'application/json';
    const text = await response.text();

    logger.info('IPTV API response', { status: response.status, length: text.length, usedMethod });

    return new Response(text, {
      status: response.status,
      headers: {
        'Content-Type': contentType,
        'X-Used-Rpi': usedMethod === 'rpi' ? 'true' : 'false',
        'X-Used-Method': usedMethod,
        'X-Hetzner-Configured': env.HETZNER_PROXY_URL ? 'true' : 'false',
        'X-Rpi-Configured': env.RPI_PROXY_URL ? 'true' : 'false',
        ...corsHeaders(origin),
      },
    });

  } catch (error) {
    logger.error('IPTV API proxy error', error as Error);
    return new Response(JSON.stringify({ 
      error: 'API proxy error', 
      details: error instanceof Error ? error.message : String(error) 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
}

/**
 * Rewrite M3U8 playlist URLs to go through the CF proxy
 * This ensures all segment requests come from the same IP that the token was bound to
 */
function rewriteM3U8ForProxy(content: string, baseUrl: string, mac: string, token: string, proxyBase: string): string {
  const baseUrlObj = new URL(baseUrl);
  const basePath = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);

  const lines = content.split('\n');
  const rewrittenLines = lines.map(line => {
    const trimmedLine = line.trim();
    
    // Handle EXT-X-KEY with URI
    if (trimmedLine.includes('URI=')) {
      const uriMatch = trimmedLine.match(/URI="([^"]+)"/);
      if (uriMatch) {
        let keyUrl = uriMatch[1];
        // Make absolute URL if relative
        if (!keyUrl.startsWith('http')) {
          if (keyUrl.startsWith('/')) {
            keyUrl = `${baseUrlObj.protocol}//${baseUrlObj.host}${keyUrl}`;
          } else {
            keyUrl = basePath + keyUrl;
          }
        }
        const params = new URLSearchParams({ url: keyUrl, mac });
        if (token) params.set('token', token);
        const proxiedKeyUrl = `${proxyBase}?${params.toString()}`;
        return trimmedLine.replace(/URI="[^"]+"/, `URI="${proxiedKeyUrl}"`);
      }
      return line;
    }
    
    // Skip empty lines and other comments
    if (!trimmedLine || trimmedLine.startsWith('#')) {
      return line;
    }
    
    // Handle segment URLs
    let segmentUrl = trimmedLine;
    
    // Make absolute URL if relative
    if (!segmentUrl.startsWith('http')) {
      if (segmentUrl.startsWith('/')) {
        segmentUrl = `${baseUrlObj.protocol}//${baseUrlObj.host}${segmentUrl}`;
      } else {
        segmentUrl = basePath + segmentUrl;
      }
    }
    
    // Proxy the segment through CF
    const params = new URLSearchParams({ url: segmentUrl, mac });
    if (token) params.set('token', token);
    return `${proxyBase}?${params.toString()}`;
  });

  return rewrittenLines.join('\n');
}

async function handleStreamProxy(request: Request, url: URL, env: Env, logger: any, origin: string | null): Promise<Response> {
  // Get client IP for token verification
  const clientIp = request.headers.get('CF-Connecting-IP') || 
                   request.headers.get('X-Real-IP') ||
                   request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
                   'unknown';

  // Check for token-based access first (preferred - hides real URL)
  const streamToken = url.searchParams.get('t');
  // Support both base64-encoded (u) and legacy plaintext (url) params
  let streamUrl = url.searchParams.get('url');
  const encodedUrl = url.searchParams.get('u');
  if (encodedUrl && !streamUrl) {
    try {
      streamUrl = atob(encodedUrl);
      logger.info('Decoded base64 URL', { decodedUrl: streamUrl.substring(0, 80) + '...' });
    } catch (e) {
      logger.warn('Failed to decode base64 URL', { error: String(e), encodedUrl: encodedUrl.substring(0, 50) });
    }
  }
  // Support both short (m) and legacy (mac) params
  let mac = url.searchParams.get('mac') || url.searchParams.get('m');
  const legacyToken = url.searchParams.get('token'); // Old auth token, not stream token
  
  logger.info('IPTV stream request', { 
    hasToken: !!streamToken, 
    hasEncodedUrl: !!encodedUrl,
    hasLegacyUrl: !!url.searchParams.get('url'),
    hasMac: !!mac,
    streamUrlPreview: streamUrl?.substring(0, 60) + '...',
  });

  // Token-based lookup (preferred method - URL is hidden from client)
  if (streamToken) {
    if (!env.STREAM_TOKENS) {
      return new Response(JSON.stringify({ error: 'Token system not configured' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    logger.info('Looking up token in KV', { token: streamToken.substring(0, 8) + '...', key: `stream:${streamToken}` });
    const tokenDataStr = await env.STREAM_TOKENS.get(`stream:${streamToken}`);
    logger.info('KV lookup result', { found: !!tokenDataStr, dataLength: tokenDataStr?.length });
    
    if (!tokenDataStr) {
      logger.warn('Invalid or expired stream token', { token: streamToken.substring(0, 8) + '...' });
      return new Response(JSON.stringify({ error: 'Invalid or expired stream token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    try {
      const tokenData = JSON.parse(tokenDataStr) as StreamTokenData;
      
      // Check expiration (belt and suspenders - KV TTL should handle this)
      if (Date.now() > tokenData.expiresAt) {
        logger.warn('Stream token expired', { token: streamToken.substring(0, 8) + '...' });
        return new Response(JSON.stringify({ error: 'Stream token expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }

      // IP binding disabled - the IPTV portal binds streams to CF's IP anyway
      // Token expiry (60s) is sufficient protection against sharing
      if (tokenData.boundIp && tokenData.boundIp !== 'unknown' && tokenData.boundIp !== clientIp) {
        logger.info('Token used from different IP (allowed)', { 
          token: streamToken.substring(0, 8) + '...',
          boundIp: tokenData.boundIp.substring(0, 20) + '...',
          requestIp: clientIp.substring(0, 20) + '...',
        });
        // Don't block - just log it
      }

      mac = tokenData.mac;
      
      // Use the pre-stored stream URL (fast path - no re-fetch needed!)
      if (tokenData.url) {
        streamUrl = tokenData.url;
        logger.info('Using stored stream URL from token (fast path)', { 
          token: streamToken.substring(0, 8) + '...', 
          url: streamUrl.substring(0, 80) + '...',
          channelName: tokenData.channelName,
        });
      } else {
        logger.error('Token data missing stream URL');
        return new Response(JSON.stringify({ error: 'Invalid token - no stream URL stored' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }
    } catch (e) {
      logger.error('Failed to parse token data', e as Error);
      return new Response(JSON.stringify({ error: 'Invalid token data' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  }

  // Require either token or legacy URL params
  if (!streamUrl) {
    return new Response(JSON.stringify({ error: 'Missing stream token or url parameter' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  try {
    // Determine if URL needs decoding:
    // - Token-based: URL is stored as-is, no decoding needed
    // - Base64 (u param): URL was base64 decoded, no further decoding needed
    // - Legacy (url param): URL is URL-encoded, needs decodeURIComponent
    const decodedUrl = streamToken ? streamUrl : (encodedUrl ? streamUrl : decodeURIComponent(streamUrl));
    logger.info('IPTV stream proxy request', { 
      url: decodedUrl.substring(0, 80) + '...', 
      viaToken: !!streamToken,
      viaBase64: !!encodedUrl,
    });

    // Extract MAC from stream URL if not provided (e.g., mac=00:1A:79:00:00:0C)
    if (!mac) {
      const macMatch = decodedUrl.match(/mac=([0-9A-Fa-f:]+)/);
      if (macMatch) {
        mac = decodeURIComponent(macMatch[1]);
        logger.info('Extracted MAC from URL', { mac: mac.substring(0, 14) + '...' });
      }
    }

    // Extract referer from stream URL
    let referer: string | undefined;
    try {
      const urlObj = new URL(decodedUrl);
      referer = `${urlObj.protocol}//${urlObj.host}/`;
    } catch {}

    // Build headers - always use STB headers for IPTV streams
    const headers = mac ? buildStreamHeaders(mac, legacyToken || undefined, referer) : {
      'User-Agent': STB_USER_AGENT,
      'X-User-Agent': 'Model: MAG250; Link: WiFi',
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Connection': 'keep-alive',
      ...(referer ? { 'Referer': referer } : {}),
    };

    let response: Response;
    let usedProxy = 'direct';

    // Helper to build proxy params
    const buildProxyParams = () => {
      const params = new URLSearchParams({ url: decodedUrl });
      if (mac) params.set('mac', mac);
      if (legacyToken) params.set('token', legacyToken);
      return params;
    };

    // NEW STRATEGY: Try direct FIRST for streams (matching API proxy behavior)
    // Priority: Direct > RPi (backup) > Hetzner (last resort)
    const fetchStartTime = Date.now();
    logger.info('STREAM FETCH START', { 
      url: decodedUrl.substring(0, 100) + '...',
      mac: mac?.substring(0, 14) + '...',
      viaToken: !!streamToken,
    });
    
    try {
      // Add timeout to prevent hanging - IPTV streams should respond quickly
      response = await fetch(decodedUrl, {
        headers,
        signal: AbortSignal.timeout(15000), // 15 second timeout
        // @ts-ignore - Cloudflare Workers support this
        cf: {
          cacheTtl: 0,
          cacheEverything: false,
        },
      });
      
      logger.info('STREAM FETCH COMPLETE', { 
        elapsed: Date.now() - fetchStartTime,
        status: response.status,
      });
      usedProxy = 'direct';
      
      // Check if blocked or token expired
      // 403 = forbidden, 429 = rate limited, 458/456 = IPTV portal token expired/invalid
      if (response.status === 403 || response.status === 429 || response.status === 458 || response.status === 456) {
        // Try to read error body for more details
        let errorBody = '';
        try {
          errorBody = await response.clone().text();
        } catch {}
        
        logger.warn('Direct stream blocked/expired', { 
          status: response.status, 
          FULL_URL: decodedUrl,
          MAC: mac,
          viaToken: !!streamToken,
          errorBody: errorBody.substring(0, 500),
          responseHeaders: Object.fromEntries(response.headers.entries()),
        });
        throw new Error(`Direct blocked/expired with ${response.status}`);
      }
      
      // Also check for non-2xx responses
      if (!response.ok) {
        logger.warn('Direct stream returned error', { 
          status: response.status,
          url: decodedUrl.substring(0, 100),
        });
        throw new Error(`Direct returned ${response.status}`);
      }
      
      logger.info('Direct stream fetch succeeded', { status: response.status });
      
    } catch (directErr) {
      logger.warn('Direct stream failed, trying fallbacks', { error: String(directErr) });
      
      // Fallback: RPi > Hetzner
      if (env.RPI_PROXY_URL && env.RPI_PROXY_KEY) {
        logger.info('Falling back to RPi proxy for stream');
        const params = buildProxyParams();
        params.set('key', env.RPI_PROXY_KEY);
        const rpiUrl = `${env.RPI_PROXY_URL}/iptv/stream?${params.toString()}`;
        
        try {
          response = await fetch(rpiUrl);
          usedProxy = 'rpi';
          if (!response.ok) throw new Error(`RPi returned ${response.status}`);
        } catch (rpiErr) {
          logger.warn('RPi stream failed', { error: String(rpiErr) });
          
          if (env.HETZNER_PROXY_URL && env.HETZNER_PROXY_KEY) {
            logger.info('Falling back to Hetzner proxy for stream');
            const hetznerParams = buildProxyParams();
            hetznerParams.set('key', env.HETZNER_PROXY_KEY);
            const hetznerUrl = `${env.HETZNER_PROXY_URL}/iptv/stream?${hetznerParams.toString()}`;
            response = await fetch(hetznerUrl);
            usedProxy = 'hetzner';
          } else {
            throw rpiErr;
          }
        }
      } else if (env.HETZNER_PROXY_URL && env.HETZNER_PROXY_KEY) {
        logger.info('Falling back to Hetzner proxy for stream (no RPi)');
        const params = buildProxyParams();
        params.set('key', env.HETZNER_PROXY_KEY);
        const hetznerUrl = `${env.HETZNER_PROXY_URL}/iptv/stream?${params.toString()}`;
        response = await fetch(hetznerUrl);
        usedProxy = 'hetzner';
      } else {
        throw directErr;
      }
    }

    if (!response.ok) {
      logger.error('Stream fetch failed', { status: response.status });
      return new Response(JSON.stringify({ 
        error: 'Stream fetch failed', 
        status: response.status 
      }), {
        status: response.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const contentType = response.headers.get('content-type') || 'video/mp2t';
    const contentLength = response.headers.get('content-length');

    // Stream the response
    const responseHeaders: Record<string, string> = {
      'Content-Type': contentType,
      ...corsHeaders(origin),
      'Cache-Control': 'no-store',
    };

    if (contentLength) {
      responseHeaders['Content-Length'] = contentLength;
    }

    logger.info('Streaming IPTV content', { contentType, contentLength });

    return new Response(response.body, {
      status: 200,
      headers: responseHeaders,
    });

  } catch (error) {
    logger.error('IPTV proxy error', error as Error);
    return new Response(JSON.stringify({ 
      error: 'Proxy error', 
      details: error instanceof Error ? error.message : String(error) 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
}
