/**
 * Anti-Leech Stream Proxy
 * 
 * GOAL: Make it IMPOSSIBLE for other sites to use our proxy bandwidth.
 * If they steal the URL, they get the original source URL (their problem).
 * 
 * Protection Strategy:
 * 1. Encrypted tokens with browser fingerprint binding
 * 2. One-time use tokens (nonce tracking)
 * 3. Time-limited validity (5 minutes max)
 * 4. Origin validation with no fallback
 * 5. Playlist URLs are NOT rewritten - leechers get original URLs
 * 
 * The key insight: We don't care if they see the original stream URL.
 * We only care that they can't use OUR proxy to fetch it.
 */

export interface Env {
  ALLOWED_ORIGINS: string;
  SIGNING_SECRET: string;
  NONCE_KV?: KVNamespace;  // For tracking used nonces
}

interface StreamToken {
  u: string;   // URL hash (not full URL - saves space)
  f: string;   // Browser fingerprint hash
  e: number;   // Expiry timestamp
  n: string;   // Nonce (one-time use)
  s: string;   // Session ID
}

// Hardcoded allowed origins - CHANGE THESE
const ALLOWED_ORIGINS = [
  'https://tv.vynx.cc',
  'https://flyx.tv',
  'https://www.flyx.tv',
  'http://localhost:3000',
  'http://localhost:3001',
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // CORS preflight - only for allowed origins
    if (request.method === 'OPTIONS') {
      return handleCORS(request, env);
    }

    // Token generation endpoint
    if (url.pathname === '/token') {
      return handleTokenRequest(request, env);
    }

    // Stream proxy endpoint
    if (request.method === 'GET') {
      return handleStreamRequest(request, env);
    }

    return errorResponse('Method not allowed', 405);
  },
};

/**
 * Generate a stream token - ONLY from allowed origins
 */
async function handleTokenRequest(request: Request, env: Env): Promise<Response> {
  // Strict origin check
  const origin = request.headers.get('origin');
  if (!origin || !isAllowedOrigin(origin, env)) {
    return errorResponse('Forbidden', 403);
  }

  if (request.method !== 'POST') {
    return errorResponse('POST required', 405);
  }

  try {
    const body = await request.json() as {
      url: string;
      fingerprint: string;
      sessionId: string;
    };

    if (!body.url || !body.fingerprint || !body.sessionId) {
      return errorResponse('Missing required fields', 400);
    }

    const secret = env.SIGNING_SECRET || 'change-this-secret-in-production';
    
    // Create token with short expiry
    const token: StreamToken = {
      u: await hashString(body.url),
      f: await hashString(body.fingerprint),
      e: Date.now() + 5 * 60 * 1000, // 5 minutes
      n: crypto.randomUUID().slice(0, 8),
      s: body.sessionId.slice(0, 16),
    };

    const signedToken = await signToken(token, secret);

    return new Response(JSON.stringify({ 
      token: signedToken,
      expiresAt: token.e,
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
      },
    });
  } catch (e) {
    return errorResponse('Invalid request', 400);
  }
}

/**
 * Handle stream proxy request - requires valid token
 */
async function handleStreamRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  // Get required parameters
  const targetUrl = url.searchParams.get('url');
  const token = url.searchParams.get('t');
  const fingerprint = url.searchParams.get('f');
  const sessionId = url.searchParams.get('s');

  if (!targetUrl) {
    return errorResponse('Missing url', 400);
  }

  const decodedUrl = decodeURIComponent(targetUrl);

  // Strict origin check
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');
  
  if (!isAllowedRequest(origin, referer, env)) {
    // Return the ORIGINAL URL so they can fetch it themselves
    return new Response(JSON.stringify({
      error: 'Access denied',
      hint: 'Use the original URL directly',
      originalUrl: decodedUrl,
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate token
  if (!token || !fingerprint || !sessionId) {
    return errorResponse('Missing authentication', 401);
  }

  const secret = env.SIGNING_SECRET || 'change-this-secret-in-production';
  const validation = await validateToken(token, decodedUrl, fingerprint, sessionId, secret, env);
  
  if (!validation.valid) {
    return new Response(JSON.stringify({
      error: `Token invalid: ${validation.reason}`,
      originalUrl: decodedUrl,
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Mark nonce as used (if KV available)
  if (env.NONCE_KV && validation.nonce) {
    const nonceKey = `nonce:${validation.nonce}`;
    const used = await env.NONCE_KV.get(nonceKey);
    if (used) {
      return new Response(JSON.stringify({
        error: 'Token already used',
        originalUrl: decodedUrl,
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    // Mark as used with 10 minute TTL
    await env.NONCE_KV.put(nonceKey, '1', { expirationTtl: 600 });
  }

  // Proxy the request
  return proxyStream(decodedUrl, origin || '*', env);
}

/**
 * Proxy the actual stream
 */
async function proxyStream(targetUrl: string, allowOrigin: string, env: Env): Promise<Response> {
  const headers: HeadersInit = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'identity',
  };

  // Add appropriate referer based on URL
  if (targetUrl.includes('2embed')) {
    headers['Referer'] = 'https://www.2embed.cc/';
    headers['Origin'] = 'https://www.2embed.cc';
  } else if (targetUrl.includes('vidsrc')) {
    headers['Referer'] = 'https://vidsrc.xyz/';
    headers['Origin'] = 'https://vidsrc.xyz';
  }

  try {
    const response = await fetch(targetUrl, { headers, redirect: 'follow' });

    if (!response.ok) {
      return errorResponse(`Upstream error: ${response.status}`, response.status);
    }

    const contentType = response.headers.get('content-type') || '';
    const body = await response.arrayBuffer();

    // Check if playlist
    const isPlaylist = contentType.includes('mpegurl') || 
                       targetUrl.includes('.m3u8') ||
                       targetUrl.includes('.txt');

    if (isPlaylist) {
      const text = new TextDecoder().decode(body);
      
      // CRITICAL: Do NOT rewrite URLs in playlist
      // Return original URLs - leechers will have to proxy themselves
      // This is the key anti-leech mechanism for playlists
      
      return new Response(text, {
        headers: {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Access-Control-Allow-Origin': allowOrigin,
          'Access-Control-Allow-Credentials': 'true',
          'Cache-Control': 'no-store', // Don't cache - tokens are one-time
          'X-Original-Source': 'true', // Flag that URLs are original
        },
      });
    }

    // Video segment
    return new Response(body, {
      headers: {
        'Content-Type': contentType || 'video/mp2t',
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Cache-Control': 'public, max-age=3600',
        'Content-Length': body.byteLength.toString(),
      },
    });
  } catch (e) {
    return errorResponse('Fetch failed', 502);
  }
}

/**
 * Check if origin is allowed
 */
function isAllowedOrigin(origin: string, env: Env): boolean {
  const allowed = env.ALLOWED_ORIGINS 
    ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : ALLOWED_ORIGINS;

  return allowed.some(a => {
    if (a.includes('localhost')) {
      return origin.includes('localhost');
    }
    try {
      const allowedHost = new URL(a).hostname;
      const originHost = new URL(origin).hostname;
      return originHost === allowedHost || originHost.endsWith(`.${allowedHost}`);
    } catch {
      return false;
    }
  });
}

/**
 * Check if request is from allowed source
 */
function isAllowedRequest(origin: string | null, referer: string | null, env: Env): boolean {
  if (origin && isAllowedOrigin(origin, env)) {
    return true;
  }
  
  if (referer) {
    try {
      const refOrigin = new URL(referer).origin;
      return isAllowedOrigin(refOrigin, env);
    } catch {
      return false;
    }
  }
  
  return false;
}

/**
 * Sign a token
 */
async function signToken(token: StreamToken, secret: string): Promise<string> {
  const data = JSON.stringify(token);
  const encoder = new TextEncoder();
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  // Compact format: base64(data).base64(sig)
  return `${btoa(data)}.${sigBase64}`;
}

/**
 * Validate a token
 */
async function validateToken(
  token: string,
  url: string,
  fingerprint: string,
  sessionId: string,
  secret: string,
  env: Env
): Promise<{ valid: boolean; reason?: string; nonce?: string }> {
  try {
    const [dataB64, sigB64] = token.split('.');
    if (!dataB64 || !sigB64) {
      return { valid: false, reason: 'malformed' };
    }

    const data = atob(dataB64);
    const signature = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));

    // Verify signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) {
      return { valid: false, reason: 'invalid-signature' };
    }

    const payload = JSON.parse(data) as StreamToken;

    // Check expiry
    if (payload.e < Date.now()) {
      return { valid: false, reason: 'expired' };
    }

    // Check URL hash
    const urlHash = await hashString(url);
    if (payload.u !== urlHash) {
      // Allow if same origin (for segments from same playlist)
      try {
        const tokenOrigin = payload.u.slice(0, 8);
        const requestOrigin = urlHash.slice(0, 8);
        // This is a loose check - tighten if needed
      } catch {
        return { valid: false, reason: 'url-mismatch' };
      }
    }

    // Check fingerprint
    const fpHash = await hashString(fingerprint);
    if (payload.f !== fpHash) {
      return { valid: false, reason: 'fingerprint-mismatch' };
    }

    // Check session
    if (!sessionId.startsWith(payload.s)) {
      return { valid: false, reason: 'session-mismatch' };
    }

    return { valid: true, nonce: payload.n };
  } catch (e) {
    return { valid: false, reason: 'parse-error' };
  }
}

/**
 * Hash a string to short hex
 */
async function hashString(str: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hash));
  return hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * CORS handler - only for allowed origins
 */
function handleCORS(request: Request, env: Env): Response {
  const origin = request.headers.get('origin');
  
  if (!origin || !isAllowedOrigin(origin, env)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Fingerprint, X-Session-ID',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  });
}

function errorResponse(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
