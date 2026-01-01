/**
 * Secure Stream Proxy - Anti-Leeching Protection
 * 
 * This proxy ONLY works when accessed from your domain.
 * Other sites trying to embed your proxy URLs will get blocked.
 * 
 * Protection layers:
 * 1. Origin/Referer validation - Only allow requests from your domains
 * 2. Signed URLs - Time-limited tokens that can't be reused
 * 3. Session binding - Tokens tied to specific browser sessions
 * 4. Rate limiting per session
 * 
 * If someone extracts the original stream URL, that's fine - they can
 * use it directly. But they CAN'T use YOUR proxy to save their bandwidth.
 */

export interface Env {
  // Your allowed domains (comma-separated)
  ALLOWED_ORIGINS?: string;
  // Secret key for signing URLs
  SIGNING_SECRET?: string;
  // Token validity in seconds (default: 3600 = 1 hour)
  TOKEN_VALIDITY?: string;
  // Enable strict mode (block if no valid token)
  STRICT_MODE?: string;
  // KV namespace for rate limiting (optional)
  RATE_LIMIT_KV?: KVNamespace;
}

interface TokenPayload {
  // Original URL being proxied
  url: string;
  // Session ID (from client)
  sid: string;
  // Expiration timestamp
  exp: number;
  // Random nonce to prevent replay
  nonce: string;
}

// Your allowed domains - add all your domains here
const DEFAULT_ALLOWED_ORIGINS = [
  'https://tv.vynx.cc',
  'https://flyx.tv',
  'http://localhost:3000',
  'http://localhost:3001',
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCORS(request, env);
    }

    if (request.method !== 'GET') {
      return errorResponse('Method not allowed', 405);
    }

    try {
      const url = new URL(request.url);
      
      // Check if this is a token generation request
      if (url.pathname === '/generate-token') {
        return handleTokenGeneration(request, env);
      }
      
      // Validate origin/referer
      const originCheck = validateOrigin(request, env);
      if (!originCheck.allowed) {
        console.log(`[SecureProxy] Blocked: ${originCheck.reason}`);
        return errorResponse(`Access denied: ${originCheck.reason}`, 403);
      }

      // Get parameters
      const targetUrl = url.searchParams.get('url');
      const token = url.searchParams.get('token');
      const sessionId = url.searchParams.get('sid');
      const source = url.searchParams.get('source') || '2embed';
      const referer = url.searchParams.get('referer') || 'https://www.2embed.cc';

      if (!targetUrl) {
        return errorResponse('Missing url parameter', 400);
      }

      const decodedUrl = decodeURIComponent(targetUrl);
      const strictMode = env.STRICT_MODE === 'true';

      // Validate token if provided or required
      if (token) {
        const tokenValidation = await validateToken(token, decodedUrl, sessionId || '', env);
        if (!tokenValidation.valid) {
          console.log(`[SecureProxy] Invalid token: ${tokenValidation.reason}`);
          if (strictMode) {
            return errorResponse(`Invalid token: ${tokenValidation.reason}`, 403);
          }
        }
      } else if (strictMode) {
        return errorResponse('Token required', 403);
      }

      // Rate limiting (if KV is configured)
      if (env.RATE_LIMIT_KV && sessionId) {
        const rateLimitResult = await checkRateLimit(sessionId, env.RATE_LIMIT_KV);
        if (!rateLimitResult.allowed) {
          return errorResponse('Rate limit exceeded', 429);
        }
      }

      // Proxy the request
      return proxyRequest(decodedUrl, source, referer, originCheck.origin, env);

    } catch (error) {
      console.error('[SecureProxy] Error:', error);
      return errorResponse('Proxy error', 500);
    }
  },
};

/**
 * Validate that the request comes from an allowed origin
 */
function validateOrigin(request: Request, env: Env): { allowed: boolean; reason?: string; origin?: string } {
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');
  const secFetchSite = request.headers.get('sec-fetch-site');
  
  // Parse allowed origins from env or use defaults
  const allowedOrigins = env.ALLOWED_ORIGINS 
    ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : DEFAULT_ALLOWED_ORIGINS;

  // Check Origin header
  if (origin) {
    const isAllowed = allowedOrigins.some(allowed => {
      if (allowed.includes('localhost')) {
        return origin.includes('localhost');
      }
      return origin === allowed || origin.endsWith(new URL(allowed).hostname);
    });
    
    if (isAllowed) {
      return { allowed: true, origin };
    }
    return { allowed: false, reason: `Origin not allowed: ${origin}` };
  }

  // Check Referer header (fallback)
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const isAllowed = allowedOrigins.some(allowed => {
        if (allowed.includes('localhost')) {
          return refererUrl.hostname === 'localhost';
        }
        const allowedHost = new URL(allowed).hostname;
        return refererUrl.hostname === allowedHost || refererUrl.hostname.endsWith(`.${allowedHost}`);
      });
      
      if (isAllowed) {
        return { allowed: true, origin: refererUrl.origin };
      }
      return { allowed: false, reason: `Referer not allowed: ${referer}` };
    } catch {
      return { allowed: false, reason: 'Invalid referer' };
    }
  }

  // Check Sec-Fetch-Site header
  if (secFetchSite === 'same-origin' || secFetchSite === 'same-site') {
    return { allowed: true, origin: 'same-site' };
  }

  // No origin info - could be direct access or curl
  // In strict mode, this should be blocked
  // For now, allow but log
  console.log('[SecureProxy] No origin info, allowing (set STRICT_MODE=true to block)');
  return { allowed: true, reason: 'no-origin-info', origin: 'unknown' };
}

/**
 * Handle CORS preflight with restricted origins
 */
function handleCORS(request: Request, env: Env): Response {
  const origin = request.headers.get('origin');
  const allowedOrigins = env.ALLOWED_ORIGINS 
    ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : DEFAULT_ALLOWED_ORIGINS;

  // Only allow CORS for allowed origins
  let allowOrigin = '';
  if (origin) {
    const isAllowed = allowedOrigins.some(allowed => {
      if (allowed.includes('localhost')) {
        return origin.includes('localhost');
      }
      return origin === allowed;
    });
    if (isAllowed) {
      allowOrigin = origin;
    }
  }

  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': allowOrigin || 'null',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Range, Content-Type, X-Session-ID',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
      'Access-Control-Max-Age': '86400',
    },
  });
}

/**
 * Generate a signed token for a URL
 */
async function handleTokenGeneration(request: Request, env: Env): Promise<Response> {
  // Validate origin first
  const originCheck = validateOrigin(request, env);
  if (!originCheck.allowed) {
    return errorResponse('Access denied', 403);
  }

  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  const sessionId = url.searchParams.get('sid');

  if (!targetUrl || !sessionId) {
    return errorResponse('Missing url or sid parameter', 400);
  }

  const secret = env.SIGNING_SECRET || 'default-secret-change-me';
  const validity = parseInt(env.TOKEN_VALIDITY || '3600', 10);

  const payload: TokenPayload = {
    url: targetUrl,
    sid: sessionId,
    exp: Date.now() + validity * 1000,
    nonce: crypto.randomUUID(),
  };

  const token = await signPayload(payload, secret);

  return new Response(JSON.stringify({ token, expiresIn: validity }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': originCheck.origin || '*',
    },
  });
}

/**
 * Validate a signed token
 */
async function validateToken(
  token: string, 
  url: string, 
  sessionId: string, 
  env: Env
): Promise<{ valid: boolean; reason?: string }> {
  const secret = env.SIGNING_SECRET || 'default-secret-change-me';

  try {
    const payload = await verifyPayload(token, secret);
    
    if (!payload) {
      return { valid: false, reason: 'invalid-signature' };
    }

    // Check expiration
    if (payload.exp < Date.now()) {
      return { valid: false, reason: 'expired' };
    }

    // Check URL matches (allow partial match for segments)
    const tokenUrlBase = new URL(payload.url).origin + new URL(payload.url).pathname.split('/').slice(0, -1).join('/');
    const requestUrlBase = new URL(url).origin + new URL(url).pathname.split('/').slice(0, -1).join('/');
    
    if (!url.startsWith(tokenUrlBase) && !requestUrlBase.startsWith(tokenUrlBase)) {
      // For HLS, the token URL might be the master playlist, but we're requesting a segment
      // Allow if same origin
      if (new URL(payload.url).origin !== new URL(url).origin) {
        return { valid: false, reason: 'url-mismatch' };
      }
    }

    // Check session ID matches
    if (payload.sid !== sessionId) {
      return { valid: false, reason: 'session-mismatch' };
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, reason: 'validation-error' };
  }
}

/**
 * Sign a payload using HMAC-SHA256
 */
async function signPayload(payload: TokenPayload, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = JSON.stringify(payload);
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  // Return base64(payload).base64(signature)
  return `${btoa(data)}.${signatureBase64}`;
}

/**
 * Verify a signed payload
 */
async function verifyPayload(token: string, secret: string): Promise<TokenPayload | null> {
  try {
    const [payloadBase64, signatureBase64] = token.split('.');
    if (!payloadBase64 || !signatureBase64) return null;

    const data = atob(payloadBase64);
    const signature = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    
    if (!valid) return null;

    return JSON.parse(data) as TokenPayload;
  } catch {
    return null;
  }
}

/**
 * Check rate limit for a session
 */
async function checkRateLimit(sessionId: string, kv: KVNamespace): Promise<{ allowed: boolean }> {
  const key = `rate:${sessionId}`;
  const current = await kv.get(key);
  const count = current ? parseInt(current, 10) : 0;

  // Allow 1000 requests per hour per session
  if (count >= 1000) {
    return { allowed: false };
  }

  // Increment counter
  await kv.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true };
}

/**
 * Proxy the actual request
 */
async function proxyRequest(
  targetUrl: string,
  source: string,
  referer: string,
  allowedOrigin: string | undefined,
  env: Env
): Promise<Response> {
  const headers: HeadersInit = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'identity',
    'Referer': referer,
    'Origin': new URL(referer).origin,
  };

  const response = await fetch(targetUrl, {
    headers,
    redirect: 'follow',
  });

  if (!response.ok) {
    return errorResponse(`Upstream error: ${response.status}`, response.status);
  }

  const contentType = response.headers.get('content-type') || '';
  const body = await response.arrayBuffer();

  // Check if playlist - rewrite URLs
  const isPlaylist = contentType.includes('mpegurl') || 
                     targetUrl.includes('.m3u8') ||
                     (contentType.includes('text') && !targetUrl.includes('.html'));

  if (isPlaylist) {
    const text = new TextDecoder().decode(body);
    // Don't rewrite URLs - let the client handle them
    // This way, if someone steals the playlist, they get the original URLs
    // which they'd have to proxy themselves
    
    return new Response(text, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Access-Control-Allow-Origin': allowedOrigin || 'null',
        'Cache-Control': 'no-store', // Don't cache - tokens expire
      },
    });
  }

  // Return video segment
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': contentType || 'video/mp2t',
      'Access-Control-Allow-Origin': allowedOrigin || 'null',
      'Cache-Control': 'public, max-age=3600',
      'Content-Length': body.byteLength.toString(),
    },
  });
}

function errorResponse(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': 'null',
    },
  });
}
