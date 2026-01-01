/**
 * AnimeKai Stream Proxy
 * 
 * Routes AnimeKai HLS streams through the RPI residential proxy.
 * MegaUp CDN (used by AnimeKai) blocks datacenter IPs, so we need
 * to proxy through a residential IP.
 * 
 * Flow:
 *   Client -> Cloudflare Worker -> RPI Proxy -> CDN
 * 
 * Routes:
 *   GET /animekai?url=<encoded_url> - Proxy HLS stream/segment
 *   GET /animekai/health - Health check
 */

import { createLogger, type LogLevel } from './logger';

export interface Env {
  LOG_LEVEL?: string;
  RPI_PROXY_URL?: string;
  RPI_PROXY_KEY?: string;
  // Hetzner VPS proxy - alternative (but blocked by datacenter IP detection)
  HETZNER_PROXY_URL?: string;
  HETZNER_PROXY_KEY?: string;
}

// CORS headers
function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
  };
}

function jsonResponse(data: object, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}

// Allowed origins for anti-leech protection
const ALLOWED_ORIGINS = [
  'https://tv.vynx.cc',
  'https://flyx.tv',
  'https://www.flyx.tv',
  'http://localhost:3000',
  'http://localhost:3001',
  '.vercel.app',
];

function isAllowedOrigin(origin: string | null, referer: string | null): boolean {
  if (!origin && !referer) return true;

  const checkOrigin = (o: string): boolean => {
    return ALLOWED_ORIGINS.some(allowed => {
      if (allowed.includes('localhost')) return o.includes('localhost');
      if (allowed.startsWith('.')) {
        try {
          const originHost = new URL(o).hostname;
          return originHost.endsWith(allowed);
        } catch { return false; }
      }
      try {
        const allowedHost = new URL(allowed).hostname;
        const originHost = new URL(o).hostname;
        return originHost === allowedHost || originHost.endsWith(`.${allowedHost}`);
      } catch { return false; }
    });
  };

  if (origin && checkOrigin(origin)) return true;
  if (referer) {
    try {
      return checkOrigin(new URL(referer).origin);
    } catch { return false; }
  }
  return false;
}

/**
 * Rewrite playlist URLs to route through this proxy
 */
function rewritePlaylistUrls(playlist: string, baseUrl: string, proxyOrigin: string): string {
  const lines = playlist.split('\n');
  const rewritten: string[] = [];
  
  const base = new URL(baseUrl);
  const basePath = base.pathname.substring(0, base.pathname.lastIndexOf('/') + 1);
  
  const proxyUrl = (url: string): string => {
    let absoluteUrl: string;
    
    if (url.startsWith('http://') || url.startsWith('https://')) {
      absoluteUrl = url;
    } else if (url.startsWith('/')) {
      absoluteUrl = `${base.origin}${url}`;
    } else {
      absoluteUrl = `${base.origin}${basePath}${url}`;
    }
    
    return `${proxyOrigin}/animekai?url=${encodeURIComponent(absoluteUrl)}`;
  };
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    
    // Handle HLS tags with URIs
    if (line.startsWith('#EXT-X-MEDIA:') || line.startsWith('#EXT-X-I-FRAME-STREAM-INF:')) {
      const uriMatch = line.match(/URI="([^"]+)"/);
      if (uriMatch) {
        const originalUri = uriMatch[1];
        const proxiedUri = proxyUrl(originalUri);
        rewritten.push(line.replace(`URI="${originalUri}"`, `URI="${proxiedUri}"`));
      } else {
        rewritten.push(line);
      }
      continue;
    }
    
    // Keep comments and empty lines
    if (line.startsWith('#') || trimmedLine === '') {
      rewritten.push(line);
      continue;
    }
    
    try {
      rewritten.push(proxyUrl(trimmedLine));
    } catch {
      rewritten.push(line);
    }
  }

  return rewritten.join('\n');
}

export async function handleAnimeKaiRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // Health check
  if (path === '/animekai/health' || path.endsWith('/health')) {
    const hasRpi = !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY);
    return jsonResponse({
      status: 'ok',
      rpiProxy: {
        configured: hasRpi,
        url: env.RPI_PROXY_URL ? env.RPI_PROXY_URL.substring(0, 30) + '...' : 'not set',
      },
      timestamp: new Date().toISOString(),
    }, 200);
  }

  // FULL EXTRACTION endpoint - routes to RPI which does ALL the work
  // Input: encrypted embed response from AnimeKai /ajax/links/view
  // Output: { success: true, streamUrl: "https://...", skip: {...} }
  if (path === '/animekai/extract') {
    const encryptedEmbed = url.searchParams.get('embed');
    
    if (!encryptedEmbed) {
      return jsonResponse({ 
        error: 'Missing embed parameter',
        usage: '/animekai/extract?embed=<encrypted_embed_response>'
      }, 400);
    }
    
    const hasRpi = !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY);
    
    if (!hasRpi) {
      logger.error('RPI proxy not configured for /animekai/extract');
      return jsonResponse({
        error: 'RPI proxy not configured',
        message: 'Set RPI_PROXY_URL and RPI_PROXY_KEY environment variables',
      }, 503);
    }
    
    logger.info('AnimeKai full extraction request', { embedLength: encryptedEmbed.length });
    
    // Forward to RPI proxy which does ALL the work
    try {
      let rpiBaseUrl = env.RPI_PROXY_URL!;
      if (!rpiBaseUrl.startsWith('http://') && !rpiBaseUrl.startsWith('https://')) {
        rpiBaseUrl = `https://${rpiBaseUrl}`;
      }
      
      const rpiUrl = `${rpiBaseUrl}/animekai/extract?key=${env.RPI_PROXY_KEY}&embed=${encodeURIComponent(encryptedEmbed)}`;
      logger.debug('Forwarding to RPI extract endpoint', { rpiUrl: rpiUrl.substring(0, 80) });
      
      const rpiResponse = await fetch(rpiUrl, {
        signal: AbortSignal.timeout(30000),
      });
      
      const responseData = await rpiResponse.json() as { success?: boolean; streamUrl?: string; error?: string };
      
      logger.info('RPI extraction response', { 
        status: rpiResponse.status, 
        success: responseData.success,
        hasStreamUrl: !!responseData.streamUrl,
      });
      
      return jsonResponse(responseData as object, rpiResponse.status);
      
    } catch (error) {
      logger.error('RPI extraction error', error as Error);
      return jsonResponse({
        error: 'Extraction failed',
        details: error instanceof Error ? error.message : String(error),
      }, 502);
    }
  }

  // FULL EXTRACTION V2 - RPI does EVERYTHING from kai_id + episode
  // Input: kai_id (anime ID) and episode number
  // Output: { success: true, streamUrl: "https://...", skip: {...} }
  if (path === '/animekai/full-extract') {
    const kaiId = url.searchParams.get('kai_id');
    const episode = url.searchParams.get('episode');
    
    if (!kaiId || !episode) {
      return jsonResponse({ 
        error: 'Missing parameters',
        usage: '/animekai/full-extract?kai_id=<anime_id>&episode=<episode_number>'
      }, 400);
    }
    
    const hasRpi = !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY);
    
    if (!hasRpi) {
      logger.error('RPI proxy not configured for /animekai/full-extract');
      return jsonResponse({
        error: 'RPI proxy not configured',
        message: 'Set RPI_PROXY_URL and RPI_PROXY_KEY environment variables',
      }, 503);
    }
    
    logger.info('AnimeKai full extraction V2 request', { kaiId, episode });
    
    // Forward to RPI proxy which does ALL the work
    try {
      let rpiBaseUrl = env.RPI_PROXY_URL!;
      if (!rpiBaseUrl.startsWith('http://') && !rpiBaseUrl.startsWith('https://')) {
        rpiBaseUrl = `https://${rpiBaseUrl}`;
      }
      
      const rpiUrl = `${rpiBaseUrl}/animekai/full-extract?key=${env.RPI_PROXY_KEY}&kai_id=${encodeURIComponent(kaiId)}&episode=${encodeURIComponent(episode)}`;
      logger.debug('Forwarding to RPI full-extract endpoint', { rpiUrl: rpiUrl.substring(0, 80) });
      
      const rpiResponse = await fetch(rpiUrl, {
        signal: AbortSignal.timeout(45000), // Longer timeout for full extraction
      });
      
      const responseData = await rpiResponse.json() as { success?: boolean; streamUrl?: string; error?: string };
      
      logger.info('RPI full extraction response', { 
        status: rpiResponse.status, 
        success: responseData.success,
        hasStreamUrl: !!responseData.streamUrl,
      });
      
      return jsonResponse(responseData as object, rpiResponse.status);
      
    } catch (error) {
      logger.error('RPI full extraction error', error as Error);
      return jsonResponse({
        error: 'Full extraction failed',
        details: error instanceof Error ? error.message : String(error),
      }, 502);
    }
  }

  // Anti-leech check
  if (!isAllowedOrigin(origin, referer)) {
    logger.warn('Blocked unauthorized request', { origin, referer });
    return jsonResponse({
      error: 'Access denied',
      message: 'This proxy only serves authorized domains',
    }, 403);
  }

  // Get target URL
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    return jsonResponse({ error: 'Missing url parameter' }, 400);
  }

  const decodedUrl = decodeURIComponent(targetUrl);
  const customUserAgent = url.searchParams.get('ua');
  const customReferer = url.searchParams.get('referer');
  
  const hasRpi = !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY);
  
  logger.info('AnimeKai proxy request', { 
    url: decodedUrl.substring(0, 100), 
    ua: customUserAgent ? 'custom' : 'default', 
    referer: customReferer ? 'custom' : 'auto',
  });

  // STRATEGY 1: Try CF direct fetch first (fastest)
  logger.debug('Trying CF direct fetch...');
  const directResult = await fetchDirectFromCF(decodedUrl, customUserAgent, customReferer);
  
  if (directResult.success) {
    logger.info('CF direct fetch succeeded!');
    return handleSuccessResponse(directResult, decodedUrl, url.origin, 'cf-direct');
  }
  
  logger.debug('CF direct failed', { status: directResult.status });

  // STRATEGY 2: Try RPI residential proxy
  if (hasRpi) {
    logger.debug('Trying RPI residential proxy...');
    return await fetchViaRpiProxy(decodedUrl, customUserAgent, customReferer, env, logger, url.origin);
  }

  // No proxies available
  logger.error('All proxy strategies failed');
  return jsonResponse({
    error: 'Proxy failed',
    message: 'CF direct failed and RPI not configured',
    cfDirectStatus: directResult.status,
  }, 502);
}


/**
 * Try direct fetch from CF Worker (fastest path)
 */
async function fetchDirectFromCF(
  url: string,
  customUserAgent: string | null,
  customReferer: string | null
): Promise<{ success: boolean; status?: number; body?: ArrayBuffer; contentType?: string; error?: string }> {
  try {
    const headers: Record<string, string> = {
      'User-Agent': customUserAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': '*/*',
      'Accept-Encoding': 'identity',
    };
    
    // Add referer if provided or auto-detect
    // IMPORTANT: MegaUp CDN blocks requests with Referer header, so don't add it for megaup domains
    const isMegaUpDomain = url.includes('megaup') || url.includes('hub26link') || url.includes('app28base');
    
    if (isMegaUpDomain) {
      // MegaUp CDN - do NOT send Referer header (they block it)
      // Only send User-Agent
    } else if (customReferer) {
      headers['Referer'] = customReferer;
    } else if (url.includes('workers.dev')) {
      headers['Referer'] = 'https://111movies.com/';
    } else if (url.match(/\.[a-z0-9]+\.site/)) {
      headers['Referer'] = 'https://animekai.to/';
    }
    
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    
    if (!response.ok) {
      return { success: false, status: response.status, error: `HTTP ${response.status}` };
    }
    
    const body = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || '';
    
    return { success: true, status: response.status, body, contentType };
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Handle successful response - rewrite playlists and return
 */
function handleSuccessResponse(
  result: { body?: ArrayBuffer; contentType?: string },
  originalUrl: string,
  proxyOrigin: string,
  via: string
): Response {
  const body = result.body!;
  const contentType = result.contentType || '';
  
  // Check if it's a playlist that needs URL rewriting
  if (contentType.includes('mpegurl') || originalUrl.includes('.m3u8')) {
    const text = new TextDecoder().decode(body);
    const rewritten = rewritePlaylistUrls(text, originalUrl, proxyOrigin);
    
    return new Response(rewritten, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Cache-Control': 'public, max-age=5',
        'X-Proxied-Via': via,
        ...corsHeaders(),
      },
    });
  }
  
  // For segments, detect content type
  const firstBytes = new Uint8Array(body.slice(0, 4));
  const isMpegTs = firstBytes[0] === 0x47;
  const isFmp4 = firstBytes[0] === 0x00 && firstBytes[1] === 0x00 && firstBytes[2] === 0x00;
  
  let actualContentType = contentType;
  if (isMpegTs) actualContentType = 'video/mp2t';
  else if (isFmp4) actualContentType = 'video/mp4';
  else if (!actualContentType) actualContentType = 'application/octet-stream';
  
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': actualContentType,
      'Content-Length': body.byteLength.toString(),
      'Cache-Control': 'public, max-age=3600',
      'X-Proxied-Via': via,
      ...corsHeaders(),
    },
  });
}

/**
 * Fetch via RPI residential proxy
 */
async function fetchViaRpiProxy(
  decodedUrl: string,
  customUserAgent: string | null,
  customReferer: string | null,
  env: Env,
  logger: ReturnType<typeof createLogger>,
  proxyOrigin: string
): Promise<Response> {
  try {
    let rpiBaseUrl = env.RPI_PROXY_URL!;
    if (!rpiBaseUrl.startsWith('http://') && !rpiBaseUrl.startsWith('https://')) {
      rpiBaseUrl = `https://${rpiBaseUrl}`;
    }

    const rpiParams = new URLSearchParams({
      url: decodedUrl,
      key: env.RPI_PROXY_KEY!,
    });
    
    if (customUserAgent) {
      rpiParams.set('ua', customUserAgent);
    }
    
    // Auto-detect referer
    if (customReferer) {
      rpiParams.set('referer', customReferer);
    } else if (decodedUrl.match(/p\.\d+\.workers\.dev/)) {
      rpiParams.set('referer', 'https://flixer.sh/');
    } else if (decodedUrl.match(/\.[a-z0-9]+\.site/)) {
      rpiParams.set('referer', 'https://animekai.to/');
    }
    
    const rpiUrl = `${rpiBaseUrl}/animekai?${rpiParams.toString()}`;
    logger.debug('Forwarding to RPI proxy', { rpiUrl: rpiUrl.substring(0, 80) });

    const rpiResponse = await fetch(rpiUrl, {
      signal: AbortSignal.timeout(30000),
    });

    if (!rpiResponse.ok) {
      logger.error('RPI proxy error', { status: rpiResponse.status });
      
      let errorDetails = '';
      try {
        const errorBody = await rpiResponse.text();
        errorDetails = errorBody.substring(0, 200);
      } catch {}
      
      return jsonResponse({
        error: `RPI proxy returned ${rpiResponse.status}`,
        details: errorDetails,
      }, rpiResponse.status);
    }

    const contentType = rpiResponse.headers.get('content-type') || '';
    
    // If it's a playlist, rewrite URLs
    if (contentType.includes('mpegurl') || decodedUrl.includes('.m3u8')) {
      const playlistText = await rpiResponse.text();
      const rewrittenPlaylist = rewritePlaylistUrls(playlistText, decodedUrl, proxyOrigin);
      
      return new Response(rewrittenPlaylist, {
        status: 200,
        headers: {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Cache-Control': 'public, max-age=5',
          'X-Proxied-Via': 'rpi',
          ...corsHeaders(),
        },
      });
    }

    // For segments
    const body = await rpiResponse.arrayBuffer();
    
    const firstBytes = new Uint8Array(body.slice(0, 4));
    const isMpegTs = firstBytes[0] === 0x47;
    const isFmp4 = firstBytes[0] === 0x00 && firstBytes[1] === 0x00 && firstBytes[2] === 0x00;
    
    let actualContentType = contentType;
    if (isMpegTs) actualContentType = 'video/mp2t';
    else if (isFmp4) actualContentType = 'video/mp4';
    else if (!actualContentType) actualContentType = 'application/octet-stream';

    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': actualContentType,
        'Content-Length': body.byteLength.toString(),
        'Cache-Control': 'public, max-age=3600',
        'X-Proxied-Via': 'rpi',
        ...corsHeaders(),
      },
    });

  } catch (error) {
    logger.error('RPI proxy error', error as Error);
    return jsonResponse({
      error: 'Proxy error',
      details: error instanceof Error ? error.message : String(error),
    }, 502);
  }
}

export default {
  fetch: handleAnimeKaiRequest,
};
