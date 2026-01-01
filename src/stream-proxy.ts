/**
 * Stream Proxy Cloudflare Worker
 * 
 * Proxies HLS streams and their segments with proper referer headers.
 * Essential for 2embed streams which require the referer header on ALL requests.
 * 
 * GET /?url=<encoded_url>&source=2embed&referer=<encoded_referer>
 */

import { Logger, createLogger, type LogLevel } from './logger';

export interface Env {
  API_KEY?: string;
  LOG_LEVEL?: string;
  // Hetzner VPS proxy for MegaUp streams (Cloudflare IPs are blocked)
  HETZNER_PROXY_URL?: string;
  HETZNER_PROXY_KEY?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const logLevel = (env.LOG_LEVEL || 'debug') as LogLevel;
    const logger = createLogger(request, logLevel);

    const requestOrigin = request.headers.get('origin');
    const requestReferer = request.headers.get('referer');

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      logger.info('CORS preflight request');
      
      // Only allow preflight for allowed origins
      if (!isAllowedOrigin(requestOrigin, requestReferer)) {
        return new Response(null, { status: 403 });
      }
      
      return new Response(null, {
        status: 200,
        headers: corsHeaders(requestOrigin),
      });
    }

    if (request.method !== 'GET') {
      logger.warn('Method not allowed', { method: request.method });
      return jsonResponse({ error: 'Method not allowed' }, 405, logger, requestOrigin);
    }

    try {
      const url = new URL(request.url);
      const targetUrl = url.searchParams.get('url');
      const source = url.searchParams.get('source') || '2embed';
      const upstreamReferer = url.searchParams.get('referer') || 'https://www.2embed.cc';

      if (!targetUrl) {
        logger.warn('Missing url parameter');
        return jsonResponse({ error: 'Missing url parameter' }, 400, logger, requestOrigin);
      }

      const decodedUrl = decodeURIComponent(targetUrl);
      
      // ANTI-LEECH: Check if request is from allowed origin
      if (!isAllowedOrigin(requestOrigin, requestReferer)) {
        logger.warn('Blocked leecher request', { origin: requestOrigin, referer: requestReferer });
        
        // Return the ORIGINAL URL - let them proxy it themselves
        return new Response(JSON.stringify({
          error: 'Access denied - use the original URL',
          originalUrl: decodedUrl,
          message: 'This proxy only serves requests from authorized domains',
        }), {
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': 'null',
          },
        });
      }
      
      // Check if we should skip referer (some servers block requests WITH referer)
      // If referer matches the target URL's origin, or if noreferer param is set, skip it
      const noRefererParam = url.searchParams.get('noreferer') === 'true' || url.searchParams.get('noref') === '1';
      
      // Parse origins for comparison
      let targetOrigin = '';
      let refererOrigin = '';
      try {
        targetOrigin = new URL(decodedUrl).origin;
        refererOrigin = upstreamReferer ? new URL(upstreamReferer).origin : '';
      } catch (e) {
        logger.warn('Failed to parse URL origins', { error: String(e) });
      }
      
      const sameOriginReferer = !!(targetOrigin && refererOrigin && targetOrigin === refererOrigin);
      const skipReferer = noRefererParam || sameOriginReferer;
      
      // Detect MegaUp/hub26link requests - these CDNs block requests with Origin header
      // They DON'T block Cloudflare IPs - they block the Origin header specifically
      const isMegaUp = decodedUrl.includes('megaup') || decodedUrl.includes('hub26link') || decodedUrl.includes('app28base');
      
      // For MegaUp, ALWAYS skip Origin/Referer headers (they cause 403)
      const effectiveSkipReferer = isMegaUp ? true : skipReferer;
      
      if (isMegaUp) {
        logger.info('MegaUp request detected - forcing noreferer mode (Origin header causes 403)', {
          targetOrigin,
          originalSkipReferer: skipReferer,
          effectiveSkipReferer,
        });
      }
      
      logger.info('Proxying request', { 
        targetUrl: decodedUrl.substring(0, 150),
        source,
        referer: effectiveSkipReferer ? '(skipped - MegaUp or noreferer)' : upstreamReferer.substring(0, 100),
        skipReferer: effectiveSkipReferer,
        routeVia: 'direct',
      });

      let response: Response;
      const fetchStart = Date.now();

      // Direct fetch - Cloudflare Worker fetches without Origin header for MegaUp
      const headers: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'identity',
      };
      
      // Only add Referer/Origin if not skipping (MegaUp blocks requests with Origin header)
      if (!effectiveSkipReferer && upstreamReferer) {
        headers['Referer'] = upstreamReferer;
        headers['Origin'] = new URL(upstreamReferer).origin;
      }
      
      logger.debug('Direct fetch headers', {
        skipReferer: effectiveSkipReferer,
        headersKeys: Object.keys(headers),
        isMegaUp,
      });

      logger.fetchStart(decodedUrl, { headers });

      try {
        response = await fetch(decodedUrl, {
          headers,
          redirect: 'manual',
        });
      } catch (fetchError) {
        logger.fetchError(decodedUrl, fetchError as Error);
        return jsonResponse({ 
          error: 'Upstream fetch failed',
          details: fetchError instanceof Error ? fetchError.message : String(fetchError),
        }, 502, logger, requestOrigin);
      }

      logger.fetchEnd(decodedUrl, response.status, Date.now() - fetchStart);

      // Handle redirects
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        logger.info('Following redirect', { status: response.status, location });
        
        if (location) {
          const redirectUrl = new URL(location, decodedUrl).toString();
          const redirectStart = Date.now();
          
          try {
            response = await fetch(redirectUrl, { headers, redirect: 'follow' });
            logger.fetchEnd(redirectUrl, response.status, Date.now() - redirectStart);
          } catch (redirectError) {
            logger.fetchError(redirectUrl, redirectError as Error);
            return jsonResponse({ error: 'Redirect fetch failed' }, 502, logger, requestOrigin);
          }
          
          if (!response.ok) {
            logger.error('Redirect target error', { status: response.status });
            return jsonResponse({ error: `Redirect target error: ${response.status}` }, response.status, logger, requestOrigin);
          }
          
          return handleStreamResponse(response, decodedUrl, source, upstreamReferer, url.origin, logger, requestOrigin, effectiveSkipReferer);
        }
      }

      if (!response.ok) {
        logger.error('Upstream error', { 
          status: response.status, 
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers),
        });
        return jsonResponse({ error: `Upstream error: ${response.status}` }, response.status, logger, requestOrigin);
      }

      return handleStreamResponse(response, decodedUrl, source, upstreamReferer, url.origin, logger, requestOrigin, effectiveSkipReferer);

    } catch (error) {
      logger.error('Proxy error', error as Error);
      return jsonResponse({
        error: 'Proxy error',
        details: error instanceof Error ? error.message : String(error),
      }, 500, logger, requestOrigin);
    }
  },
};

async function handleStreamResponse(
  response: Response,
  decodedUrl: string,
  source: string,
  referer: string,
  proxyOrigin: string,
  logger: Logger,
  requestOrigin?: string | null,
  skipReferer: boolean = false
): Promise<Response> {
  const contentType = response.headers.get('content-type') || '';
  
  let arrayBuffer: ArrayBuffer;
  try {
    arrayBuffer = await response.arrayBuffer();
  } catch (bufferError) {
    logger.error('Failed to read response body', bufferError as Error);
    return jsonResponse({ error: 'Failed to read upstream response' }, 502, logger, requestOrigin);
  }

  logger.debug('Response body read', { 
    size: arrayBuffer.byteLength,
    contentType,
  });
  
  // Check if this is video data
  const firstBytes = new Uint8Array(arrayBuffer.slice(0, 4));
  const isMpegTs = firstBytes[0] === 0x47;
  const isFmp4 = firstBytes[0] === 0x00 && firstBytes[1] === 0x00 && firstBytes[2] === 0x00;
  const isVideoData = isMpegTs || isFmp4;

  const isPlaylist = !isVideoData && (
    contentType.includes('mpegurl') ||
    decodedUrl.includes('.m3u8') ||
    decodedUrl.includes('.txt') ||
    (contentType.includes('text') && !decodedUrl.includes('.html'))
  );

  logger.debug('Content type detection', {
    isPlaylist,
    isVideoData,
    isMpegTs,
    isFmp4,
    contentType,
    urlHint: decodedUrl.includes('.m3u8') ? 'm3u8' : decodedUrl.includes('.ts') ? 'ts' : 'other',
  });

  if (isPlaylist) {
    const text = new TextDecoder().decode(arrayBuffer);
    const lineCount = text.split('\n').length;
    logger.info('Processing playlist', { lineCount, size: arrayBuffer.byteLength });
    
    const rewrittenPlaylist = rewritePlaylistUrls(text, decodedUrl, source, referer, proxyOrigin, logger, skipReferer);
    
    const res = new Response(rewrittenPlaylist, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.apple.mpegurl',
        ...corsHeaders(requestOrigin),
        'Cache-Control': 'public, max-age=300',
      },
    });
    
    logger.requestEnd(res);
    return res;
  }

  // Return video segment
  let actualContentType = 'video/mp2t';
  if (isMpegTs) actualContentType = 'video/mp2t';
  else if (isFmp4) actualContentType = 'video/mp4';

  logger.info('Returning video segment', { 
    type: actualContentType, 
    size: arrayBuffer.byteLength,
  });

  const res = new Response(arrayBuffer, {
    status: 200,
    headers: {
      'Content-Type': actualContentType,
      ...corsHeaders(requestOrigin),
      'Cache-Control': 'public, max-age=3600',
      'Content-Length': arrayBuffer.byteLength.toString(),
    },
  });

  logger.requestEnd(res);
  return res;
}

function rewritePlaylistUrls(
  playlist: string,
  baseUrl: string,
  source: string,
  referer: string,
  proxyOrigin: string,
  logger: Logger,
  skipReferer: boolean = false
): string {
  const lines = playlist.split('\n');
  const rewritten: string[] = [];
  let urlsRewritten = 0;
  
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
    
    urlsRewritten++;
    // Include noreferer flag if we're skipping referer (for servers that block requests with Referer header)
    const noRefParam = skipReferer ? '&noreferer=true' : '';
    return `${proxyOrigin}/stream/?url=${encodeURIComponent(absoluteUrl)}&source=${source}&referer=${encodeURIComponent(referer)}${noRefParam}`;
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

    if (!trimmedLine) {
      rewritten.push(line);
      continue;
    }
    
    try {
      rewritten.push(proxyUrl(trimmedLine));
    } catch {
      rewritten.push(line);
    }
  }

  logger.debug('Playlist rewritten', { 
    originalLines: lines.length, 
    urlsRewritten,
  });

  return rewritten.join('\n');
}

// Allowed origins - requests from other origins get the original URL exposed
const ALLOWED_ORIGINS = [
  'https://tv.vynx.cc',
  'https://flyx.tv',
  'https://www.flyx.tv',
  'http://localhost:3000',
  'http://localhost:3001',
  // Allow Vercel preview deployments
  '.vercel.app',
];

function isAllowedOrigin(origin: string | null, referer: string | null): boolean {
  const checkOrigin = (o: string): boolean => {
    return ALLOWED_ORIGINS.some(allowed => {
      if (allowed.includes('localhost')) return o.includes('localhost');
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

function corsHeaders(origin?: string | null): Record<string, string> {
  // Allow all origins - protection is done via origin checking in the handler
  // Setting 'null' breaks CORS completely, so use '*' as fallback
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, X-Request-ID',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
  };
}

function jsonResponse(data: object, status: number, logger?: Logger, origin?: string | null): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin),
    },
  });
  
  if (logger) {
    logger.requestEnd(res);
  }
  
  return res;
}
