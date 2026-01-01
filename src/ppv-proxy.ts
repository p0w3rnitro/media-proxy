/**
 * PPV.to Stream Proxy
 * 
 * Routes:
 *   GET /ppv/stream?url=<encoded_url> - Proxy m3u8/ts with proper headers
 *   GET /ppv/health - Health check
 *   GET /ppv/test - Test upstream connectivity
 * 
 * PPV streams from pooembed.top require proper Referer header.
 * This proxy adds the required headers and rewrites playlist URLs.
 * 
 * Stream domains: *.poocloud.in (e.g., gg.poocloud.in)
 */

import { createLogger, type LogLevel } from './logger';

export interface Env {
  LOG_LEVEL?: string;
  // Optional: RPI proxy for residential IP fallback
  RPI_PROXY_URL?: string;
  RPI_PROXY_KEY?: string;
}

const REFERER = 'https://pooembed.top/';
const ORIGIN = 'https://pooembed.top';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// Valid domains for PPV streams
const VALID_DOMAINS = ['poocloud.in', 'pooembed.top', 'dzine.ai'];

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
  };
}

function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}

function isValidDomain(url: string): boolean {
  try {
    const parsed = new URL(url);
    return VALID_DOMAINS.some(domain => parsed.hostname.endsWith(domain));
  } catch {
    return false;
  }
}

async function fetchWithRetry(
  url: string, 
  headers: Record<string, string>,
  logger: ReturnType<typeof createLogger>,
  env: Env
): Promise<Response> {
  // If we have RPI proxy configured, use it directly (poocloud.in blocks datacenter IPs)
  if (env.RPI_PROXY_URL && env.RPI_PROXY_KEY) {
    logger.info('Using RPI proxy for PPV stream', { url: url.substring(0, 80) });
    
    try {
      const rpiUrl = `${env.RPI_PROXY_URL}/ppv?url=${encodeURIComponent(url)}`;
      const rpiResponse = await fetch(rpiUrl, {
        headers: {
          'X-API-Key': env.RPI_PROXY_KEY,
        },
      });
      
      if (rpiResponse.ok) {
        logger.info('RPI proxy succeeded', { status: rpiResponse.status });
        return rpiResponse;
      }
      
      logger.warn('RPI proxy failed', { status: rpiResponse.status });
      // Fall through to direct fetch
    } catch (error) {
      logger.error('RPI proxy error', error as Error);
      // Fall through to direct fetch
    }
  }
  
  // Try direct fetch as fallback (may work for some streams)
  logger.info('Attempting direct fetch', { url: url.substring(0, 80) });
  
  const directResponse = await fetch(url, { headers });
  
  if (directResponse.ok) {
    logger.info('Direct fetch succeeded', { status: directResponse.status });
  } else {
    logger.warn('Direct fetch failed', { 
      status: directResponse.status,
      url: url.substring(0, 80)
    });
  }
  
  return directResponse;
}

export async function handlePPVRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/ppv/, '');
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // Health check
  if (path === '/health' || path === '') {
    return jsonResponse({
      status: 'ok',
      service: 'ppv-proxy',
      timestamp: new Date().toISOString(),
      config: {
        validDomains: VALID_DOMAINS,
        rpiProxyConfigured: !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY),
      },
    });
  }

  // Test endpoint - verify upstream connectivity
  if (path === '/test') {
    const testUrl = 'https://gg.poocloud.in/southpark/index.m3u8';
    
    try {
      const response = await fetch(testUrl, {
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Referer': REFERER,
          'Origin': ORIGIN,
        },
      });
      
      const contentType = response.headers.get('content-type');
      const contentLength = response.headers.get('content-length');
      let preview = '';
      
      if (response.ok) {
        const text = await response.text();
        preview = text.substring(0, 200);
      }
      
      return jsonResponse({
        testUrl,
        status: response.status,
        ok: response.ok,
        contentType,
        contentLength,
        preview,
        headers: {
          sent: {
            'User-Agent': USER_AGENT,
            'Referer': REFERER,
            'Origin': ORIGIN,
          },
        },
      });
    } catch (error) {
      return jsonResponse({
        testUrl,
        error: String(error),
      }, 500);
    }
  }

  // Stream proxy
  if (path === '/stream') {
    const streamUrl = url.searchParams.get('url');
    
    if (!streamUrl) {
      return jsonResponse({ error: 'URL parameter required' }, 400);
    }

    try {
      const decodedUrl = decodeURIComponent(streamUrl);
      
      // Validate domain
      if (!isValidDomain(decodedUrl)) {
        logger.warn('Invalid domain', { url: decodedUrl.substring(0, 80) });
        return jsonResponse({ 
          error: 'Invalid URL domain',
          validDomains: VALID_DOMAINS,
        }, 400);
      }
      
      logger.info('Proxying PPV stream', { url: decodedUrl.substring(0, 80) });

      const headers = {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': REFERER,
        'Origin': ORIGIN,
      };

      const response = await fetchWithRetry(decodedUrl, headers, logger, env);

      if (!response.ok) {
        logger.error('Upstream error', { status: response.status, url: decodedUrl.substring(0, 80) });
        
        // Try to get error details
        let errorDetails = '';
        try {
          errorDetails = await response.text();
          errorDetails = errorDetails.substring(0, 500);
        } catch {}
        
        return jsonResponse(
          { 
            error: `Upstream error: ${response.status}`,
            url: decodedUrl.substring(0, 80),
            details: errorDetails,
          },
          response.status
        );
      }

      const contentType = response.headers.get('content-type') || 'application/octet-stream';
      
      // For m3u8 playlists, rewrite URLs to go through our proxy
      if (contentType.includes('mpegurl') || decodedUrl.endsWith('.m3u8') || decodedUrl.includes('.m3u8?')) {
        const text = await response.text();
        
        // Get base URL for relative paths
        const baseUrl = decodedUrl.substring(0, decodedUrl.lastIndexOf('/') + 1);
        
        // Rewrite URLs in the playlist
        const rewritten = text.split('\n').map((line: string) => {
          const trimmed = line.trim();
          
          // Skip empty lines
          if (trimmed === '') return line;
          
          // Handle EXT-X-KEY URI
          if (trimmed.includes('URI="')) {
            return trimmed.replace(/URI="([^"]+)"/, (_: string, uri: string) => {
              const fullUrl = uri.startsWith('http') ? uri : baseUrl + uri;
              return `URI="/ppv/stream?url=${encodeURIComponent(fullUrl)}"`;
            });
          }
          
          // Skip other comments
          if (trimmed.startsWith('#')) return line;
          
          // Rewrite segment URLs (any file extension - they use obfuscation)
          if (trimmed.startsWith('http')) {
            return `/ppv/stream?url=${encodeURIComponent(trimmed)}`;
          } else if (trimmed.length > 0 && !trimmed.startsWith('#')) {
            // Any non-comment, non-empty line is a segment URL
            const fullUrl = baseUrl + trimmed;
            return `/ppv/stream?url=${encodeURIComponent(fullUrl)}`;
          }
          
          return line;
        }).join('\n');

        return new Response(rewritten, {
          headers: {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Cache-Control': 'no-cache',
            ...corsHeaders(),
          },
        });
      }

      // For binary content (ts segments), stream directly
      const data = await response.arrayBuffer();
      
      return new Response(data, {
        headers: {
          'Content-Type': contentType,
          'Cache-Control': 'no-cache',
          ...corsHeaders(),
        },
      });
    } catch (error) {
      logger.error('PPV proxy error', error as Error);
      return jsonResponse(
        { error: 'Proxy failed', details: String(error) },
        500
      );
    }
  }

  return jsonResponse({ error: 'Not found', path }, 404);
}
