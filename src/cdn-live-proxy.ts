/**
 * CDN-Live.tv Stream Proxy
 * 
 * Routes:
 *   GET /cdn-live/stream?url=<encoded_url> - Proxy m3u8/ts with proper headers
 *   GET /cdn-live/health - Health check
 * 
 * The edge.cdn-live-tv.ru server requires proper Referer header.
 * This proxy adds the required headers and rewrites playlist URLs.
 */

import { createLogger, type LogLevel } from './logger';

export interface Env {
  LOG_LEVEL?: string;
}

const REFERER = 'https://cdn-live.tv/';
const ORIGIN = 'https://cdn-live.tv';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

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

export async function handleCDNLiveRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/cdn-live/, '');
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
      service: 'cdn-live-proxy',
      timestamp: new Date().toISOString(),
    });
  }

  // Stream proxy
  if (path === '/stream') {
    const streamUrl = url.searchParams.get('url');
    
    if (!streamUrl) {
      return jsonResponse({ error: 'URL parameter required' }, 400);
    }

    try {
      const decodedUrl = decodeURIComponent(streamUrl);
      
      // Validate URL is from expected domain
      if (!decodedUrl.includes('cdn-live-tv.ru') && !decodedUrl.includes('cdn-live.tv') && !decodedUrl.includes('cdn-live-tv.cfd')) {
        return jsonResponse({ error: 'Invalid URL domain' }, 400);
      }

      logger.info('Proxying CDN-Live stream', { url: decodedUrl.substring(0, 80) });

      const response = await fetch(decodedUrl, {
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Referer': REFERER,
          'Origin': ORIGIN,
        },
      });

      if (!response.ok) {
        logger.error('Upstream error', { status: response.status, url: decodedUrl.substring(0, 80) });
        return jsonResponse(
          { error: `Upstream error: ${response.status}` },
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
              return `URI="/cdn-live/stream?url=${encodeURIComponent(fullUrl)}"`;
            });
          }
          
          // Skip other comments
          if (trimmed.startsWith('#')) return line;
          
          // Rewrite segment URLs
          if (trimmed.startsWith('http')) {
            return `/cdn-live/stream?url=${encodeURIComponent(trimmed)}`;
          } else if (trimmed.endsWith('.ts') || trimmed.endsWith('.m3u8') || 
                     trimmed.includes('.ts?') || trimmed.includes('.m3u8?')) {
            const fullUrl = baseUrl + trimmed;
            return `/cdn-live/stream?url=${encodeURIComponent(fullUrl)}`;
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
      logger.error('CDN-Live proxy error', error as Error);
      return jsonResponse(
        { error: 'Proxy failed', details: String(error) },
        500
      );
    }
  }

  return jsonResponse({ error: 'Not found', path }, 404);
}
