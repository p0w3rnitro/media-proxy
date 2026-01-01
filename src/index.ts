/**
 * Combined Stream & TV Proxy Cloudflare Worker
 * 
 * Routes:
 *   /stream/*    - Anti-leech stream proxy (requires token)
 *   /tv/*        - TV proxy for DLHD live streams
 *   /analytics/* - Analytics proxy (presence, events, pageviews)
 *   /decode      - Isolated decoder sandbox for untrusted scripts
 *   /health      - Health check endpoint
 * 
 * Anti-Leech Protection:
 *   - All stream requests require cryptographic tokens
 *   - Tokens are bound to browser fingerprint + session
 *   - Tokens expire after 5 minutes
 *   - Unauthorized requests get the ORIGINAL URL (not proxied)
 * 
 * Deploy: wrangler deploy
 * Tail logs: npx wrangler tail media-proxy
 */

import streamProxy from './stream-proxy';
import antiLeechProxy from './anti-leech-proxy';
import fortressProxy from './fortress-proxy';
import quantumShield from './quantum-shield';
import quantumShieldV2 from './quantum-shield-v2';
import quantumShieldV3 from './quantum-shield-v3';
import tvProxy from './tv-proxy';
import decoderSandbox from './decoder-sandbox';
import { handleIPTVRequest } from './iptv-proxy';
import { handleDLHDRequest } from './dlhd-proxy';
import { handleAnimeKaiRequest } from './animekai-proxy';
import { handleFlixerRequest } from './flixer-proxy';
import { handleAnalyticsRequest } from './analytics-proxy';
import { handleTMDBRequest } from './tmdb-proxy';
import { handleCDNLiveRequest } from './cdn-live-proxy';
import { handlePPVRequest } from './ppv-proxy';
import { createLogger, generateRequestId, type LogLevel } from './logger';

export interface Env {
  API_KEY?: string;
  RPI_PROXY_URL?: string;
  RPI_PROXY_KEY?: string;
  LOG_LEVEL?: string;
  // TMDB API key for content proxy
  TMDB_API_KEY?: string;
  // Hetzner VPS proxy (PRIMARY for IPTV)
  HETZNER_PROXY_URL?: string;
  HETZNER_PROXY_KEY?: string;
  // Anti-leech settings
  ALLOWED_ORIGINS?: string;
  SIGNING_SECRET?: string;
  NONCE_KV?: KVNamespace;
  SESSION_KV?: KVNamespace;
  BLACKLIST_KV?: KVNamespace;
  WATERMARK_SECRET?: string;
  // Protection modes: 'none' | 'basic' | 'fortress' | 'quantum'
  PROTECTION_MODE?: string;
  // Legacy - kept for backwards compatibility
  ENABLE_ANTI_LEECH?: string;
  // Oxylabs proxy settings
  OXYLABS_USERNAME?: string;
  OXYLABS_PASSWORD?: string;
  OXYLABS_ENDPOINT?: string;
  OXYLABS_COUNTRY?: string;
  OXYLABS_CITY?: string;
}

// Simple in-memory metrics (resets on worker restart)
const metrics = {
  requests: 0,
  errors: 0,
  streamRequests: 0,
  tvRequests: 0,
  dlhdRequests: 0,
  decodeRequests: 0,
  animekaiRequests: 0,
  flixerRequests: 0,
  analyticsRequests: 0,
  tmdbRequests: 0,
  startTime: Date.now(),
};

// CORS headers for all responses
function getCorsHeaders(origin?: string | null): Record<string, string> {
  // Always allow all origins for stream proxy - CORS is handled by the browser
  // The anti-leech protection is done via tokens, not CORS
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, X-Request-ID, Authorization',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range',
    'Access-Control-Max-Age': '86400',
  };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const logLevel = (env.LOG_LEVEL || 'debug') as LogLevel;
    const logger = createLogger(request, logLevel);
    const requestOrigin = request.headers.get('origin');

    metrics.requests++;

    // Handle CORS preflight for ALL routes
    if (request.method === 'OPTIONS') {
      logger.info('CORS preflight request', { path, origin: requestOrigin });
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(requestOrigin),
      });
    }

    // Health check endpoint
    if (path === '/health' || path === '/health/') {
      const uptime = Math.floor((Date.now() - metrics.startTime) / 1000);
      logger.info('Health check', { uptime, metrics });
      
      return new Response(JSON.stringify({
        status: 'healthy',
        uptime: `${uptime}s`,
        metrics: {
          totalRequests: metrics.requests,
          errors: metrics.errors,
          streamRequests: metrics.streamRequests,
          tvRequests: metrics.tvRequests,
          dlhdRequests: metrics.dlhdRequests,
          decodeRequests: metrics.decodeRequests,
          animekaiRequests: metrics.animekaiRequests,
          flixerRequests: metrics.flixerRequests,
          analyticsRequests: metrics.analyticsRequests,
          tmdbRequests: metrics.tmdbRequests,
        },
        timestamp: new Date().toISOString(),
      }, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // Route to stream proxy (with protection based on mode)
    if (path.startsWith('/stream')) {
      metrics.streamRequests++;
      
      // Determine protection mode
      const protectionMode = env.PROTECTION_MODE || 
        (env.ENABLE_ANTI_LEECH === 'true' ? 'basic' : 'none');
      
      try {
        const newUrl = new URL(request.url);
        newUrl.pathname = path.replace(/^\/stream/, '') || '/';
        const newRequest = new Request(newUrl.toString(), request);

        switch (protectionMode) {
          case 'quantum-v3':
          case 'paranoid':
            // QUANTUM V3 PARANOID MODE: Maximum security
            // Requires: 3 challenges, PoW, fingerprint, behavioral data
            // Tokens expire in 10 seconds, strict rate limiting
            logger.info('Routing to QUANTUM SHIELD V3 (PARANOID)', { path });
            return await quantumShieldV3.fetch(newRequest, env as any);

          case 'quantum-v2':
            // QUANTUM V2: Enhanced with behavioral analysis, automation detection
            // Dynamic challenges, impossible travel detection, mouse entropy
            logger.info('Routing to QUANTUM SHIELD V2', { path });
            return await quantumShieldV2.fetch(newRequest, env as any);

          case 'quantum':
            // QUANTUM MODE: The most paranoid protection ever created
            // Requires SESSION_KV, BLACKLIST_KV, WATERMARK_SECRET
            // Features: Browser proofs, WASM challenges, Merkle trees,
            // Honeypots, Watermarking, Behavioral analysis, ASN binding
            logger.info('Routing to QUANTUM SHIELD', { path });
            return await quantumShield.fetch(newRequest, env as any);

          case 'fortress':
            // FORTRESS MODE: PoW + Session + Chaining
            // Requires SESSION_KV binding and client-side fortress-client.ts
            logger.info('Routing to FORTRESS proxy', { path });
            return await fortressProxy.fetch(newRequest, env as any);
            
          case 'basic':
            // BASIC MODE: Token + Fingerprint binding
            logger.info('Routing to anti-leech proxy', { path });
            return await antiLeechProxy.fetch(newRequest, env as any);
            
          default:
            // NO PROTECTION: Legacy mode
            logger.info('Routing to stream proxy (NO PROTECTION)', { path });
            return await streamProxy.fetch(newRequest, env);
        }
      } catch (error) {
        metrics.errors++;
        logger.error('Stream proxy error', error as Error);
        return errorResponse('Stream proxy error', 500);
      }
    }
    
    // FORTRESS endpoints (session init, challenge)
    if (path === '/init' || path === '/challenge') {
      const mode = env.PROTECTION_MODE || 'fortress';
      if (mode === 'quantum') {
        logger.info('Routing to quantum endpoint', { path });
        return await quantumShield.fetch(request, env as any);
      }
      logger.info('Routing to fortress endpoint', { path });
      return await fortressProxy.fetch(request, env as any);
    }

    // QUANTUM SHIELD V3 endpoints (PARANOID MODE)
    if (path.startsWith('/v3/')) {
      logger.info('Routing to quantum shield v3 (PARANOID)', { path });
      return await quantumShieldV3.fetch(request, env as any);
    }

    // QUANTUM SHIELD V2 endpoints
    if (path.startsWith('/v2/')) {
      logger.info('Routing to quantum shield v2', { path });
      return await quantumShieldV2.fetch(request, env as any);
    }

    // QUANTUM SHIELD endpoints
    if (path.startsWith('/quantum/')) {
      logger.info('Routing to quantum shield', { path });
      return await quantumShield.fetch(request, env as any);
    }

    // Route to DLHD proxy (Oxylabs residential IPs)
    if (path.startsWith('/dlhd')) {
      metrics.dlhdRequests++;
      logger.info('Routing to DLHD proxy (Oxylabs)', { path });
      
      try {
        return await handleDLHDRequest(request, env);
      } catch (error) {
        metrics.errors++;
        const err = error as Error;
        logger.error('DLHD proxy error', err);
        return new Response(JSON.stringify({
          error: 'DLHD proxy error',
          message: err.message,
          stack: err.stack,
          timestamp: new Date().toISOString(),
        }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
    }

    // Route to AnimeKai proxy (MegaUp CDN via RPI residential IP)
    if (path.startsWith('/animekai')) {
      metrics.animekaiRequests++;
      logger.info('Routing to AnimeKai proxy (RPI)', { path });
      
      try {
        return await handleAnimeKaiRequest(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('AnimeKai proxy error', error as Error);
        return errorResponse('AnimeKai proxy error', 500);
      }
    }

    // Route to Flixer proxy (WASM-based extraction)
    if (path.startsWith('/flixer')) {
      metrics.flixerRequests++;
      logger.info('Routing to Flixer proxy', { path });
      
      try {
        return await handleFlixerRequest(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('Flixer proxy error', error as Error);
        return errorResponse('Flixer proxy error', 500);
      }
    }

    // Route to Analytics proxy (presence, events, pageviews)
    // This bypasses Vercel Edge and writes directly to Neon
    if (path.startsWith('/analytics')) {
      metrics.analyticsRequests++;
      logger.info('Routing to Analytics proxy', { path });
      
      try {
        return await handleAnalyticsRequest(request, env as any);
      } catch (error) {
        metrics.errors++;
        logger.error('Analytics proxy error', error as Error);
        return errorResponse('Analytics proxy error', 500);
      }
    }

    // Route to TMDB proxy (content API)
    // This bypasses Vercel Edge for all TMDB API calls
    if (path.startsWith('/tmdb')) {
      metrics.tmdbRequests++;
      logger.info('Routing to TMDB proxy', { path });
      
      try {
        return await handleTMDBRequest(request, env as any);
      } catch (error) {
        metrics.errors++;
        logger.error('TMDB proxy error', error as Error);
        return errorResponse('TMDB proxy error', 500);
      }
    }

    // Route to CDN-Live.tv proxy (live TV streams)
    // Proxies m3u8/ts with proper Referer headers
    if (path.startsWith('/cdn-live')) {
      logger.info('Routing to CDN-Live proxy', { path });
      
      try {
        return await handleCDNLiveRequest(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('CDN-Live proxy error', error as Error);
        return errorResponse('CDN-Live proxy error', 500);
      }
    }

    // Route to PPV.to proxy (PPV streams)
    // Proxies m3u8/ts with proper Referer headers for pooembed.top
    if (path.startsWith('/ppv')) {
      logger.info('Routing to PPV proxy', { path });
      
      try {
        return await handlePPVRequest(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('PPV proxy error', error as Error);
        return errorResponse('PPV proxy error', 500);
      }
    }

    // Route to IPTV proxy (Stalker portals)
    // Handle both /iptv/* and /tv/iptv/* (legacy path from NEXT_PUBLIC_CF_TV_PROXY_URL)
    if (path.startsWith('/iptv') || path.startsWith('/tv/iptv')) {
      logger.info('Routing to IPTV proxy', { path });
      
      try {
        // If path starts with /tv/iptv, strip the /tv prefix for the handler
        if (path.startsWith('/tv/iptv')) {
          const newUrl = new URL(request.url);
          newUrl.pathname = path.replace(/^\/tv/, '');
          const newRequest = new Request(newUrl.toString(), request);
          return await handleIPTVRequest(newRequest, env);
        }
        return await handleIPTVRequest(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('IPTV proxy error', error as Error);
        return errorResponse('IPTV proxy error', 500);
      }
    }

    // Route to TV proxy (DLHD streams - NOT IPTV)
    if (path.startsWith('/tv')) {
      metrics.tvRequests++;
      logger.info('Routing to TV proxy', { path });
      
      try {
        const newUrl = new URL(request.url);
        newUrl.pathname = path.replace(/^\/tv/, '') || '/';
        const newRequest = new Request(newUrl.toString(), request);
        logger.debug('TV proxy request', { newUrl: newUrl.toString() });
        return await tvProxy.fetch(newRequest, env);
      } catch (error) {
        metrics.errors++;
        const err = error as Error;
        logger.error('TV proxy error', err);
        return new Response(JSON.stringify({
          error: 'TV proxy error',
          message: err.message,
          stack: err.stack,
          timestamp: new Date().toISOString(),
        }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
    }

    // Route to decoder sandbox
    if (path === '/decode' || path === '/decode/') {
      metrics.decodeRequests++;
      logger.info('Routing to decoder sandbox');
      
      try {
        return await decoderSandbox.fetch(request, env);
      } catch (error) {
        metrics.errors++;
        logger.error('Decoder sandbox error', error as Error);
        return errorResponse('Decoder sandbox error', 500);
      }
    }

    // Root - show usage and status
    logger.info('Root endpoint accessed');
    
    const antiLeechEnabled = env.ENABLE_ANTI_LEECH === 'true';
    
    return new Response(JSON.stringify({
      name: 'Cloudflare Stream & TV Proxy',
      version: '3.0.0',
      status: 'operational',
      uptime: `${Math.floor((Date.now() - metrics.startTime) / 1000)}s`,
      antiLeech: {
        enabled: antiLeechEnabled,
        description: antiLeechEnabled 
          ? 'Requests require cryptographic tokens bound to browser fingerprint'
          : 'Legacy mode - no protection (set ENABLE_ANTI_LEECH=true to enable)',
      },
      routes: {
        stream: {
          path: '/stream/',
          description: antiLeechEnabled 
            ? 'Anti-leech HLS stream proxy (requires token)'
            : 'HLS stream proxy for 2embed',
          usage: antiLeechEnabled
            ? '/stream/?url=<url>&t=<token>&f=<fingerprint>&s=<session>'
            : '/stream/?url=<encoded_url>&source=2embed&referer=<encoded_referer>',
          tokenEndpoint: antiLeechEnabled ? '/stream/token' : undefined,
        },
        tv: {
          path: '/tv/',
          description: 'DLHD live TV proxy (direct/RPI fallback)',
          usage: '/tv/?channel=<id>',
          subRoutes: {
            key: '/tv/key?url=<encoded_url>',
            segment: '/tv/segment?url=<encoded_url>',
          },
        },
        dlhd: {
          path: '/dlhd/',
          description: 'DLHD proxy with Oxylabs residential IP rotation',
          usage: '/dlhd?channel=<id>',
          subRoutes: {
            key: '/dlhd/key?url=<encoded_url>',
            segment: '/dlhd/segment?url=<encoded_url>',
            health: '/dlhd/health',
          },
          config: {
            oxylabs: !!(env.OXYLABS_USERNAME && env.OXYLABS_PASSWORD) ? 'configured' : 'not configured',
            country: env.OXYLABS_COUNTRY || 'auto',
          },
        },
        iptv: {
          path: '/iptv/',
          description: 'IPTV Stalker portal proxy',
          subRoutes: {
            api: '/iptv/api?url=<encoded_url>&mac=<mac>&token=<token>',
            stream: '/iptv/stream?url=<encoded_url>&mac=<mac>&token=<token>',
          },
        },
        animekai: {
          path: '/animekai/',
          description: 'AnimeKai stream proxy via RPI residential IP (MegaUp CDN)',
          usage: '/animekai?url=<encoded_url>',
          subRoutes: {
            health: '/animekai/health',
          },
          config: {
            rpiProxy: !!(env.RPI_PROXY_URL && env.RPI_PROXY_KEY) ? 'configured' : 'not configured',
          },
        },
        flixer: {
          path: '/flixer/',
          description: 'Flixer stream extraction via WASM-based decryption',
          usage: '/flixer/extract?tmdbId=<id>&type=<movie|tv>&season=<n>&episode=<n>&server=<name>',
          subRoutes: {
            extract: '/flixer/extract - Extract m3u8 URL from Flixer',
            health: '/flixer/health - Health check',
          },
          servers: ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'],
        },
        ppv: {
          path: '/ppv/',
          description: 'PPV.to stream proxy (pooembed.top/poocloud.in)',
          usage: '/ppv/stream?url=<encoded_url>',
          subRoutes: {
            stream: '/ppv/stream?url=<encoded_url> - Proxy m3u8/ts with proper Referer',
            health: '/ppv/health - Health check',
            test: '/ppv/test - Test upstream connectivity',
          },
          validDomains: ['poocloud.in', 'pooembed.top'],
          requiredHeaders: {
            Referer: 'https://pooembed.top/',
            Origin: 'https://pooembed.top',
          },
        },
        cdnLive: {
          path: '/cdn-live/',
          description: 'CDN-Live.tv stream proxy',
          usage: '/cdn-live/stream?url=<encoded_url>',
          subRoutes: {
            stream: '/cdn-live/stream?url=<encoded_url> - Proxy m3u8/ts',
            health: '/cdn-live/health - Health check',
          },
        },
        analytics: {
          path: '/analytics/',
          description: 'Analytics proxy - bypasses Vercel Edge, writes directly to Neon',
          subRoutes: {
            presence: 'POST /analytics/presence - User presence heartbeat',
            pageview: 'POST /analytics/pageview - Page view tracking',
            event: 'POST /analytics/event - Generic analytics event',
            health: 'GET /analytics/health - Health check',
          },
          benefits: [
            'Cloudflare free tier: 100k requests/day',
            'Lower latency (edge closer to users)',
            'No cold starts',
            'Reduced Vercel costs',
          ],
        },
        decode: {
          path: '/decode',
          description: 'Isolated decoder sandbox for untrusted scripts',
          method: 'POST',
          body: '{ script: string, divId: string, encodedContent: string }',
        },
        health: {
          path: '/health',
          description: 'Health check and metrics',
        },
      },
      observability: {
        logs: 'View in Cloudflare Dashboard > Workers > Logs',
        tailCommand: 'npx wrangler tail media-proxy',
        logLevel: logLevel,
      },
    }, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  },
};

function errorResponse(message: string, status: number): Response {
  return new Response(JSON.stringify({ 
    error: message,
    timestamp: new Date().toISOString(),
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
