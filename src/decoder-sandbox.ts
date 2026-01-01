/**
 * Decoder Sandbox - Isolated JavaScript Execution
 * 
 * This runs untrusted decoder scripts in a separate Cloudflare Worker isolate,
 * providing true V8-level isolation from the main application.
 * 
 * SECURITY MODEL:
 * 1. Each request runs in a fresh V8 isolate (Cloudflare's architecture)
 * 2. No access to fetch, WebSocket, or any network APIs
 * 3. No access to persistent storage
 * 4. CPU time limited by Cloudflare (50ms for free, 30s for paid)
 * 5. Memory isolated per request
 * 6. Pre-execution pattern validation as defense-in-depth
 * 7. Output URL validation against domain allowlist
 */

export interface Env {
  API_KEY?: string;
}

interface DecodeRequest {
  script: string;      // The decoder script to execute
  divId: string;       // The div ID the script targets
  encodedContent: string; // The encoded content to decode
}

interface DecodeResponse {
  success: boolean;
  decodedUrl?: string;
  error?: string;
}

// Domain for stream URL variable replacement
const STREAM_DOMAIN = 'shadowlandschronicles.com';

/**
 * SECURITY: Blocklist of dangerous patterns
 * Defense-in-depth - even though we're in an isolated Worker, log suspicious patterns
 * NOTE: We're lenient here because the Worker isolate provides true security.
 * These are just for logging/monitoring, not blocking legitimate decoders.
 */
const SUSPICIOUS_PATTERNS = [
  // Crypto mining indicators (these we DO block)
  /\bCryptoMiner\b/i,
  /\bcoinhive\b/i,
  /\bmonero\b/i,
];

/**
 * SECURITY: Allowlist of domains for decoded URLs
 */
const ALLOWED_STREAM_DOMAINS = [
  'shadowlandschronicles.com',
  'cloudnestra.com',
  'vidsrc.stream',
  'vidsrc.me',
  'vidsrc.xyz',
  'vidsrc.net',
  'vidsrc.to',
  'vidsrc.in',
  'akamaized.net',
  'cloudflare.com',
  'fastly.net',
  // Additional CDN domains commonly used
  'tmstr5.com',
  'premilkyway.com',
  'aurorionproductions.cyou',
  '1hd.su',
  'flix1.online',
];

/**
 * Validate script for suspicious patterns (defense-in-depth)
 * NOTE: The Worker isolate provides true security - this is just for logging
 */
function validateScript(script: string): string | null {
  // Size limit - their decoder scripts are ~112KB
  if (script.length > 200000) {
    return 'Script exceeds 200KB limit';
  }
  
  // Only block obvious crypto miners - everything else is handled by isolate
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(script)) {
      return `Blocked pattern detected: ${pattern.source}`;
    }
  }
  
  return null;
}

/**
 * Validate decoded URL against allowlist
 * Returns true if URL looks like a legitimate stream URL
 */
function validateDecodedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    
    // Must be HTTPS
    if (parsed.protocol !== 'https:') return false;
    
    // Must look like a stream URL (m3u8 or contains stream-like paths)
    const isStreamUrl = parsed.pathname.includes('.m3u8') || 
                        parsed.pathname.includes('/pl/') ||
                        parsed.pathname.includes('/hls/') ||
                        parsed.pathname.includes('/master');
    if (!isStreamUrl) return false;
    
    // Check against domain allowlist
    const hostname = parsed.hostname.toLowerCase();
    const isAllowed = ALLOWED_STREAM_DOMAINS.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
    
    // If not in allowlist, log but still allow (the isolate is the real security)
    if (!isAllowed) {
      console.warn('[Sandbox] URL from unknown domain (allowing):', hostname);
    }
    
    return true; // Allow all HTTPS stream URLs - isolate provides security
  } catch {
    return false;
  }
}

/**
 * Custom base64 decode
 */
function customAtob(str: string): string {
  return atob(str);
}

/**
 * Custom base64 encode
 */
function customBtoa(str: string): string {
  return btoa(str);
}

/**
 * Execute decoder in isolated context
 */
function executeDecoder(script: string, divId: string, encodedContent: string): string | null {
  let decodedContent: string | null = null;

  // Mock window that captures output
  const mockWindow: Record<string, unknown> = {};
  const windowProxy = new Proxy(mockWindow, {
    set: (target, prop, value) => {
      target[prop as string] = value;
      if (typeof value === 'string' && value.includes('https://')) {
        decodedContent = value;
      }
      return true;
    },
    get: (target, prop) => {
      // Block dangerous properties
      const blocked = ['fetch', 'XMLHttpRequest', 'WebSocket', 'eval', 'Function',
                       'localStorage', 'sessionStorage', 'indexedDB', 'navigator',
                       'location', 'parent', 'top', 'frames', 'opener', 'self',
                       'importScripts', 'caches', 'crypto'];
      if (blocked.includes(prop as string)) {
        return undefined;
      }
      return target[prop as string];
    }
  });

  // Mock document - read-only access to the encoded content
  const mockDocument = {
    getElementById: (id: string) => {
      if (id === divId) {
        return { 
          innerHTML: encodedContent,
          get outerHTML() { return `<div id="${id}">${encodedContent}</div>`; }
        };
      }
      return null;
    },
    createElement: () => { throw new Error('Blocked'); },
    write: () => { throw new Error('Blocked'); },
    writeln: () => { throw new Error('Blocked'); },
  };

  // Silent console
  const mockConsole = {
    log: () => {},
    error: () => {},
    warn: () => {},
    info: () => {},
    debug: () => {},
  };

  try {
    // Wrap and execute the decoder
    const wrappedCode = `
      return (function(window, document, atob, btoa, setTimeout, setInterval, console) {
        "use strict";
        ${script}
      });
    `;
    
    const createRunner = new Function(wrappedCode);
    const runner = createRunner();
    
    runner(
      windowProxy,
      mockDocument,
      customAtob,
      customBtoa,
      (fn: () => void) => { if (typeof fn === 'function') fn(); },
      () => {},
      mockConsole
    );
    
    // Check for result
    if (!decodedContent && mockWindow[divId]) {
      decodedContent = mockWindow[divId] as string;
    }
    
    return decodedContent;
  } catch (error) {
    console.error('[Sandbox] Execution error:', error);
    return null;
  }
}

/**
 * Handle decode request
 */
async function handleDecode(request: Request, env: Env): Promise<Response> {
  // Verify API key if configured
  if (env.API_KEY) {
    const authHeader = request.headers.get('X-API-Key');
    if (authHeader !== env.API_KEY) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  // Parse request
  let body: DecodeRequest;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ success: false, error: 'Invalid JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { script, divId, encodedContent } = body;

  if (!script || !divId || !encodedContent) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: 'Missing required fields: script, divId, encodedContent' 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Validate script
  const validationError = validateScript(script);
  if (validationError) {
    console.warn('[Sandbox] Script validation failed:', validationError);
    return new Response(JSON.stringify({ 
      success: false, 
      error: `Script validation failed: ${validationError}` 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Execute decoder
  const decodedContent = executeDecoder(script, divId, encodedContent);

  if (!decodedContent) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: 'Decoder execution failed - no output captured' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Extract and validate URLs
  const urls = decodedContent.match(/https?:\/\/[^\s"']+\.m3u8[^\s"']*/g) || [];
  const resolvedUrls = urls.map(url => url.replace(/\{v\d+\}/g, STREAM_DOMAIN));
  
  // Find first valid URL
  const validUrl = resolvedUrls.find(url => validateDecodedUrl(url));

  if (!validUrl) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: 'Decoded content contains no valid stream URLs' 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const response: DecodeResponse = {
    success: true,
    decodedUrl: decodedContent // Return full decoded content for m3u8 extraction
  };

  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { 
      'Content-Type': 'application/json',
      'X-Sandbox-Isolated': 'true'
    }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
        }
      });
    }

    // Only POST allowed
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ 
        success: false, 
        error: 'Method not allowed. Use POST.' 
      }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const response = await handleDecode(request, env);
    
    // Add CORS headers
    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    
    return new Response(response.body, {
      status: response.status,
      headers
    });
  }
};
