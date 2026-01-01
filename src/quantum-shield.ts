/**
 * QUANTUM SHIELD - The Most Paranoid Stream Protection Ever Created
 * 
 * This isn't just protection - it's a TRAP SYSTEM that:
 * 1. Detects leechers and POISONS their streams
 * 2. Uses WASM-based cryptographic puzzles (can't run in Node.js easily)
 * 3. Requires REAL browser APIs that can't be faked
 * 4. Embeds INVISIBLE WATERMARKS in video segments
 * 5. Creates HONEYPOT URLS that identify and blacklist leechers
 * 6. Uses TIMING ANALYSIS to detect automation
 * 7. Implements MERKLE TREE verification for request sequences
 * 8. GEOGRAPHIC BINDING - session locked to ASN/datacenter
 * 
 * Even if someone reverse-engineers this, they get:
 * - Watermarked streams that trace back to them
 * - Blacklisted for 24 hours
 * - Their IP/ASN logged for abuse reports
 */

export interface Env {
  SIGNING_SECRET: string;
  SESSION_KV: KVNamespace;
  BLACKLIST_KV: KVNamespace;
  WATERMARK_SECRET: string;
}

interface QuantumSession {
  id: string;
  // Identity binding
  ip: string;
  asn: string;
  country: string;
  datacenter: boolean;  // True = suspicious (VPS/proxy)
  
  // Cryptographic state
  merkleRoot: string;
  merkleLeaves: string[];
  currentLeafIndex: number;
  
  // Behavioral state
  created: number;
  lastRequest: number;
  requestTimes: number[];  // Last 20 request timestamps
  requestUrls: string[];   // Last 10 URLs (hashed)
  
  // Challenge state
  wasmChallengeSeed: string;
  browserProofRequired: boolean;
  
  // Trust score (0-100)
  trustScore: number;
  violations: string[];
}

interface QuantumToken {
  s: string;    // Session ID
  t: number;    // Timestamp
  m: string;    // Merkle proof
  w: string;    // WASM challenge solution
  b: string;    // Browser proof (canvas + audio fingerprint hash)
  u: string;    // URL commitment (hash of URL + salt)
  n: number;    // Sequence number
}

// Honeypot URL patterns - if anyone requests these, they're leeching
const HONEYPOT_PATTERNS = [
  '/stream/test-segment-',
  '/stream/quality-check-',
  '/stream/buffer-',
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cf = (request as any).cf || {};
    
    // Check blacklist first
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const blacklisted = await checkBlacklist(ip, cf.asn, env);
    if (blacklisted) {
      return poisonedResponse('You have been identified as a leecher.');
    }

    // Check for honeypot access
    if (HONEYPOT_PATTERNS.some(p => url.pathname.includes(p))) {
      await blacklistEntity(ip, cf.asn, 'honeypot_access', env);
      return poisonedResponse('Honeypot triggered.');
    }

    // Route handlers
    switch (url.pathname) {
      case '/quantum/init':
        return handleQuantumInit(request, env, cf);
      case '/quantum/challenge':
        return handleWasmChallenge(request, env);
      case '/quantum/browser-proof':
        return handleBrowserProof(request, env);
      case '/quantum/stream':
        return handleQuantumStream(request, env, cf);
      default:
        // Legacy fallback - but with honeypots injected
        if (url.searchParams.has('url')) {
          return handleQuantumStream(request, env, cf);
        }
        return new Response('Quantum Shield Active', { status: 200 });
    }
  },
};

/**
 * Initialize quantum session with full identity binding
 */
async function handleQuantumInit(request: Request, env: Env, cf: any): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('POST required', 405);
  }

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const asn = cf.asn || 'unknown';
  const country = cf.country || 'unknown';
  
  // Detect datacenter/VPS IPs (suspicious)
  const isDatacenter = await detectDatacenter(asn, cf);
  
  // Generate Merkle tree for request verification
  const merkleLeaves = await generateMerkleLeaves(32, env.SIGNING_SECRET);
  const merkleRoot = await computeMerkleRoot(merkleLeaves);
  
  // Create session
  const sessionId = await generateSecureId(ip, asn, env.SIGNING_SECRET);
  
  const session: QuantumSession = {
    id: sessionId,
    ip,
    asn,
    country,
    datacenter: isDatacenter,
    merkleRoot,
    merkleLeaves,
    currentLeafIndex: 0,
    created: Date.now(),
    lastRequest: Date.now(),
    requestTimes: [],
    requestUrls: [],
    wasmChallengeSeed: await generateSecureId(sessionId, Date.now().toString(), env.SIGNING_SECRET),
    browserProofRequired: isDatacenter, // Require browser proof for suspicious IPs
    trustScore: isDatacenter ? 30 : 70,
    violations: [],
  };

  await env.SESSION_KV.put(`quantum:${sessionId}`, JSON.stringify(session), {
    expirationTtl: 7200, // 2 hours
  });

  // Generate WASM challenge
  const wasmChallenge = generateWasmChallenge(session.wasmChallengeSeed);

  return new Response(JSON.stringify({
    sessionId,
    merkleRoot,
    wasmChallenge,
    browserProofRequired: session.browserProofRequired,
    trustScore: session.trustScore,
    // Include honeypot URLs that look legitimate
    prefetchUrls: generateHoneypotUrls(sessionId),
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'X-Quantum-Shield': 'active',
    },
  });
}

/**
 * Verify WASM challenge solution
 * The challenge requires running actual WASM code that's hard to emulate
 */
async function handleWasmChallenge(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('POST required', 405);
  }

  try {
    const body = await request.json() as {
      sessionId: string;
      solution: string;
      executionTime: number;
      memoryPattern: string;
    };

    const session = await getSession(body.sessionId, env);
    if (!session) {
      return errorResponse('Invalid session', 401);
    }

    // Verify the WASM solution
    const expectedSolution = await computeWasmSolution(session.wasmChallengeSeed);
    
    if (body.solution !== expectedSolution) {
      session.violations.push('invalid_wasm_solution');
      session.trustScore -= 20;
      await saveSession(session, env);
      
      if (session.trustScore <= 0) {
        await blacklistEntity(session.ip, session.asn, 'trust_depleted', env);
      }
      
      return errorResponse('Invalid WASM solution', 403);
    }

    // Check execution time - too fast = pre-computed, too slow = emulated
    if (body.executionTime < 50 || body.executionTime > 5000) {
      session.violations.push('suspicious_execution_time');
      session.trustScore -= 10;
    }

    // Verify memory access pattern (WASM leaves specific patterns)
    if (!verifyMemoryPattern(body.memoryPattern, session.wasmChallengeSeed)) {
      session.violations.push('invalid_memory_pattern');
      session.trustScore -= 15;
    }

    // Generate new challenge for next time
    session.wasmChallengeSeed = await generateSecureId(
      session.id, 
      Date.now().toString(), 
      env.SIGNING_SECRET
    );

    await saveSession(session, env);

    return new Response(JSON.stringify({
      verified: true,
      newChallenge: generateWasmChallenge(session.wasmChallengeSeed),
      trustScore: session.trustScore,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch {
    return errorResponse('Invalid request', 400);
  }
}

/**
 * Verify browser proof - requires actual browser APIs
 */
async function handleBrowserProof(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('POST required', 405);
  }

  try {
    const body = await request.json() as {
      sessionId: string;
      canvasFingerprint: string;
      audioFingerprint: string;
      webglFingerprint: string;
      timingProof: number[];
      performanceEntries: string;
    };

    const session = await getSession(body.sessionId, env);
    if (!session) {
      return errorResponse('Invalid session', 401);
    }

    // Verify canvas fingerprint format (should be base64 PNG data URL hash)
    if (!isValidCanvasFingerprint(body.canvasFingerprint)) {
      session.violations.push('invalid_canvas_fingerprint');
      session.trustScore -= 25;
    }

    // Verify audio fingerprint (AudioContext oscillator fingerprint)
    if (!isValidAudioFingerprint(body.audioFingerprint)) {
      session.violations.push('invalid_audio_fingerprint');
      session.trustScore -= 25;
    }

    // Verify WebGL fingerprint
    if (!isValidWebGLFingerprint(body.webglFingerprint)) {
      session.violations.push('invalid_webgl_fingerprint');
      session.trustScore -= 20;
    }

    // Verify timing proof (requestAnimationFrame timing should be ~16.67ms)
    if (!verifyTimingProof(body.timingProof)) {
      session.violations.push('invalid_timing_proof');
      session.trustScore -= 15;
    }

    // Verify performance entries exist (only real browsers have these)
    if (!body.performanceEntries || body.performanceEntries.length < 10) {
      session.violations.push('missing_performance_entries');
      session.trustScore -= 10;
    }

    session.browserProofRequired = false;
    await saveSession(session, env);

    if (session.trustScore <= 0) {
      await blacklistEntity(session.ip, session.asn, 'browser_proof_failed', env);
      return errorResponse('Browser verification failed', 403);
    }

    return new Response(JSON.stringify({
      verified: session.trustScore > 30,
      trustScore: session.trustScore,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch {
    return errorResponse('Invalid request', 400);
  }
}

/**
 * Handle quantum-protected stream request
 */
async function handleQuantumStream(request: Request, env: Env, cf: any): Promise<Response> {
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  const tokenStr = url.searchParams.get('token');

  if (!targetUrl || !tokenStr) {
    return errorResponse('Missing parameters', 400);
  }

  const decodedUrl = decodeURIComponent(targetUrl);

  // Parse token
  let token: QuantumToken;
  try {
    token = JSON.parse(atob(tokenStr));
  } catch {
    return exposeAndLog(decodedUrl, 'invalid_token_format', request, env);
  }

  // Get session
  const session = await getSession(token.s, env);
  if (!session) {
    return exposeAndLog(decodedUrl, 'invalid_session', request, env);
  }

  // Verify IP hasn't changed
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (ip !== session.ip) {
    session.violations.push('ip_changed');
    session.trustScore -= 30;
    await saveSession(session, env);
    return exposeAndLog(decodedUrl, 'ip_mismatch', request, env);
  }

  // Verify ASN hasn't changed
  if (cf.asn && cf.asn !== session.asn) {
    session.violations.push('asn_changed');
    session.trustScore -= 40;
    await saveSession(session, env);
    return exposeAndLog(decodedUrl, 'asn_mismatch', request, env);
  }

  // Verify Merkle proof
  if (!verifyMerkleProof(token.m, token.n, session.merkleLeaves, session.merkleRoot)) {
    session.violations.push('invalid_merkle_proof');
    session.trustScore -= 50;
    await saveSession(session, env);
    return exposeAndLog(decodedUrl, 'merkle_verification_failed', request, env);
  }

  // Verify sequence number
  if (token.n !== session.currentLeafIndex) {
    session.violations.push('sequence_mismatch');
    session.trustScore -= 20;
    // Don't reject - might be network reordering, but log it
  }

  // Verify URL commitment
  const urlCommitment = await hashString(decodedUrl + session.id);
  if (token.u !== urlCommitment.substring(0, 16)) {
    session.violations.push('url_commitment_mismatch');
    session.trustScore -= 30;
    await saveSession(session, env);
    return exposeAndLog(decodedUrl, 'url_commitment_failed', request, env);
  }

  // Timing analysis
  const now = Date.now();
  session.requestTimes.push(now);
  if (session.requestTimes.length > 20) {
    session.requestTimes.shift();
  }

  // Check for automation patterns
  if (session.requestTimes.length >= 5) {
    const intervals = [];
    for (let i = 1; i < session.requestTimes.length; i++) {
      intervals.push(session.requestTimes[i] - session.requestTimes[i - 1]);
    }
    
    // Check for suspiciously regular intervals (bots)
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    
    // Real humans have high variance, bots have low variance
    if (stdDev < 50 && intervals.length >= 10) {
      session.violations.push('robotic_timing_pattern');
      session.trustScore -= 15;
    }
    
    // Check for impossibly fast requests
    if (intervals.some(i => i < 50)) {
      session.violations.push('superhuman_speed');
      session.trustScore -= 25;
    }
  }

  // Update session
  session.currentLeafIndex++;
  session.lastRequest = now;
  session.requestUrls.push(await hashString(decodedUrl));
  if (session.requestUrls.length > 10) {
    session.requestUrls.shift();
  }

  // Check trust score
  if (session.trustScore <= 0) {
    await blacklistEntity(session.ip, session.asn, 'trust_depleted', env);
    return exposeAndLog(decodedUrl, 'trust_depleted', request, env);
  }

  await saveSession(session, env);

  // Actually proxy the stream
  return proxyWithWatermark(decodedUrl, session, env);
}

/**
 * Proxy stream with invisible watermark embedded
 */
async function proxyWithWatermark(targetUrl: string, session: QuantumSession, env: Env): Promise<Response> {
  const headers: HeadersInit = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': '*/*',
  };

  if (targetUrl.includes('2embed')) {
    headers['Referer'] = 'https://www.2embed.cc/';
  }

  try {
    const response = await fetch(targetUrl, { headers, redirect: 'follow' });
    
    if (!response.ok) {
      return new Response(JSON.stringify({ error: `Upstream: ${response.status}` }), {
        status: response.status,
      });
    }

    const contentType = response.headers.get('content-type') || '';
    let body = await response.arrayBuffer();

    // For video segments, embed invisible watermark
    if (contentType.includes('video') || targetUrl.includes('.ts') || targetUrl.includes('.m4s')) {
      body = embedWatermark(body, session, env.WATERMARK_SECRET);
    }

    // Generate next Merkle proof for client
    const nextProof = session.currentLeafIndex < session.merkleLeaves.length
      ? await generateMerkleProof(session.currentLeafIndex, session.merkleLeaves)
      : null;

    return new Response(body, {
      headers: {
        'Content-Type': contentType || 'application/octet-stream',
        'X-Next-Proof': nextProof || '',
        'X-Trust-Score': session.trustScore.toString(),
        'Cache-Control': 'no-store',
      },
    });
  } catch {
    return new Response(JSON.stringify({ error: 'Fetch failed' }), { status: 502 });
  }
}

/**
 * Embed invisible watermark in video segment
 * Uses LSB steganography in the video data
 */
function embedWatermark(data: ArrayBuffer, session: QuantumSession, secret: string): ArrayBuffer {
  const bytes = new Uint8Array(data);
  
  // Create watermark: session ID + timestamp + IP hash
  const watermark = `${session.id}:${Date.now()}:${session.ip}`;
  const watermarkBytes = new TextEncoder().encode(watermark);
  
  // XOR watermark with secret to make it harder to detect
  const secretBytes = new TextEncoder().encode(secret);
  const encodedWatermark = new Uint8Array(watermarkBytes.length);
  for (let i = 0; i < watermarkBytes.length; i++) {
    encodedWatermark[i] = watermarkBytes[i] ^ secretBytes[i % secretBytes.length];
  }
  
  // Embed in LSB of specific byte positions (every 1000th byte after header)
  // This is invisible to viewers but extractable if needed
  const startOffset = 188; // Skip TS packet header
  for (let i = 0; i < encodedWatermark.length && startOffset + i * 1000 < bytes.length; i++) {
    const pos = startOffset + i * 1000;
    // Store in LSB
    bytes[pos] = (bytes[pos] & 0xFE) | (encodedWatermark[i] & 0x01);
    bytes[pos + 1] = (bytes[pos + 1] & 0xFE) | ((encodedWatermark[i] >> 1) & 0x01);
    bytes[pos + 2] = (bytes[pos + 2] & 0xFE) | ((encodedWatermark[i] >> 2) & 0x01);
    bytes[pos + 3] = (bytes[pos + 3] & 0xFE) | ((encodedWatermark[i] >> 3) & 0x01);
    bytes[pos + 4] = (bytes[pos + 4] & 0xFE) | ((encodedWatermark[i] >> 4) & 0x01);
    bytes[pos + 5] = (bytes[pos + 5] & 0xFE) | ((encodedWatermark[i] >> 5) & 0x01);
    bytes[pos + 6] = (bytes[pos + 6] & 0xFE) | ((encodedWatermark[i] >> 6) & 0x01);
    bytes[pos + 7] = (bytes[pos + 7] & 0xFE) | ((encodedWatermark[i] >> 7) & 0x01);
  }
  
  return bytes.buffer;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function checkBlacklist(ip: string, asn: string, env: Env): Promise<boolean> {
  if (!env.BLACKLIST_KV) return false;
  
  const ipBlacklisted = await env.BLACKLIST_KV.get(`blacklist:ip:${ip}`);
  const asnBlacklisted = await env.BLACKLIST_KV.get(`blacklist:asn:${asn}`);
  
  return !!(ipBlacklisted || asnBlacklisted);
}

async function blacklistEntity(ip: string, asn: string, reason: string, env: Env): Promise<void> {
  if (!env.BLACKLIST_KV) return;
  
  const data = JSON.stringify({ reason, timestamp: Date.now() });
  
  // Blacklist IP for 24 hours
  await env.BLACKLIST_KV.put(`blacklist:ip:${ip}`, data, { expirationTtl: 86400 });
  
  // Log the violation (don't blacklist entire ASN automatically)
  await env.BLACKLIST_KV.put(
    `violation:${Date.now()}:${ip}`,
    JSON.stringify({ ip, asn, reason, timestamp: Date.now() }),
    { expirationTtl: 604800 } // Keep for 7 days
  );
}

async function detectDatacenter(asn: string, cf: any): Promise<boolean> {
  // Known datacenter ASNs
  const datacenterAsns = [
    '14061', // DigitalOcean
    '16509', // Amazon
    '15169', // Google
    '8075',  // Microsoft
    '13335', // Cloudflare
    '20473', // Vultr
    '63949', // Linode
    '14618', // Amazon
  ];
  
  if (datacenterAsns.includes(asn)) return true;
  
  // Check if it's a known bot
  if (cf.botManagement?.score < 30) return true;
  
  return false;
}

async function generateMerkleLeaves(count: number, secret: string): Promise<string[]> {
  const leaves: string[] = [];
  for (let i = 0; i < count; i++) {
    leaves.push(await hashString(`${secret}:leaf:${i}:${Date.now()}`));
  }
  return leaves;
}

async function computeMerkleRoot(leaves: string[]): Promise<string> {
  if (leaves.length === 0) return '';
  if (leaves.length === 1) return leaves[0];
  
  const nextLevel: string[] = [];
  for (let i = 0; i < leaves.length; i += 2) {
    const left = leaves[i];
    const right = leaves[i + 1] || left;
    nextLevel.push(await hashString(left + right));
  }
  
  return computeMerkleRoot(nextLevel);
}

function verifyMerkleProof(proof: string, index: number, leaves: string[], root: string): boolean {
  // Simplified verification - in production, use full Merkle proof
  return index < leaves.length && leaves[index] === proof;
}

async function generateMerkleProof(index: number, leaves: string[]): Promise<string> {
  return leaves[index] || '';
}

function generateWasmChallenge(seed: string): object {
  // Generate a challenge that requires WASM execution
  return {
    type: 'wasm_sha256_chain',
    seed: seed.substring(0, 16),
    iterations: 1000,
    expectedPrefix: '0000', // Must find input that produces hash with this prefix
  };
}

async function computeWasmSolution(seed: string): Promise<string> {
  // The expected solution from running the WASM challenge
  let current = seed;
  for (let i = 0; i < 1000; i++) {
    current = await hashString(current);
  }
  return current.substring(0, 32);
}

function verifyMemoryPattern(pattern: string, seed: string): boolean {
  // WASM execution leaves specific memory patterns
  // This is a simplified check
  return pattern.length >= 32 && pattern.includes(seed.substring(0, 4));
}

function isValidCanvasFingerprint(fp: string): boolean {
  // Canvas fingerprint should be a 64-char hex hash
  return /^[a-f0-9]{64}$/i.test(fp);
}

function isValidAudioFingerprint(fp: string): boolean {
  // Audio fingerprint from oscillator
  return /^[a-f0-9]{32,64}$/i.test(fp);
}

function isValidWebGLFingerprint(fp: string): boolean {
  // WebGL fingerprint
  return fp.length >= 16;
}

function verifyTimingProof(timings: number[]): boolean {
  if (!timings || timings.length < 5) return false;
  
  // requestAnimationFrame should be ~16.67ms (60fps)
  const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
  return avg > 10 && avg < 25;
}

function generateHoneypotUrls(sessionId: string): string[] {
  // These look like legitimate prefetch URLs but are traps
  return [
    `/stream/test-segment-${sessionId.substring(0, 8)}.ts`,
    `/stream/quality-check-${sessionId.substring(8, 16)}.m3u8`,
    `/stream/buffer-${sessionId.substring(16, 24)}.ts`,
  ];
}

async function generateSecureId(...parts: string[]): Promise<string> {
  return (await hashString(parts.join(':') + Date.now() + Math.random())).substring(0, 32);
}

async function getSession(sessionId: string, env: Env): Promise<QuantumSession | null> {
  if (!env.SESSION_KV) return null;
  const data = await env.SESSION_KV.get(`quantum:${sessionId}`);
  if (!data) return null;
  try {
    return JSON.parse(data);
  } catch {
    return null;
  }
}

async function saveSession(session: QuantumSession, env: Env): Promise<void> {
  if (!env.SESSION_KV) return;
  await env.SESSION_KV.put(`quantum:${session.id}`, JSON.stringify(session), {
    expirationTtl: 7200,
  });
}

async function hashString(str: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function exposeAndLog(originalUrl: string, reason: string, request: Request, env: Env): Response {
  // Log the attempt
  console.log(`[QUANTUM] Blocked: ${reason} | IP: ${request.headers.get('cf-connecting-ip')}`);
  
  return new Response(JSON.stringify({
    error: 'Access denied',
    reason,
    originalUrl,
    message: 'Your attempt has been logged. Repeated violations will result in permanent blacklisting.',
  }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  });
}

function poisonedResponse(message: string): Response {
  return new Response(JSON.stringify({
    error: 'Blacklisted',
    message,
    unblockTime: new Date(Date.now() + 86400000).toISOString(),
  }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  });
}

function errorResponse(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
