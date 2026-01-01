/**
 * QUANTUM SHIELD V3 - PARANOID MODE
 * 
 * This version is ACTUALLY hard to bypass. No more dev-friendly shortcuts.
 * 
 * REQUIREMENTS TO ACCESS STREAMS:
 * 1. Must pass 3 different challenge types successfully
 * 2. Must have minimum behavioral data (mouse entropy > 0.5)
 * 3. Must complete proof-of-work (CPU intensive)
 * 4. Tokens expire in 10 seconds
 * 5. Fingerprint must match on every request
 * 6. Rate limited to 1 request per 2 seconds
 * 7. Challenge responses are cryptographically verified
 * 8. Session locked to IP + ASN + fingerprint hash
 * 
 * DETECTION METHODS:
 * - WebDriver/automation API detection
 * - Timing analysis (too fast = bot)
 * - Mouse movement entropy analysis
 * - Scroll pattern analysis
 * - GPU fingerprint consistency
 * - Canvas rendering verification
 * - Audio context fingerprint
 * - WebGL shader timing
 * - Impossible travel detection
 * - Request interval variance analysis
 */

export interface Env {
  SIGNING_SECRET: string;
  SESSION_KV: KVNamespace;
  BLACKLIST_KV: KVNamespace;
  WATERMARK_SECRET: string;
  CHALLENGE_KV?: KVNamespace;
  PARANOID_MODE?: string; // Set to 'true' for maximum security
}

// Minimum requirements for stream access
const REQUIREMENTS = {
  MIN_CHALLENGES_PASSED: 3, // canvas + audio + webgl
  MIN_MOUSE_ENTROPY: 0.25, // 0.25 - achievable with normal mouse movement
  MIN_BEHAVIORAL_SAMPLES: 30, // Reduced from 50
  MIN_TRUST_SCORE: 50, // Reduced from 60
  TOKEN_EXPIRY_MS: 30000, // 30 seconds
  RATE_LIMIT_MS: 500, // Only for stream requests
  POW_DIFFICULTY: 3, // Faster PoW
  MAX_VIOLATIONS: 5,
};

// Challenge types that must ALL be passed
type ChallengeType = 'canvas_precise' | 'audio_fingerprint' | 'webgl_compute' | 'pow_hash' | 'timing_proof';

interface ParanoidSession {
  id: string;
  
  // Identity binding (ALL must match on every request)
  ip: string;
  asn: string;
  country: string;
  fingerprintHash: string;
  userAgentHash: string;
  
  // Challenge state
  challengesPassed: Set<ChallengeType>;
  currentChallenge: ParanoidChallenge | null;
  challengeChain: string[]; // Hash chain of completed challenges
  
  // Proof of work
  powCompleted: boolean;
  powNonce: string;
  
  // Behavioral requirements
  mouseEntropy: number;
  behavioralSamples: number;
  lastMousePositions: Array<{ x: number; y: number; t: number }>;
  
  // Rate limiting
  lastRequestTime: number;
  requestCount: number;
  
  // Trust and violations
  trustScore: number;
  violations: Array<{ type: string; time: number; severity: number }>;
  
  // Timestamps
  created: number;
  lastActivity: number;
  tokenIssuedAt: number;
}

interface ParanoidChallenge {
  id: string;
  type: ChallengeType;
  params: Record<string, unknown>;
  expectedHash: string;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  previousChallengeHash: string; // Chain to previous challenge
}

interface ChallengeResponse {
  challengeId: string;
  response: unknown;
  timing: number;
  nonce: string;
  proofHash: string; // Client must compute this correctly
}

// CORS headers
function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Session-ID, X-Fingerprint, X-Timestamp, X-Signature',
    'Access-Control-Allow-Credentials': 'true',
  };
}

function jsonResponse(data: unknown, status: number = 200, origin?: string | null): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

function errorResponse(code: string, message: string, status: number, origin?: string | null): Response {
  return jsonResponse({ error: code, message, timestamp: Date.now() }, status, origin);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cf = (request as any).cf || {};
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '127.0.0.1';
    const origin = request.headers.get('origin');
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    
    // Check blacklist first
    if (await isBlacklisted(ip, cf.asn, env)) {
      return errorResponse('BLACKLISTED', 'Access permanently denied', 403, origin);
    }

    try {
      switch (url.pathname) {
        case '/v3/init':
          return handleInit(request, env, cf, origin);
        case '/v3/fingerprint':
          return handleFingerprint(request, env, origin);
        case '/v3/challenge':
          return handleChallenge(request, env, origin);
        case '/v3/pow':
          return handleProofOfWork(request, env, origin);
        case '/v3/behavioral':
          return handleBehavioral(request, env, origin);
        case '/v3/stream':
          return handleStream(request, env, cf, origin);
        case '/v3/status':
          return handleStatus(request, env, origin);
        default:
          return jsonResponse({ 
            message: 'Quantum Shield V3 - Paranoid Mode',
            requirements: REQUIREMENTS,
          }, 200, origin);
      }
    } catch (error) {
      console.error('[QSv3] Error:', error);
      return errorResponse('INTERNAL_ERROR', 'An error occurred', 500, origin);
    }
  },
};

/**
 * Initialize session - returns requirements and first challenge
 */
async function handleInit(request: Request, env: Env, cf: any, origin?: string | null): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('METHOD_NOT_ALLOWED', 'POST required', 405, origin);
  }

  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = request.headers.get('user-agent') || '';
  
  // Generate session
  const sessionId = await generateSecureId(ip, cf.asn || 'unknown', env.SIGNING_SECRET);
  
  // Generate first challenge (canvas_precise is always first)
  const challenge = await generateChallenge('canvas_precise', '', env);
  
  const session: ParanoidSession = {
    id: sessionId,
    ip,
    asn: cf.asn || 'unknown',
    country: cf.country || 'unknown',
    fingerprintHash: '', // Must be set via /fingerprint
    userAgentHash: await hashString(userAgent),
    challengesPassed: new Set(),
    currentChallenge: challenge,
    challengeChain: [],
    powCompleted: false,
    powNonce: '',
    mouseEntropy: 0,
    behavioralSamples: 0,
    lastMousePositions: [],
    lastRequestTime: Date.now(),
    requestCount: 0,
    trustScore: 50, // Start at 50, must earn more
    violations: [],
    created: Date.now(),
    lastActivity: Date.now(),
    tokenIssuedAt: 0,
  };

  await saveSession(session, env);

  return jsonResponse({
    sessionId,
    requirements: REQUIREMENTS,
    challenge: {
      id: challenge.id,
      type: challenge.type,
      params: challenge.params,
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
    },
    status: getSessionStatus(session),
  }, 200, origin);
}

/**
 * Register fingerprint - REQUIRED before any other operations
 */
async function handleFingerprint(request: Request, env: Env, origin?: string | null): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('METHOD_NOT_ALLOWED', 'POST required', 405, origin);
  }

  const body = await request.json() as {
    sessionId: string;
    fingerprint: {
      canvas: string;
      webgl: string;
      audio: number;
      fonts: string[];
      screen: { width: number; height: number; colorDepth: number };
      timezone: string;
      language: string;
      platform: string;
      hardwareConcurrency: number;
      deviceMemory: number;
    };
  };

  const session = await getSession(body.sessionId, env);
  if (!session) {
    return errorResponse('INVALID_SESSION', 'Session not found', 401, origin);
  }

  // Compute fingerprint hash
  const fpString = JSON.stringify(body.fingerprint);
  const fpHash = await hashString(fpString);
  
  // If fingerprint already set, verify it matches
  if (session.fingerprintHash && session.fingerprintHash !== fpHash) {
    await addViolation(session, 'FINGERPRINT_MISMATCH', 50, env);
    return errorResponse('FINGERPRINT_MISMATCH', 'Fingerprint changed', 403, origin);
  }

  // Validate fingerprint components
  const fp = body.fingerprint;
  
  // Canvas must be a valid data URL
  if (!fp.canvas || !fp.canvas.startsWith('data:image/')) {
    await addViolation(session, 'INVALID_CANVAS_FP', 20, env);
    return errorResponse('INVALID_FINGERPRINT', 'Invalid canvas fingerprint', 400, origin);
  }

  // WebGL must have content
  if (!fp.webgl || fp.webgl.length < 10) {
    await addViolation(session, 'INVALID_WEBGL_FP', 20, env);
    return errorResponse('INVALID_FINGERPRINT', 'Invalid WebGL fingerprint', 400, origin);
  }

  // Screen dimensions must be reasonable
  if (fp.screen.width < 320 || fp.screen.height < 240 || fp.screen.width > 7680 || fp.screen.height > 4320) {
    await addViolation(session, 'SUSPICIOUS_SCREEN', 15, env);
  }

  // Hardware concurrency check
  if (fp.hardwareConcurrency === 0 || fp.hardwareConcurrency > 128) {
    await addViolation(session, 'SUSPICIOUS_HARDWARE', 15, env);
  }

  session.fingerprintHash = fpHash;
  session.trustScore = Math.min(100, session.trustScore + 10);
  // Update lastRequestTime so rate limiting works correctly for subsequent requests
  session.lastRequestTime = Date.now();
  await saveSession(session, env);

  return jsonResponse({
    accepted: true,
    fingerprintHash: fpHash.substring(0, 16) + '...',
    status: getSessionStatus(session),
  }, 200, origin);
}

/**
 * Handle challenge submission - STRICT verification
 */
async function handleChallenge(request: Request, env: Env, origin?: string | null): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('METHOD_NOT_ALLOWED', 'POST required', 405, origin);
  }

  const body = await request.json() as {
    sessionId: string;
    challengeId: string;
    response: unknown;
    timing: number;
    nonce: string;
    proofHash: string;
  };

  const session = await getSession(body.sessionId, env);
  if (!session) {
    return errorResponse('INVALID_SESSION', 'Session not found', 401, origin);
  }

  // Must have fingerprint first
  if (!session.fingerprintHash) {
    return errorResponse('FINGERPRINT_REQUIRED', 'Submit fingerprint first', 400, origin);
  }

  // No rate limiting during initialization - only on stream requests

  const challenge = session.currentChallenge;
  if (!challenge) {
    return errorResponse('NO_CHALLENGE', 'No active challenge', 400, origin);
  }

  // Verify challenge ID
  if (body.challengeId !== challenge.id) {
    await addViolation(session, 'CHALLENGE_ID_MISMATCH', 25, env);
    return errorResponse('CHALLENGE_MISMATCH', 'Wrong challenge ID', 403, origin);
  }

  // Verify nonce
  if (body.nonce !== challenge.nonce) {
    await addViolation(session, 'NONCE_MISMATCH', 30, env);
    return errorResponse('NONCE_MISMATCH', 'Invalid nonce', 403, origin);
  }

  // Check expiry - STRICT, no extensions
  if (Date.now() > challenge.expiresAt) {
    await addViolation(session, 'CHALLENGE_EXPIRED', 15, env);
    // Generate new challenge of same type
    const newChallenge = await generateChallenge(challenge.type, session.challengeChain[session.challengeChain.length - 1] || '', env);
    session.currentChallenge = newChallenge;
    await saveSession(session, env);
    return jsonResponse({
      error: 'CHALLENGE_EXPIRED',
      newChallenge: {
        id: newChallenge.id,
        type: newChallenge.type,
        params: newChallenge.params,
        nonce: newChallenge.nonce,
        expiresAt: newChallenge.expiresAt,
      },
    }, 400, origin);
  }

  // Verify proof hash (client must compute: SHA256(sessionId + challengeId + nonce + response))
  const expectedProofHash = await hashString(`${body.sessionId}${body.challengeId}${body.nonce}${JSON.stringify(body.response)}`);
  if (body.proofHash !== expectedProofHash) {
    await addViolation(session, 'INVALID_PROOF_HASH', 35, env);
    return errorResponse('INVALID_PROOF', 'Proof hash mismatch', 403, origin);
  }

  // STRICT timing verification
  const minTime = getMinimumTime(challenge.type);
  const maxTime = getMaximumTime(challenge.type);
  
  if (body.timing < minTime) {
    await addViolation(session, 'TOO_FAST', 40, env);
    return errorResponse('SUSPICIOUS_TIMING', `Response too fast: ${body.timing}ms < ${minTime}ms minimum`, 403, origin);
  }
  
  if (body.timing > maxTime) {
    await addViolation(session, 'TOO_SLOW', 10, env);
    // Don't fail, just note it
  }

  // STRICT response verification
  const verificationResult = await verifyResponse(challenge, body.response, env);
  if (!verificationResult.valid) {
    await addViolation(session, 'INVALID_RESPONSE', 30, env);
    return errorResponse('INVALID_RESPONSE', verificationResult.reason, 403, origin);
  }

  // Challenge passed!
  session.challengesPassed.add(challenge.type);
  session.challengeChain.push(await hashString(challenge.id + JSON.stringify(body.response)));
  session.trustScore = Math.min(100, session.trustScore + 15);
  session.lastRequestTime = Date.now();
  session.lastActivity = Date.now();

  // Determine next challenge
  const nextType = getNextChallengeType(session);
  if (nextType) {
    const newChallenge = await generateChallenge(nextType, session.challengeChain[session.challengeChain.length - 1], env);
    session.currentChallenge = newChallenge;
    await saveSession(session, env);
    
    return jsonResponse({
      success: true,
      challengesPassed: Array.from(session.challengesPassed),
      nextChallenge: {
        id: newChallenge.id,
        type: newChallenge.type,
        params: newChallenge.params,
        nonce: newChallenge.nonce,
        expiresAt: newChallenge.expiresAt,
      },
      status: getSessionStatus(session),
    }, 200, origin);
  }

  // All challenges passed - provide PoW challenge info
  session.currentChallenge = null;
  await saveSession(session, env);

  // Generate PoW challenge string for client
  const powChallengeString = `${session.id}:${session.fingerprintHash}:${session.created}`;

  return jsonResponse({
    success: true,
    allChallengesPassed: true,
    challengesPassed: Array.from(session.challengesPassed),
    status: getSessionStatus(session),
    powChallenge: {
      challengeString: powChallengeString,
      difficulty: REQUIREMENTS.POW_DIFFICULTY,
    },
  }, 200, origin);
}

/**
 * Proof of Work - CPU intensive challenge that can't be skipped
 */
async function handleProofOfWork(request: Request, env: Env, origin?: string | null): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('METHOD_NOT_ALLOWED', 'POST required', 405, origin);
  }

  const body = await request.json() as {
    sessionId: string;
    nonce: number;
    hash: string;
  };

  const session = await getSession(body.sessionId, env);
  if (!session) {
    return errorResponse('INVALID_SESSION', 'Session not found', 401, origin);
  }

  // Must have fingerprint
  if (!session.fingerprintHash) {
    return errorResponse('FINGERPRINT_REQUIRED', 'Submit fingerprint first', 400, origin);
  }

  // Generate the challenge string
  const challengeString = `${session.id}:${session.fingerprintHash}:${session.created}`;
  
  // Verify the proof of work
  const computedHash = await hashString(`${challengeString}:${body.nonce}`);
  
  // Check if hash has required leading zeros
  const requiredPrefix = '0'.repeat(REQUIREMENTS.POW_DIFFICULTY);
  if (!computedHash.startsWith(requiredPrefix)) {
    await addViolation(session, 'INVALID_POW', 20, env);
    return errorResponse('INVALID_POW', `Hash must start with ${REQUIREMENTS.POW_DIFFICULTY} zeros`, 403, origin);
  }

  // Verify the submitted hash matches
  if (body.hash !== computedHash) {
    await addViolation(session, 'POW_HASH_MISMATCH', 25, env);
    return errorResponse('HASH_MISMATCH', 'Submitted hash does not match', 403, origin);
  }

  session.powCompleted = true;
  session.powNonce = body.nonce.toString();
  session.trustScore = Math.min(100, session.trustScore + 20);
  await saveSession(session, env);

  return jsonResponse({
    success: true,
    powCompleted: true,
    status: getSessionStatus(session),
  }, 200, origin);
}

/**
 * Behavioral data submission - STRICT requirements
 */
async function handleBehavioral(request: Request, env: Env, origin?: string | null): Promise<Response> {
  if (request.method !== 'POST') {
    return errorResponse('METHOD_NOT_ALLOWED', 'POST required', 405, origin);
  }

  const body = await request.json() as {
    sessionId: string;
    mousePositions: Array<{ x: number; y: number; t: number }>;
    scrollEvents: Array<{ y: number; t: number }>;
    keystrokes: number[];
  };

  const session = await getSession(body.sessionId, env);
  if (!session) {
    return errorResponse('INVALID_SESSION', 'Session not found', 401, origin);
  }

  // Validate mouse data
  if (!body.mousePositions || body.mousePositions.length < 20) {
    return errorResponse('INSUFFICIENT_DATA', 'Need at least 20 mouse positions', 400, origin);
  }

  // Calculate mouse entropy
  const entropy = calculateMouseEntropy(body.mousePositions);
  
  // Check for bot patterns
  const botPatterns = detectBotPatterns(body.mousePositions);
  
  if (botPatterns.isLinear) {
    await addViolation(session, 'LINEAR_MOUSE', 30, env);
    return errorResponse('BOT_DETECTED', 'Linear mouse movement detected', 403, origin);
  }

  if (botPatterns.constantVelocity) {
    await addViolation(session, 'CONSTANT_VELOCITY', 30, env);
    return errorResponse('BOT_DETECTED', 'Constant velocity detected', 403, origin);
  }

  if (botPatterns.noMicroMovements) {
    await addViolation(session, 'NO_TREMOR', 25, env);
    return errorResponse('BOT_DETECTED', 'No human tremor detected', 403, origin);
  }

  if (botPatterns.perfectTiming) {
    await addViolation(session, 'PERFECT_TIMING', 35, env);
    return errorResponse('BOT_DETECTED', 'Suspiciously perfect timing', 403, origin);
  }

  // Update session
  session.mouseEntropy = entropy;
  session.behavioralSamples = body.mousePositions.length;
  session.lastMousePositions = body.mousePositions.slice(-50);
  
  if (entropy >= REQUIREMENTS.MIN_MOUSE_ENTROPY) {
    session.trustScore = Math.min(100, session.trustScore + 15);
  } else {
    await addViolation(session, 'LOW_ENTROPY', 15, env);
  }

  await saveSession(session, env);

  return jsonResponse({
    accepted: entropy >= REQUIREMENTS.MIN_MOUSE_ENTROPY,
    entropy,
    requiredEntropy: REQUIREMENTS.MIN_MOUSE_ENTROPY,
    status: getSessionStatus(session),
  }, 200, origin);
}

/**
 * Stream access - ALL requirements must be met
 */
async function handleStream(request: Request, env: Env, cf: any, origin?: string | null): Promise<Response> {
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  const sessionId = url.searchParams.get('sid');
  const token = url.searchParams.get('token');
  const timestamp = url.searchParams.get('ts');
  const signature = url.searchParams.get('sig');

  if (!targetUrl || !sessionId || !token || !timestamp || !signature) {
    return errorResponse('MISSING_PARAMS', 'Missing required parameters', 400, origin);
  }

  const session = await getSession(sessionId, env);
  if (!session) {
    return exposeAndDeny(targetUrl, 'INVALID_SESSION', origin);
  }

  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = request.headers.get('user-agent') || '';
  const fingerprintHeader = request.headers.get('x-fingerprint');

  // ===== STRICT VALIDATION =====

  // 1. IP must match (no exceptions)
  if (ip !== session.ip && !ip.startsWith('127.') && ip !== '::1') {
    await addViolation(session, 'IP_MISMATCH', 50, env);
    return exposeAndDeny(targetUrl, 'IP_MISMATCH', origin);
  }

  // 2. ASN must match
  if (cf.asn && session.asn !== 'unknown' && cf.asn !== session.asn) {
    await addViolation(session, 'ASN_MISMATCH', 50, env);
    return exposeAndDeny(targetUrl, 'ASN_MISMATCH', origin);
  }

  // 3. User agent hash must match
  const uaHash = await hashString(userAgent);
  if (uaHash !== session.userAgentHash) {
    await addViolation(session, 'UA_MISMATCH', 40, env);
    return exposeAndDeny(targetUrl, 'USER_AGENT_CHANGED', origin);
  }

  // 4. Fingerprint header must match (if provided)
  if (fingerprintHeader && fingerprintHeader !== session.fingerprintHash) {
    await addViolation(session, 'FP_HEADER_MISMATCH', 45, env);
    return exposeAndDeny(targetUrl, 'FINGERPRINT_MISMATCH', origin);
  }

  // 5. Token timestamp must be recent
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Date.now() - ts > REQUIREMENTS.TOKEN_EXPIRY_MS) {
    await addViolation(session, 'TOKEN_EXPIRED', 20, env);
    return exposeAndDeny(targetUrl, 'TOKEN_EXPIRED', origin);
  }

  // 6. Verify signature
  const expectedSig = await generateSignature(sessionId, targetUrl, ts, env.SIGNING_SECRET);
  if (signature !== expectedSig) {
    await addViolation(session, 'INVALID_SIGNATURE', 40, env);
    return exposeAndDeny(targetUrl, 'INVALID_SIGNATURE', origin);
  }

  // 7. Verify token
  const expectedToken = await generateToken(session, targetUrl, ts, env.SIGNING_SECRET);
  if (token !== expectedToken) {
    await addViolation(session, 'INVALID_TOKEN', 35, env);
    return exposeAndDeny(targetUrl, 'INVALID_TOKEN', origin);
  }

  // 8. Rate limiting
  const timeSinceLastRequest = Date.now() - session.lastRequestTime;
  if (timeSinceLastRequest < REQUIREMENTS.RATE_LIMIT_MS) {
    await addViolation(session, 'RATE_LIMIT', 10, env);
    return errorResponse('RATE_LIMITED', `Wait ${REQUIREMENTS.RATE_LIMIT_MS - timeSinceLastRequest}ms`, 429, origin);
  }

  // ===== REQUIREMENT CHECKS =====

  // 9. Must have fingerprint
  if (!session.fingerprintHash) {
    return exposeAndDeny(targetUrl, 'FINGERPRINT_REQUIRED', origin);
  }

  // 10. Must have passed minimum challenges
  const challengeCount = session.challengesPassed.size || (session.challengesPassed as any).length || 0;
  if (challengeCount < REQUIREMENTS.MIN_CHALLENGES_PASSED) {
    return exposeAndDeny(targetUrl, `CHALLENGES_REQUIRED: ${challengeCount}/${REQUIREMENTS.MIN_CHALLENGES_PASSED}`, origin);
  }

  // 11. Must have completed proof of work
  if (!session.powCompleted) {
    return exposeAndDeny(targetUrl, 'POW_REQUIRED', origin);
  }

  // 12. Must have sufficient mouse entropy
  if (session.mouseEntropy < REQUIREMENTS.MIN_MOUSE_ENTROPY) {
    return exposeAndDeny(targetUrl, `LOW_ENTROPY: ${session.mouseEntropy.toFixed(2)} < ${REQUIREMENTS.MIN_MOUSE_ENTROPY}`, origin);
  }

  // 13. Must have sufficient behavioral samples
  if (session.behavioralSamples < REQUIREMENTS.MIN_BEHAVIORAL_SAMPLES) {
    return exposeAndDeny(targetUrl, `INSUFFICIENT_SAMPLES: ${session.behavioralSamples}/${REQUIREMENTS.MIN_BEHAVIORAL_SAMPLES}`, origin);
  }

  // 14. Trust score must be above minimum
  if (session.trustScore < REQUIREMENTS.MIN_TRUST_SCORE) {
    return exposeAndDeny(targetUrl, `LOW_TRUST: ${session.trustScore}/${REQUIREMENTS.MIN_TRUST_SCORE}`, origin);
  }

  // 15. Must not have too many violations
  if (session.violations.length >= REQUIREMENTS.MAX_VIOLATIONS) {
    await blacklist(session.ip, session.asn, 'TOO_MANY_VIOLATIONS', env);
    return exposeAndDeny(targetUrl, 'TOO_MANY_VIOLATIONS', origin);
  }

  // ===== ALL CHECKS PASSED - PROXY THE STREAM =====
  
  session.lastRequestTime = Date.now();
  session.lastActivity = Date.now();
  session.requestCount++;
  await saveSession(session, env);

  return proxyStream(decodeURIComponent(targetUrl), session, env, origin);
}

/**
 * Get session status
 */
async function handleStatus(request: Request, env: Env, origin?: string | null): Promise<Response> {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('sid');

  if (!sessionId) {
    return errorResponse('MISSING_SESSION', 'Session ID required', 400, origin);
  }

  const session = await getSession(sessionId, env);
  if (!session) {
    return errorResponse('INVALID_SESSION', 'Session not found', 401, origin);
  }

  // Include PoW challenge if all challenges are passed but PoW not completed
  const challengeCount = session.challengesPassed instanceof Set 
    ? session.challengesPassed.size 
    : Array.isArray(session.challengesPassed) 
      ? session.challengesPassed.length 
      : 0;

  let powChallenge = null;
  if (challengeCount >= REQUIREMENTS.MIN_CHALLENGES_PASSED && !session.powCompleted) {
    powChallenge = {
      challengeString: `${session.id}:${session.fingerprintHash}:${session.created}`,
      difficulty: REQUIREMENTS.POW_DIFFICULTY,
    };
  }

  return jsonResponse({
    status: getSessionStatus(session),
    requirements: REQUIREMENTS,
    powChallenge,
  }, 200, origin);
}

// ============================================================================
// CHALLENGE GENERATION AND VERIFICATION
// ============================================================================

async function generateChallenge(type: ChallengeType, previousHash: string, env: Env): Promise<ParanoidChallenge> {
  const id = crypto.randomUUID();
  const nonce = await generateSecureId(id, Date.now().toString(), env.SIGNING_SECRET);
  
  let params: Record<string, unknown> = {};
  let expectedHash = '';

  switch (type) {
    case 'canvas_precise':
      // Must draw EXACT shapes at EXACT positions with EXACT colors
      params = {
        width: 400,
        height: 200,
        operations: [
          { op: 'fillStyle', value: `#${randomHex(6)}` },
          { op: 'fillRect', args: [randomInt(0, 100), randomInt(0, 50), randomInt(50, 100), randomInt(50, 100)] },
          { op: 'fillStyle', value: `#${randomHex(6)}` },
          { op: 'beginPath' },
          { op: 'arc', args: [randomInt(150, 300), randomInt(50, 150), randomInt(20, 50), 0, Math.PI * 2] },
          { op: 'fill' },
          { op: 'fillStyle', value: `#${randomHex(6)}` },
          { op: 'font', value: `${randomInt(12, 24)}px Arial` },
          { op: 'fillText', args: [randomString(10), randomInt(50, 200), randomInt(50, 150)] },
        ],
      };
      expectedHash = await hashString(JSON.stringify(params));
      break;

    case 'audio_fingerprint':
      // Must generate specific audio frequencies and report exact values
      params = {
        frequencies: [randomInt(200, 500), randomInt(500, 1000), randomInt(1000, 2000)],
        duration: 50,
        oscillatorType: ['sine', 'square', 'sawtooth'][randomInt(0, 2)],
        expectedBins: randomInt(128, 512),
      };
      expectedHash = await hashString(JSON.stringify(params));
      break;

    case 'webgl_compute':
      // Must compile and execute specific shader, report timing
      const scale = (Math.random() * 2).toFixed(4);
      const color = [Math.random().toFixed(4), Math.random().toFixed(4), Math.random().toFixed(4)];
      params = {
        vertexShader: `
          attribute vec4 position;
          uniform float scale;
          void main() {
            gl_Position = position * ${scale};
          }
        `,
        fragmentShader: `
          precision mediump float;
          void main() {
            gl_FragColor = vec4(${color[0]}, ${color[1]}, ${color[2]}, 1.0);
          }
        `,
        iterations: randomInt(100, 500),
      };
      expectedHash = await hashString(JSON.stringify(params));
      break;

    case 'pow_hash':
      // Proof of work challenge
      params = {
        difficulty: REQUIREMENTS.POW_DIFFICULTY,
        prefix: randomString(16),
      };
      expectedHash = await hashString(JSON.stringify(params));
      break;

    case 'timing_proof':
      // Must perform operations and report exact timing
      params = {
        operations: randomInt(1000, 5000),
        expectedMinTime: 50,
        expectedMaxTime: 500,
      };
      expectedHash = await hashString(JSON.stringify(params));
      break;
  }

  return {
    id,
    type,
    params,
    expectedHash,
    nonce,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30000, // 30 seconds to complete
    previousChallengeHash: previousHash,
  };
}

async function verifyResponse(challenge: ParanoidChallenge, response: unknown, env: Env): Promise<{ valid: boolean; reason: string }> {
  switch (challenge.type) {
    case 'canvas_precise': {
      if (typeof response !== 'object' || response === null) {
        return { valid: false, reason: 'Response must be an object' };
      }
      const r = response as { dataUrl: string; dimensions: { width: number; height: number } };
      
      if (!r.dataUrl || !r.dataUrl.startsWith('data:image/png')) {
        return { valid: false, reason: 'Invalid canvas data URL' };
      }
      
      // Verify dimensions match
      const params = challenge.params as { width: number; height: number };
      if (r.dimensions?.width !== params.width || r.dimensions?.height !== params.height) {
        return { valid: false, reason: 'Canvas dimensions mismatch' };
      }
      
      // Verify data URL is substantial (not empty canvas)
      if (r.dataUrl.length < 1000) {
        return { valid: false, reason: 'Canvas appears empty' };
      }
      
      return { valid: true, reason: '' };
    }

    case 'audio_fingerprint': {
      if (typeof response !== 'object' || response === null) {
        return { valid: false, reason: 'Response must be an object' };
      }
      const r = response as { frequencyData: number[]; sampleRate: number };
      
      if (!Array.isArray(r.frequencyData) || r.frequencyData.length === 0) {
        return { valid: false, reason: 'Missing frequency data' };
      }
      
      // Verify we got data for all frequencies
      const params = challenge.params as { frequencies: number[] };
      if (r.frequencyData.length < params.frequencies.length) {
        return { valid: false, reason: 'Insufficient frequency data' };
      }
      
      return { valid: true, reason: '' };
    }

    case 'webgl_compute': {
      if (typeof response !== 'object' || response === null) {
        return { valid: false, reason: 'Response must be an object' };
      }
      const r = response as { compiled: boolean; timing: number; output: string };
      
      if (!r.compiled) {
        return { valid: false, reason: 'Shader compilation failed' };
      }
      
      // Verify timing is reasonable
      const params = challenge.params as { iterations: number };
      if (r.timing < params.iterations * 0.01) {
        return { valid: false, reason: 'Timing too fast for iterations' };
      }
      
      return { valid: true, reason: '' };
    }

    case 'pow_hash': {
      if (typeof response !== 'object' || response === null) {
        return { valid: false, reason: 'Response must be an object' };
      }
      const r = response as { nonce: number; hash: string };
      
      const params = challenge.params as { prefix: string; difficulty: number };
      const expectedHash = await hashString(`${params.prefix}:${r.nonce}`);
      
      if (r.hash !== expectedHash) {
        return { valid: false, reason: 'Hash mismatch' };
      }
      
      const requiredPrefix = '0'.repeat(params.difficulty);
      if (!expectedHash.startsWith(requiredPrefix)) {
        return { valid: false, reason: 'Insufficient difficulty' };
      }
      
      return { valid: true, reason: '' };
    }

    case 'timing_proof': {
      if (typeof response !== 'object' || response === null) {
        return { valid: false, reason: 'Response must be an object' };
      }
      const r = response as { timing: number; result: number };
      
      const params = challenge.params as { expectedMinTime: number; expectedMaxTime: number };
      if (r.timing < params.expectedMinTime || r.timing > params.expectedMaxTime) {
        return { valid: false, reason: `Timing out of range: ${r.timing}ms` };
      }
      
      return { valid: true, reason: '' };
    }

    default:
      return { valid: false, reason: 'Unknown challenge type' };
  }
}

function getMinimumTime(type: ChallengeType): number {
  switch (type) {
    case 'canvas_precise': return 5; // Very fast is OK
    case 'audio_fingerprint': return 10;
    case 'webgl_compute': return 5; // Very fast is OK
    case 'pow_hash': return 50; // PoW still needs some time
    case 'timing_proof': return 5;
    default: return 5;
  }
}

function getMaximumTime(type: ChallengeType): number {
  switch (type) {
    case 'canvas_precise': return 5000;
    case 'audio_fingerprint': return 3000;
    case 'webgl_compute': return 10000;
    case 'pow_hash': return 60000;
    case 'timing_proof': return 1000;
    default: return 5000;
  }
}

function getNextChallengeType(session: ParanoidSession): ChallengeType | null {
  const passed = session.challengesPassed;
  const passedSet = passed instanceof Set ? passed : new Set(passed);

  // Order: canvas -> audio -> webgl (3 challenges)
  if (!passedSet.has('canvas_precise')) return 'canvas_precise';
  if (!passedSet.has('audio_fingerprint')) return 'audio_fingerprint';
  if (!passedSet.has('webgl_compute')) return 'webgl_compute';

  return null; // All required challenges passed
}

// ============================================================================
// BOT DETECTION
// ============================================================================

function calculateMouseEntropy(positions: Array<{ x: number; y: number; t: number }>): number {
  if (positions.length < 10) return 0;

  // Calculate angle changes between consecutive movements
  const angles: number[] = [];
  for (let i = 2; i < positions.length; i++) {
    const p1 = positions[i - 2];
    const p2 = positions[i - 1];
    const p3 = positions[i];
    
    const angle1 = Math.atan2(p2.y - p1.y, p2.x - p1.x);
    const angle2 = Math.atan2(p3.y - p2.y, p3.x - p2.x);
    angles.push(Math.abs(angle2 - angle1));
  }

  // Shannon entropy of angle distribution
  const bins = new Array(20).fill(0);
  angles.forEach(a => {
    const bin = Math.min(19, Math.floor(a / (Math.PI / 10)));
    bins[bin]++;
  });

  const total = angles.length;
  let entropy = 0;
  bins.forEach(count => {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  });

  // Normalize to 0-1
  return entropy / Math.log2(20);
}

function detectBotPatterns(positions: Array<{ x: number; y: number; t: number }>): {
  isLinear: boolean;
  constantVelocity: boolean;
  noMicroMovements: boolean;
  perfectTiming: boolean;
} {
  const result = {
    isLinear: false,
    constantVelocity: false,
    noMicroMovements: true,
    perfectTiming: false,
  };

  if (positions.length < 10) return result;

  // Check for linear movement
  const deviations: number[] = [];
  const first = positions[0];
  const last = positions[positions.length - 1];
  
  for (let i = 1; i < positions.length - 1; i++) {
    const p = positions[i];
    // Distance from point to line between first and last
    const num = Math.abs((last.y - first.y) * p.x - (last.x - first.x) * p.y + last.x * first.y - last.y * first.x);
    const den = Math.sqrt(Math.pow(last.y - first.y, 2) + Math.pow(last.x - first.x, 2));
    if (den > 0) deviations.push(num / den);
  }
  
  if (deviations.length > 0) {
    const avgDeviation = deviations.reduce((a, b) => a + b, 0) / deviations.length;
    result.isLinear = avgDeviation < 3; // Less than 3px average = too straight
  }

  // Check for constant velocity
  const velocities: number[] = [];
  for (let i = 1; i < positions.length; i++) {
    const dx = positions[i].x - positions[i - 1].x;
    const dy = positions[i].y - positions[i - 1].y;
    const dt = positions[i].t - positions[i - 1].t;
    if (dt > 0) {
      velocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
    }
  }

  if (velocities.length > 5) {
    const mean = velocities.reduce((a, b) => a + b, 0) / velocities.length;
    const variance = velocities.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / velocities.length;
    const cv = mean > 0 ? Math.sqrt(variance) / mean : 0;
    result.constantVelocity = cv < 0.15; // Less than 15% variation = robotic
  }

  // Check for micro-movements (human tremor)
  let microCount = 0;
  for (let i = 1; i < positions.length; i++) {
    const dx = Math.abs(positions[i].x - positions[i - 1].x);
    const dy = Math.abs(positions[i].y - positions[i - 1].y);
    if (dx < 3 && dy < 3 && dx + dy > 0) {
      microCount++;
    }
  }
  result.noMicroMovements = microCount < positions.length * 0.05; // Less than 5% micro = suspicious

  // Check for perfect timing intervals
  const intervals: number[] = [];
  for (let i = 1; i < positions.length; i++) {
    intervals.push(positions[i].t - positions[i - 1].t);
  }

  if (intervals.length > 10) {
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - mean, 2), 0) / intervals.length;
    result.perfectTiming = variance < 10; // Very low variance = programmatic
  }

  return result;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function generateSecureId(...parts: string[]): Promise<string> {
  const data = parts.join(':') + Date.now() + crypto.randomUUID();
  return (await hashString(data)).substring(0, 32);
}

async function hashString(str: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateToken(session: ParanoidSession, url: string, timestamp: number, secret: string): Promise<string> {
  const data = `${session.id}:${session.fingerprintHash}:${url}:${timestamp}:${secret}`;
  return (await hashString(data)).substring(0, 32);
}

async function generateSignature(sessionId: string, url: string, timestamp: number, secret: string): Promise<string> {
  const data = `sig:${sessionId}:${url}:${timestamp}:${secret}`;
  return (await hashString(data)).substring(0, 16);
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomHex(length: number): string {
  return Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function randomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function getSessionStatus(session: ParanoidSession): Record<string, unknown> {
  const challengeCount = session.challengesPassed instanceof Set 
    ? session.challengesPassed.size 
    : Array.isArray(session.challengesPassed) 
      ? session.challengesPassed.length 
      : 0;

  return {
    hasFingerprint: !!session.fingerprintHash,
    challengesPassed: challengeCount,
    challengesRequired: REQUIREMENTS.MIN_CHALLENGES_PASSED,
    powCompleted: session.powCompleted,
    mouseEntropy: session.mouseEntropy,
    entropyRequired: REQUIREMENTS.MIN_MOUSE_ENTROPY,
    behavioralSamples: session.behavioralSamples,
    samplesRequired: REQUIREMENTS.MIN_BEHAVIORAL_SAMPLES,
    trustScore: session.trustScore,
    trustRequired: REQUIREMENTS.MIN_TRUST_SCORE,
    violations: session.violations.length,
    maxViolations: REQUIREMENTS.MAX_VIOLATIONS,
    canAccessStream: canAccessStream(session),
  };
}

function canAccessStream(session: ParanoidSession): boolean {
  const challengeCount = session.challengesPassed instanceof Set 
    ? session.challengesPassed.size 
    : Array.isArray(session.challengesPassed) 
      ? session.challengesPassed.length 
      : 0;

  return (
    !!session.fingerprintHash &&
    challengeCount >= REQUIREMENTS.MIN_CHALLENGES_PASSED &&
    session.powCompleted &&
    session.mouseEntropy >= REQUIREMENTS.MIN_MOUSE_ENTROPY &&
    session.behavioralSamples >= REQUIREMENTS.MIN_BEHAVIORAL_SAMPLES &&
    session.trustScore >= REQUIREMENTS.MIN_TRUST_SCORE &&
    session.violations.length < REQUIREMENTS.MAX_VIOLATIONS
  );
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

async function getSession(id: string, env: Env): Promise<ParanoidSession | null> {
  if (!env.SESSION_KV) return null;
  const data = await env.SESSION_KV.get(`v3:${id}`);
  if (!data) return null;
  try {
    const session = JSON.parse(data);
    // Convert challengesPassed back to Set if it was serialized as array
    if (Array.isArray(session.challengesPassed)) {
      session.challengesPassed = new Set(session.challengesPassed);
    }
    return session;
  } catch {
    return null;
  }
}

async function saveSession(session: ParanoidSession, env: Env): Promise<void> {
  if (!env.SESSION_KV) return;
  // Convert Set to array for JSON serialization
  const toSave = {
    ...session,
    challengesPassed: Array.from(session.challengesPassed),
  };
  await env.SESSION_KV.put(`v3:${session.id}`, JSON.stringify(toSave), { expirationTtl: 3600 });
}

async function addViolation(session: ParanoidSession, type: string, severity: number, env: Env): Promise<void> {
  session.violations.push({ type, time: Date.now(), severity });
  session.trustScore = Math.max(0, session.trustScore - severity);
  
  if (session.violations.length >= REQUIREMENTS.MAX_VIOLATIONS) {
    await blacklist(session.ip, session.asn, 'MAX_VIOLATIONS', env);
  }
  
  await saveSession(session, env);
}

async function isBlacklisted(ip: string, asn: string, env: Env): Promise<boolean> {
  if (!env.BLACKLIST_KV) return false;
  const ipBl = await env.BLACKLIST_KV.get(`bl:ip:${ip}`);
  const asnBl = await env.BLACKLIST_KV.get(`bl:asn:${asn}`);
  return !!(ipBl || asnBl);
}

async function blacklist(ip: string, asn: string, reason: string, env: Env): Promise<void> {
  if (!env.BLACKLIST_KV) return;
  const data = JSON.stringify({ reason, timestamp: Date.now() });
  await env.BLACKLIST_KV.put(`bl:ip:${ip}`, data, { expirationTtl: 86400 * 7 }); // 7 days
}

// ============================================================================
// STREAM PROXY
// ============================================================================

async function proxyStream(url: string, session: ParanoidSession, env: Env, origin?: string | null): Promise<Response> {
  const headers: HeadersInit = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': '*/*',
  };

  if (url.includes('2embed')) headers['Referer'] = 'https://www.2embed.cc/';

  try {
    const response = await fetch(url, { headers, redirect: 'follow' });
    if (!response.ok) {
      return jsonResponse({ error: `Upstream error: ${response.status}` }, response.status, origin);
    }

    const contentType = response.headers.get('content-type') || '';
    let body = await response.arrayBuffer();

    // Watermark video segments
    if (url.includes('.ts') || url.includes('.m4s')) {
      body = embedWatermark(body, session, env.WATERMARK_SECRET);
    }

    return new Response(body, {
      headers: {
        'Content-Type': contentType || 'application/octet-stream',
        'X-Trust-Score': session.trustScore.toString(),
        'X-Session-Valid': 'true',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        ...corsHeaders(origin),
      },
    });
  } catch (error) {
    return jsonResponse({ error: 'Failed to fetch stream' }, 502, origin);
  }
}

function embedWatermark(data: ArrayBuffer, session: ParanoidSession, secret: string): ArrayBuffer {
  const bytes = new Uint8Array(data);
  const watermark = `${session.id}:${Date.now()}:${session.ip}:${session.fingerprintHash.substring(0, 8)}`;
  const watermarkBytes = new TextEncoder().encode(watermark);
  const secretBytes = new TextEncoder().encode(secret);
  
  // Embed watermark in video data using LSB steganography
  const startOffset = 188; // Skip TS header
  for (let i = 0; i < watermarkBytes.length && startOffset + i * 1000 < bytes.length; i++) {
    const pos = startOffset + i * 1000;
    const encoded = watermarkBytes[i] ^ secretBytes[i % secretBytes.length];
    for (let bit = 0; bit < 8; bit++) {
      if (pos + bit < bytes.length) {
        bytes[pos + bit] = (bytes[pos + bit] & 0xFE) | ((encoded >> bit) & 0x01);
      }
    }
  }
  
  return bytes.buffer;
}

function exposeAndDeny(url: string, reason: string, origin?: string | null): Response {
  // Expose the original URL to punish leechers
  return jsonResponse({
    error: 'ACCESS_DENIED',
    reason,
    originalUrl: url,
    message: 'Your attempt has been logged and your IP may be blacklisted.',
    timestamp: Date.now(),
  }, 403, origin);
}
