# Quantum Shield V3 - PARANOID MODE

The most secure stream protection system ever created. This version is **actually hard to bypass**.

## Why V3?

V2 was designed with development-friendly shortcuts that made testing easier. V3 removes ALL shortcuts and enforces strict requirements.

## Behavioral Tracking Integration

V3 integrates with the main app's presence tracking system to build historical trust profiles:

- **Mouse entropy** is tracked from the moment a user lands on any page
- **Historical data** is stored in the database and used to calculate a "human score"
- **New users** start with a neutral score (50) and build trust over time
- **Returning users** with good history get faster verification
- **Suspicious users** with low entropy history face stricter challenges

### Trust Levels
| Level | Human Score | Description |
|-------|-------------|-------------|
| new | N/A | Account < 1 day old or < 100 samples |
| low | < 30 | Suspicious behavior patterns |
| medium | 30-60 | Some human-like behavior |
| high | 60-80 | Consistent human behavior |
| verified | 80+ | Long history of human behavior |

### API Endpoint
```
GET /api/user/trust?userId=xxx
```
Returns historical trust data for integration with stream protection.

## Requirements to Access Streams

ALL of these must be met before a single byte of stream data is served:

| Requirement | Threshold | Description |
|-------------|-----------|-------------|
| Fingerprint | Required | Browser fingerprint must be submitted and verified |
| Challenges | 3 passed | Must pass canvas, audio, AND WebGL challenges |
| Proof of Work | Required | CPU-intensive hash computation (4 leading zeros) |
| Mouse Entropy | ≥ 0.5 | Movement patterns must show human-like randomness |
| Behavioral Samples | ≥ 50 | Must collect at least 50 mouse position samples |
| Trust Score | ≥ 60 | Starts at 50, earned through successful verifications |
| Violations | < 5 | Too many violations = permanent blacklist |

## Token Security

- Tokens expire in **10 seconds** (not minutes)
- Each token is bound to: session ID, fingerprint hash, URL, timestamp
- Signature verification on every request
- Rate limited to 1 request per 2 seconds

## Bot Detection

### Mouse Analysis
- **Entropy calculation**: Shannon entropy of angle changes between movements
- **Linear detection**: Average deviation from straight line < 3px = bot
- **Velocity variance**: Coefficient of variation < 15% = robotic
- **Micro-movements**: Human hands have natural tremor (< 5% micro = suspicious)
- **Timing variance**: Very low interval variance = programmatic

### Challenge Types

1. **Canvas Precise**: Must draw exact shapes at exact positions with exact colors
2. **Audio Fingerprint**: Generate specific frequencies, report exact values
3. **WebGL Compute**: Compile shaders, perform iterations, report timing
4. **Proof of Work**: Find nonce where SHA256 has N leading zeros
5. **Timing Proof**: Perform operations, timing must be within expected range

## Violation Penalties

| Violation | Severity | Description |
|-----------|----------|-------------|
| FINGERPRINT_MISMATCH | 50 | Fingerprint changed mid-session |
| IP_MISMATCH | 50 | IP address changed |
| ASN_MISMATCH | 50 | Network provider changed |
| INVALID_SIGNATURE | 40 | Token signature invalid |
| UA_MISMATCH | 40 | User agent changed |
| FP_HEADER_MISMATCH | 45 | Fingerprint header doesn't match |
| INVALID_TOKEN | 35 | Token verification failed |
| INVALID_PROOF_HASH | 35 | Challenge proof hash wrong |
| TOO_FAST | 40 | Challenge completed impossibly fast |
| LINEAR_MOUSE | 30 | Mouse moves in straight lines |
| CONSTANT_VELOCITY | 30 | Mouse moves at constant speed |
| NO_TREMOR | 25 | No human hand tremor detected |
| PERFECT_TIMING | 35 | Suspiciously perfect timing intervals |
| RATE_LIMIT | 10 | Too many requests |
| TOKEN_EXPIRED | 20 | Token older than 10 seconds |

## API Endpoints

```
POST /v3/init          - Initialize session, get first challenge
POST /v3/fingerprint   - Submit browser fingerprint
POST /v3/challenge     - Submit challenge response
POST /v3/pow           - Submit proof of work
POST /v3/behavioral    - Submit behavioral data
GET  /v3/stream        - Access protected stream (all requirements must be met)
GET  /v3/status        - Check session status
```

## Usage

### Client Side
```typescript
import { initQuantumSessionV3, getQuantumStreamUrlV3 } from '@/app/lib/stream/quantum-client-v3';

// Initialize (this takes time - challenges, PoW, behavioral collection)
const session = await initQuantumSessionV3();

// Check if ready
if (session.status.canAccessStream) {
  // Get protected URL (valid for 10 seconds only!)
  const url = await getQuantumStreamUrlV3(originalStreamUrl);
  // Use immediately
}
```

### Server Side (wrangler.toml)
```toml
[vars]
PROTECTION_MODE = "quantum-v3"  # or "paranoid"
SIGNING_SECRET = "your-secret-key"
WATERMARK_SECRET = "your-watermark-key"

[[kv_namespaces]]
binding = "SESSION_KV"
id = "your-kv-id"

[[kv_namespaces]]
binding = "BLACKLIST_KV"
id = "your-blacklist-kv-id"
```

## Test Page

Visit `/test-quantum-v3` to test the system interactively.

## Comparison

| Feature | V2 | V3 |
|---------|----|----|
| Challenges required | 1 | 3 |
| Token expiry | 60 seconds | 10 seconds |
| Proof of Work | Optional | Required |
| Behavioral minimum | None | 50 samples |
| Entropy minimum | None | 0.5 |
| Trust score start | 100 | 50 |
| Rate limiting | Loose | Strict (2s) |
| Dev shortcuts | Yes | None |
