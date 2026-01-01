# DLHD Proxy - Cloudflare-Only Authentication

This proxy routes daddyhd.com live streams through Cloudflare Workers with proper authentication.

**NO RPI PROXY NEEDED!** The authentication works directly from Cloudflare Workers.

## Architecture (Dec 2024)

```
Browser → Cloudflare Worker → DLHD CDN (with auth headers)
```

## How It Works

### Authentication Flow

DLHD uses a 3-step authentication process, all handled by the CF Worker:

```
1. Fetch Player Page → Get AUTH_TOKEN, CHANNEL_KEY, AUTH_COUNTRY, AUTH_TS
2. Call Heartbeat → Establish Session  
3. Fetch Key → Use Authorization + X-Channel-Key + X-Client-Token
```

### Step 1: Get Auth Token

Fetch the player page to extract the embedded auth token:

```
GET https://epicplayplay.cfd/premiumtv/daddyhd.php?id=<channel>
Headers:
  Referer: https://daddyhd.com/

Response contains:
  AUTH_TOKEN = "abc123..."
  CHANNEL_KEY = "premium51"
  AUTH_COUNTRY = "US"
  AUTH_TS = "1766182626"
```

### Step 2: Establish Heartbeat Session

Call the heartbeat endpoint to create a session:

```
GET https://chevy.kiko2.ru/heartbeat
Headers:
  Authorization: Bearer <AUTH_TOKEN>
  X-Channel-Key: premium<channel>
  X-Client-Token: base64(channelKey|country|timestamp|userAgent|fingerprint)

Response:
  {"message":"Session created","status":"ok"}
```

### Step 3: Fetch Encryption Key

With an active session, fetch the AES-128 encryption key:

```
GET https://chevy.kiko2.ru/key/premium51/<key_id>
Headers:
  Authorization: Bearer <AUTH_TOKEN>
  X-Channel-Key: premium<channel>
  X-Client-Token: <same as heartbeat>

Response: 16-byte binary key
```

## X-Client-Token Format

The client token is a base64-encoded fingerprint:

```javascript
function generateClientToken(channelKey, country, timestamp, userAgent) {
  const screen = '1920x1080';
  const tz = 'America/New_York';
  const lang = 'en-US';
  const fingerprint = `${userAgent}|${screen}|${tz}|${lang}`;
  const signData = `${channelKey}|${country}|${timestamp}|${userAgent}|${fingerprint}`;
  return btoa(signData);
}
```

## Error Codes

| Error | Meaning | Solution |
|-------|---------|----------|
| `E2` | "Session must be created via heartbeat first" | Call heartbeat endpoint |
| `E3` | Token expired or invalid | Refresh auth token from player page |

## What Requires What?

| Component | Auth Token | Heartbeat | Notes |
|-----------|------------|-----------|-------|
| Server Lookup | ❌ | ❌ | Public endpoint |
| M3U8 Playlist | ❌ | ❌ | Public CDN |
| **Encryption Key** | ✅ | ✅ | Requires full auth |
| Video Segments | ❌ | ❌ | Public CDN |

## Routes

| Route | Description |
|-------|-------------|
| `GET /dlhd?channel=<id>` | Get proxied M3U8 playlist |
| `GET /dlhd/key?url=<encoded_url>` | Proxy encryption key (handles auth) |
| `GET /dlhd/segment?url=<encoded_url>` | Proxy video segment |
| `GET /dlhd/schedule` | Fetch live events schedule |
| `GET /dlhd/health` | Health check |

## Session Management

The Cloudflare Worker automatically:
- Caches auth tokens per channel (5 min TTL)
- Calls heartbeat before each key fetch
- Retries with fresh session on E2 errors
- Caches server keys (30 min TTL)

## Setup

### Deploy Cloudflare Worker

```bash
cd cloudflare-proxy
npx wrangler deploy
```

No secrets needed! The proxy handles all authentication internally.

## Usage

```bash
# Get a channel stream
curl "https://your-worker.workers.dev/dlhd?channel=51"

# Check health
curl "https://your-worker.workers.dev/dlhd/health"

# Test key fetching
curl "https://your-worker.workers.dev/dlhd/key?url=https://chevy.kiko2.ru/key/premium51/5885916"
```

## Key Servers

All key requests go to `chevy.kiko2.ru` - it's the only server with a working heartbeat endpoint.

| Server Key | M3U8 URL Pattern |
|------------|------------------|
| zeko | `https://zekonew.kiko2.ru/zeko/premium{ch}/mono.css` |
| chevy | `https://chevynew.kiko2.ru/chevy/premium{ch}/mono.css` |
| wind | `https://windnew.kiko2.ru/wind/premium{ch}/mono.css` |
| nfs | `https://nfsnew.kiko2.ru/nfs/premium{ch}/mono.css` |
| ddy6 | `https://ddy6new.kiko2.ru/ddy6/premium{ch}/mono.css` |
| top1/cdn | `https://top1.kiko2.ru/top1/cdn/premium{ch}/mono.css` |

## Troubleshooting

### "Session must be created via heartbeat first" (E2)
- The heartbeat call failed
- Worker will automatically retry with fresh session

### "Token expired" (E3)
- Auth token expired
- Worker will automatically refresh from player page

### Stream keeps reconnecting
- Normal for live streams
- HLS.js handles reconnection automatically
