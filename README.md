# Cloudflare Media Proxy

A Cloudflare Worker that proxies HLS streams and live TV with proper headers and CORS support.

## Features

- **Stream Proxy** (`/stream/`) - Proxies HLS streams for 2embed/vidsrc
- **AnimeKai Proxy** (`/animekai/`) - Proxies MegaUp CDN streams via RPI residential IP
- **TV Proxy** (`/tv/`) - Proxies DLHD live TV streams
- **IPTV Proxy** (`/iptv/`) - Proxies Stalker portal IPTV streams
- **DLHD Proxy** (`/dlhd/`) - Proxies DLHD via Oxylabs residential IPs
- **Analytics Proxy** (`/analytics/`) - Routes analytics through CF instead of Vercel Edge
- **Decoder Sandbox** (`/decode`) - Isolated script execution environment
- **Health Check** (`/health`) - Status and metrics endpoint
- **Full Observability** - Structured JSON logging with request tracing

## Deployment

```bash
# Install dependencies
npm install

# Deploy to Cloudflare
npx wrangler deploy

# Deploy to production
npx wrangler deploy --env production
```

## Observability & Logging

### Real-time Log Streaming

Stream logs in real-time to your terminal:

```bash
# Tail logs from production worker
npx wrangler tail media-proxy

# With filters
npx wrangler tail media-proxy --status error
npx wrangler tail media-proxy --search "stream"
npx wrangler tail media-proxy --format json
```

### Cloudflare Dashboard

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **Workers & Pages** → **media-proxy**
3. Click **Logs** tab to view recent logs
4. Use **Real-time Logs** for live streaming

### Log Levels

Set `LOG_LEVEL` in `wrangler.toml` or via environment variable:

- `debug` - All logs including detailed request/response info
- `info` - Standard operational logs
- `warn` - Warnings and potential issues
- `error` - Errors only

### Log Format

All logs are structured JSON for easy parsing:

```json
{
  "timestamp": "2024-12-06T17:30:00.000Z",
  "level": "info",
  "message": "Request completed",
  "context": {
    "requestId": "abc123",
    "method": "GET",
    "path": "/stream/",
    "url": "https://media-proxy.xxx.workers.dev/stream/?url=..."
  },
  "data": {
    "status": 200,
    "contentType": "application/vnd.apple.mpegurl",
    "contentLength": "1234"
  },
  "duration": 150
}
```

### Health Check

```bash
curl https://media-proxy.xxx.workers.dev/health
```

Returns:
```json
{
  "status": "healthy",
  "uptime": "3600s",
  "metrics": {
    "totalRequests": 1000,
    "errors": 5,
    "streamRequests": 800,
    "tvRequests": 195,
    "decodeRequests": 5
  }
}
```

## API Routes

### Stream Proxy

```
GET /stream/?url=<encoded_url>&source=<source>&referer=<encoded_referer>
```

Parameters:
- `url` (required) - URL-encoded target stream URL
- `source` - Source identifier (default: `2embed`)
- `referer` - URL-encoded referer header

### TV Proxy

```
GET /tv/?channel=<id>
GET /tv/key?url=<encoded_url>
GET /tv/segment?url=<encoded_url>
```

### AnimeKai Proxy (MegaUp CDN)

```
GET /animekai?url=<encoded_url>
GET /animekai/health
```

Routes MegaUp CDN streams through RPI residential proxy. MegaUp blocks:
1. Datacenter IPs (Cloudflare, AWS, etc.)
2. Requests with Origin header

Requires `RPI_PROXY_URL` and `RPI_PROXY_KEY` secrets to be configured.

### Decoder Sandbox

```
POST /decode
Content-Type: application/json

{
  "script": "<decoder script>",
  "divId": "player",
  "encodedContent": "<base64 content>"
}
```

### Analytics Proxy

Routes analytics through Cloudflare Worker instead of Vercel Edge functions.

**Benefits:**
- Cloudflare free tier: 100k requests/day (vs Vercel's 100k/month)
- Lower latency (edge closer to users)
- No cold starts
- Reduced Vercel costs
- More frequent real-time tracking

**Tracking Intervals (when using CF):**
- Heartbeat: Every 30 seconds (real-time presence)
- Min gap: 10 seconds between heartbeats
- Inactivity timeout: 5 minutes

**Fallback Intervals (Vercel):**
- Heartbeat: Every 30 minutes (conservative)
- Min gap: 5 minutes
- Inactivity timeout: 60 minutes

**Endpoints:**

```
POST /analytics/presence      - User presence heartbeat
POST /analytics/pageview      - Page view tracking
POST /analytics/event         - Generic analytics event
POST /analytics/watch-session - Video playback tracking
GET  /analytics/health        - Health check
```

**Presence Payload:**
```json
{
  "userId": "u_abc123",
  "sessionId": "s_xyz789",
  "activityType": "browsing|watching|livetv",
  "contentId": "movie_123",
  "contentTitle": "Movie Title",
  "isActive": true,
  "isVisible": true,
  "validation": {
    "isBot": false,
    "botConfidence": 0,
    "hasInteracted": true,
    "mouseEntropy": 0.6
  },
  "timestamp": 1703001234567
}
```

**Setup:**

1. **Set DATABASE_URL secret** (your Neon connection string):
   ```bash
   cd cloudflare-proxy
   npx wrangler secret put DATABASE_URL
   # Paste your Neon connection string when prompted
   # Format: postgresql://user:password@host/database?sslmode=require
   ```

2. **Set ALLOWED_ORIGINS** (optional, for CORS):
   ```bash
   npx wrangler secret put ALLOWED_ORIGINS
   # Enter: https://tv.vynx.cc,https://localhost:3000
   ```

3. **Deploy the worker**:
   ```bash
   npx wrangler deploy
   ```

4. **Set NEXT_PUBLIC_CF_ANALYTICS_URL** in your Next.js app's `.env.local`:
   ```bash
   NEXT_PUBLIC_CF_ANALYTICS_URL=https://media-proxy.your-subdomain.workers.dev
   ```

5. **Test the analytics endpoint**:
   ```bash
   curl https://media-proxy.your-subdomain.workers.dev/analytics/health
   # Should return: {"status":"healthy","hasDatabase":true,...}
   ```

### TMDB Proxy

Routes all TMDB API calls through Cloudflare Worker instead of Vercel Edge.

**Benefits:**
- Built-in edge caching (5-60 min depending on endpoint)
- Cloudflare free tier: 100k requests/day
- Lower latency
- Reduced Vercel costs

**Endpoints:**

```
GET /tmdb/search?query=<query>&type=<movie|tv|multi>&page=<n>
GET /tmdb/trending?type=<movie|tv|all>&time=<day|week>&page=<n>
GET /tmdb/details?id=<id>&type=<movie|tv>
GET /tmdb/recommendations?id=<id>&type=<movie|tv>
GET /tmdb/season?id=<id>&season=<number>
GET /tmdb/movies?category=<popular|top_rated|upcoming|now_playing>&page=<n>
GET /tmdb/series?category=<popular|top_rated|on_the_air|airing_today>&page=<n>
GET /tmdb/discover?type=<movie|tv>&genres=<ids>&sort_by=<field>&year=<year>
GET /tmdb/health
```

**Setup:**

1. **Set TMDB_API_KEY secret**:
   ```bash
   cd cloudflare-proxy
   npx wrangler secret put TMDB_API_KEY
   # Paste your TMDB API key (v3 auth) when prompted
   # Get from: https://www.themoviedb.org/settings/api
   ```

2. **Deploy the worker**:
   ```bash
   npx wrangler deploy
   ```

3. **Set NEXT_PUBLIC_CF_TMDB_URL** in your Next.js app's `.env.local`:
   ```bash
   NEXT_PUBLIC_CF_TMDB_URL=https://media-proxy.your-subdomain.workers.dev
   ```

4. **Test the TMDB endpoint**:
   ```bash
   curl "https://media-proxy.your-subdomain.workers.dev/tmdb/trending?type=movie&time=week"
   ```

## Configuration

### Environment Variables

Set via `wrangler secret` or Cloudflare Dashboard:

```bash
# Required for analytics proxy (Neon PostgreSQL connection string)
wrangler secret put DATABASE_URL

# Optional: RPI proxy for geo-restricted content
wrangler secret put RPI_PROXY_URL
wrangler secret put RPI_PROXY_KEY

# Optional: API key protection
wrangler secret put API_KEY
```

### wrangler.toml

```toml
[vars]
LOG_LEVEL = "debug"  # debug, info, warn, error

[observability]
enabled = true
```

## Troubleshooting

### CORS Errors

If you see CORS errors in the browser:
1. Check that the worker is deployed with latest code
2. Verify the request is going to the correct worker URL
3. Check logs for upstream errors

### Stream Not Loading

1. Check `/health` endpoint for worker status
2. Tail logs: `npx wrangler tail media-proxy`
3. Look for upstream fetch errors in logs
4. Verify the source URL is accessible

### Debugging

```bash
# Local development
npx wrangler dev

# Test specific endpoint
curl -v "https://media-proxy.xxx.workers.dev/stream/?url=..."

# Check worker status
curl https://media-proxy.xxx.workers.dev/health
```

## License

MIT
