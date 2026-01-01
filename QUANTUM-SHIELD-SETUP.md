# Quantum Shield V2 - Local Development Setup

## Quick Start

### 1. Install Dependencies
```bash
cd cloudflare-proxy
npm install
```

### 2. Start Local Worker
```bash
npm run dev
```

This starts the worker at `http://localhost:8787` with:
- Local KV storage (persisted in `.wrangler/state`)
- Development secrets pre-configured
- Quantum Shield V2 enabled

### 3. Start Next.js App
In another terminal:
```bash
cd ..
npm run dev
```

### 4. Test the Shield
Open `http://localhost:3000/test-quantum` in your browser.

## Testing Endpoints

### Health Check
```bash
curl http://localhost:8787/health
```

### Initialize Session
```bash
curl -X POST http://localhost:8787/v2/init
```

### Test Stream (will fail without valid session)
```bash
curl "http://localhost:8787/v2/stream?url=https://example.com/test.m3u8&sid=test&token=test"
```

## Protection Modes

Set `PROTECTION_MODE` in wrangler.toml:

| Mode | Description |
|------|-------------|
| `none` | No protection (legacy) |
| `basic` | Token + fingerprint |
| `fortress` | PoW + session chaining |
| `quantum` | V1 quantum shield |
| `quantum-v2` | V2 with behavioral analysis |

## What V2 Adds Over V1

1. **Dynamic Challenges** - Canvas, audio, WebGL, mouse path, typing tests
2. **Behavioral Analysis** - Mouse entropy, scroll patterns, keystroke timing
3. **Automation Detection** - WebDriver, CDP, plugin anomalies
4. **Impossible Travel** - Geographic consistency checks
5. **Trust Score System** - Violations reduce score, too low = blacklist

## Debugging

### View Worker Logs
```bash
# In cloudflare-proxy directory
npx wrangler tail media-proxy-dev
```

### Check KV Contents
```bash
# List sessions
npx wrangler kv:key list --binding=SESSION_KV --env=development

# Get specific session
npx wrangler kv:key get --binding=SESSION_KV "v2:SESSION_ID" --env=development
```

### Clear KV (Reset State)
```bash
rm -rf .wrangler/state
```

## Production Deployment

### 1. Create KV Namespaces
```bash
wrangler kv:namespace create "SESSION_KV"
wrangler kv:namespace create "BLACKLIST_KV"
```

### 2. Add KV IDs to wrangler.toml
```toml
[[kv_namespaces]]
binding = "SESSION_KV"
id = "your-session-kv-id"

[[kv_namespaces]]
binding = "BLACKLIST_KV"
id = "your-blacklist-kv-id"
```

### 3. Set Secrets
```bash
wrangler secret put SIGNING_SECRET
wrangler secret put WATERMARK_SECRET
```

### 4. Deploy
```bash
npm run deploy:prod
```
