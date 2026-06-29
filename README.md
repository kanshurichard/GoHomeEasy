# GoHomeEasy

GoHomeEasy v2 receives Lucky webhooks, stores multiple records keyed by `ruleName`, and renders Shadowsocks or Clash subscriptions on demand.

Supported deployments:

- Cloudflare Workers + KV
- AWS Lambda + DynamoDB
- Self-hosted Go
- Self-hosted Python (`gohomeeasy.py` + `dashboard.html`)

## V2 behavior

- `ruleName` is required, trimmed, case-sensitive, and limited to 128 UTF-8 bytes.
- Duplicate `ruleName` means update, not reject.
- Supported record types are `ss` and `site`.
- Missing `type` defaults to `ss`.
- `type=site` must be explicit and must not include `method` or `password`.
- Only `ss` records enter subscriptions. `site` records are shown in the dashboard only.
- If there are no v2 `ss` records yet, legacy subscription content is still returned as a fallback.
- Cloudflare KV and DynamoDB GSI reads are eventually consistent. Right after a write or delete, `/subscription`, `/dashboard`, and `/api/records` may briefly show stale data.

## Routes

| Route | Method | Purpose |
| :--- | :--- | :--- |
| `/` | `POST` | Lucky webhook |
| `/webhook` | `POST` | Alias of `/` |
| `/?api_key=...` | `GET` | Legacy subscription entry, still respects `SUBSCRIPTION_FORMAT` when `subtype` is omitted |
| `/subscription?subtype=ss|clash&api_key=...` | `GET` | Explicit subscription entry |
| `/dashboard?api_key=...` | `GET` | Exchanges token for a signed session cookie, then redirects to clean `/dashboard` |
| `/api/records` | `GET` | Dashboard data API |
| `/api/delete` | `POST` | Deletes a record by `ruleName` |
| `/healthz` | `GET` | Health check |

Rules:

- `Authorization: Bearer READ_TOKEN` works on both subscription routes and overrides `?api_key=`.
- `?api_key=` only works on `/`, `/subscription`, and `/dashboard`.
- `/api/*` always ignores query tokens.
- `/api/records` accepts a read/write dashboard cookie or `Authorization: Bearer READ_TOKEN|WRITE_TOKEN`.
- `/api/delete` accepts `Authorization: Bearer WRITE_TOKEN`, or a write-mode cookie plus same-origin `Origin`.
- If `SESSION_SECRET` is unset, `/dashboard` and `/api/*` return `500 dashboard not configured`.

## Webhook payload rules

- Address priority is `ip` -> `host` -> `server`.
- Once a non-empty address field is chosen, an invalid value returns `400`; it does not fall through to the next field.
- `ipAddr` is used only when `ip`, `host`, and `server` are all empty.
- `ipAddr` must be `host:port` or `[ipv6]:port`. When `ipAddr` is used, the standalone `port` field is ignored.
- `time`, when present, is copied to `sourceTime`.
- Lucky webhook only upserts. Rename and delete are manual operations.

Shadowsocks record example:

```json
{
  "ruleName": "Home-SS",
  "ip": "#{ip}",
  "port": "#{port}",
  "method": "chacha20-ietf-poly1305",
  "password": "replace-with-password"
}
```

Site record example:

```json
{
  "ruleName": "Home-NAS",
  "type": "site",
  "host": "nas.example.com",
  "port": 443,
  "time": "#{time}"
}
```

## Required webhook fields

| Record type | Required fields | Optional fields | Notes |
| :--- | :--- | :--- | :--- |
| `ss` | `ruleName`, one address source, `method`, `password` | `type`, `time` | `type` may be omitted because it defaults to `ss` |
| `site` | `ruleName`, `type=site`, one address source | `time` | `method` and `password` must be absent |

Address source means one of these shapes:

- `ip` + `port`
- `host` + `port`
- `server` + `port`
- `ipAddr` as `host:port` or `[ipv6]:port`

Examples:

- Update an existing record by reusing the same `ruleName`
- Create a `site` record with `type=site`
- Use `time` only when you want the original Lucky timestamp shown in the dashboard

## Configuration

| Variable | Required | Purpose |
| :--- | :--- | :--- |
| `READ_TOKEN` | Yes | Read access for subscriptions and read-only dashboard login |
| `WRITE_TOKEN` | Yes | Write access for Lucky webhook and delete operations |
| `SESSION_SECRET` | Required for dashboard/API | HMAC secret used to sign dashboard cookies |
| `SESSION_TTL_SECONDS` | No | Dashboard cookie TTL, default `86400` |
| `SUBSCRIPTION_FORMAT` | No | Default output format for legacy root `GET /`, default `ss` |
| `ALLOWED_METHODS` | No | Comma-separated Shadowsocks cipher allowlist override |
| `TABLE_NAME` | AWS only | DynamoDB table name |
| `RECORD_INDEX_NAME` | AWS only | GSI name, default `RecordIndex` |
| `LISTEN_ADDR` | Go/Python only | Listen address, default `127.0.0.1:8080` |
| `STORAGE_PATH` | Go/Python only | Local JSON document path, default `./data/records.json` |
| `KV_NAMESPACE` | Workers only | KV binding name in `wrangler.jsonc` |

## Local verification

Run the full automated suite:

```bash
make test
```

Or run each stack separately:

```bash
npm install
npm test
go test ./...
python3 -m unittest discover -s pytests -p 'test_*.py' -v
```

## Calling examples

Create or update a Shadowsocks record:

```bash
curl -X POST 'https://your-endpoint.example.com/webhook' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "ruleName": "Home-SS",
    "host": "edge.example.com",
    "port": 443,
    "method": "aes-256-gcm",
    "password": "replace-with-password"
  }'
```

Create a dashboard-only `site` record:

```bash
curl -X POST 'https://your-endpoint.example.com/webhook' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "ruleName": "Home-NAS",
    "type": "site",
    "host": "nas.example.com",
    "port": 443
  }'
```

Fetch subscriptions:

```bash
curl 'https://your-endpoint.example.com/subscription?subtype=ss&api_key=READ_TOKEN'
curl 'https://your-endpoint.example.com/subscription?subtype=clash&api_key=READ_TOKEN'
curl -H 'Authorization: Bearer READ_TOKEN' 'https://your-endpoint.example.com/'
```

Read dashboard data without opening the UI:

```bash
curl -H 'Authorization: Bearer READ_TOKEN' \
  'https://your-endpoint.example.com/api/records'
```

Delete a record by `ruleName`:

```bash
curl -X POST 'https://your-endpoint.example.com/api/delete' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"ruleName":"Home-SS"}'
```

## Cloudflare Workers

Workers is the primary deployment target for v2.

1. Install dependencies:

```bash
npm install
```

2. Create a KV namespace and put its id into [`wrangler.jsonc`](wrangler.jsonc).

3. Set required secrets:

```bash
npx wrangler secret put READ_TOKEN
npx wrangler secret put WRITE_TOKEN
npx wrangler secret put SESSION_SECRET
```

4. Adjust runtime vars in [`wrangler.jsonc`](wrangler.jsonc):

- `main: "GoHomeEasy_CF.js"` uses `SUBSCRIPTION_FORMAT`
- `GoHomeEasy_CF_SS.js` and `GoHomeEasy_CF_Clash.js` are fixed-format wrappers
- `SESSION_TTL_SECONDS` is optional

5. Deploy:

```bash
npx wrangler deploy
```

Known limitation:

- KV is eventually consistent across PoPs. After an update or delete, readers in another region may briefly see old data.

## AWS Lambda + DynamoDB

1. Install dependencies:

```bash
npm install
```

2. Create a DynamoDB table:

- Table name: `Subscription` or your own value
- Partition key: `id` (String)

3. Add a GSI for v2 records:

- Index name: `RecordIndex` or your own value
- Partition key: `gsi1pk` (String)
- Sort key: `gsi1sk` (String)

4. Package the Lambda code:

```bash
zip -r gohomeeasy-aws.zip GoHomeEasy_AWS.js GoHomeEasy_AWS_SS.js GoHomeEasy_AWS_Clash.js src package.json package-lock.json node_modules
```

5. Configure environment variables:

- `READ_TOKEN`
- `WRITE_TOKEN`
- `SESSION_SECRET`
- `TABLE_NAME=Subscription`
- `RECORD_INDEX_NAME=RecordIndex` if you did not use the default
- `SUBSCRIPTION_FORMAT=ss` or `clash` if you use `GoHomeEasy_AWS.js`

6. Set the handler:

- `GoHomeEasy_AWS.handler`
- `GoHomeEasy_AWS_SS.handler`
- `GoHomeEasy_AWS_Clash.handler`

7. Grant the Lambda role:

- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:DeleteItem`
- `dynamodb:Query`

8. Expose the function through API Gateway HTTP API.

Known limitation:

- DynamoDB GSI reads are eventually consistent. Just-written or just-deleted records may not be visible immediately.

## Self-host with Go

1. Build:

```bash
go build -o gohomeeasy ./cmd/gohomeeasy
```

2. Export variables:

```bash
export READ_TOKEN=replace-with-read-token
export WRITE_TOKEN=replace-with-write-token
export SESSION_SECRET=replace-with-long-random-secret
export SUBSCRIPTION_FORMAT=ss
export LISTEN_ADDR=127.0.0.1:8080
export STORAGE_PATH=/var/lib/gohomeeasy/records.json
```

3. Start:

```bash
./gohomeeasy
```

4. Put Nginx or Caddy in front if you want TLS and a public domain.

5. A sample [`gohomeeasy.service`](gohomeeasy.service) is included for `systemd`.

6. If you use Nginx, start from [`deploy/nginx-gohomeeasy.conf.example`](deploy/nginx-gohomeeasy.conf.example). The forwarded `Host` and `X-Forwarded-Proto` headers are required for correct dashboard origin checks and secure cookies.

## Self-host with Python

This path does not need Node.js or extra Python packages.

1. Export variables:

```bash
export READ_TOKEN=replace-with-read-token
export WRITE_TOKEN=replace-with-write-token
export SESSION_SECRET=replace-with-long-random-secret
export SUBSCRIPTION_FORMAT=ss
export LISTEN_ADDR=127.0.0.1:8080
export STORAGE_PATH=/var/lib/gohomeeasy/records.json
```

2. Start:

```bash
python3 gohomeeasy.py
```

3. Keep [`dashboard.html`](dashboard.html) next to [`gohomeeasy.py`](gohomeeasy.py).

4. A sample [`gohomeeasy-python.service`](gohomeeasy-python.service) is included for `systemd`.

5. If you use Nginx, start from [`deploy/nginx-gohomeeasy.conf.example`](deploy/nginx-gohomeeasy.conf.example). Forwarded proxy headers are required here too.

## Reverse proxy notes for Go/Python

- Terminate TLS at Nginx or Caddy and proxy to `127.0.0.1:8080`.
- Forward `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`.
- Without those headers, dashboard-origin checks and `Secure` cookie behavior will be wrong.

## Post-deploy smoke test

Use the built-in script after any deploy or config change:

```bash
./scripts/smoke-test.sh https://your-endpoint.example.com READ_TOKEN WRITE_TOKEN
```

Or through the Makefile:

```bash
make smoke ENDPOINT=https://your-endpoint.example.com READ_TOKEN=... WRITE_TOKEN=...
```

The smoke test checks:

- `/healthz`
- webhook upsert
- SS and Clash subscriptions
- `/api/records`
- dashboard login redirect
- `/api/delete` cleanup

## Subscription URLs

- Legacy-compatible root: `GET /?api_key=READ_TOKEN`
- Explicit SS: `GET /subscription?subtype=ss&api_key=READ_TOKEN`
- Explicit Clash: `GET /subscription?subtype=clash&api_key=READ_TOKEN`
- Header auth also works: `Authorization: Bearer READ_TOKEN`

Root compatibility matters because old clients without `subtype` still keep following `SUBSCRIPTION_FORMAT`.

## Dashboard

The dashboard is a static HTML page with no build step.

- Shows SS and Clash subscription URLs
- Lists both `ss` and `site` records
- Hides passwords by default and allows reveal in the browser
- Disables delete in read-only mode
- Shows a legacy fallback notice when no v2 `ss` record exists yet

## Notes

- Records are rendered into subscriptions in ascending `ruleName` order for stable output.
- `site` records never appear in subscriptions.
- If no v2 `ss` record exists and no legacy content exists, subscription routes return `204`.
- Existing plain-string self-hosted storage files are treated as legacy content on first read, so upgrades do not blank subscriptions immediately.
