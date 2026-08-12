# downloader

A media resolver. It answers one question — *what are the real format URLs for this post?* — and
only moves bytes when the platform makes handing the URL to the browser impossible.

## The isolation rule

**Separate Railway project. Separate domain. Separate billing. Nothing shared with the portfolio.**

Not a preference. This service takes arbitrary URLs from the public internet, runs an extractor
stack that changes weekly, and shells out to ffmpeg on attacker-influenced media. It will
eventually get abused, rate-limited by an upstream, or hit with a takedown. When that happens the
blast radius must stop at this project: a different Railway project (own env vars, own Redis, own
usage meter), a different apex domain, a different Cloudflare zone. The portfolio must not share
a database, a secret, a domain, or a spend limit with it. If you find yourself adding a variable
that exists in both projects, stop and reconsider.

---

## Architecture in one paragraph

`POST /v1/resolve` runs `yt_dlp.extract_info(download=False)` and gets back format URLs. For
TikTok, Instagram, Facebook, X, Reddit and Pinterest those CDN URLs are fetchable straight from
the browser, so the response is `delivery: "direct"` and the service moves **zero bytes**. For
YouTube — IP-bound URLs, and separate video/audio streams that must be muxed — the response is
`delivery: "job"`, the client calls `POST /v1/jobs`, an arq worker downloads to `/scratch`, muxes
with ffmpeg, uploads to R2, and returns a presigned URL that expires. Everything is gated on a
120-second single-use HMAC ticket, a Turnstile check, per-IP-hash daily quotas, and a global
spend killswitch.

---

## Local development

```bash
cp .env.example .env          # fill TICKET_SECRET and IP_SALT at minimum
docker compose up --build     # api on :8080, redis on :6379

# Health
curl -s localhost:8080/healthz

# Mint a dev ticket and resolve something
TICKET=$(python -c "
import os; os.environ.setdefault('ENVIRONMENT','development')
os.environ.setdefault('TICKET_SECRET','$(grep TICKET_SECRET .env | cut -d= -f2)')
from app.security.tickets import mint_ticket; print(mint_ticket('127.0.0.1'))")

curl -s -X POST localhost:8080/v1/resolve \
  -H "X-Download-Ticket: $TICKET" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.tiktok.com/@user/video/1234567890"}' | jq
```

### Running it against the portfolio locally

Two traps, both of which present as `401 ticket_bad_signature` / `ip_mismatch`:

**1. Run the API on the host, not in Docker.** The ticket is bound to a hash of
the client IP, computed independently by the Next.js mint route and by this
service. In Docker the container sees the bridge gateway address while Next.js
sees the browser, so every ticket is rejected. `docker compose up -d redis minio`
and run uvicorn + arq on the host:

```bash
python -m venv .venv && ./.venv/bin/pip install -e .
PYTHONPATH=. ./.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
PYTHONPATH=. ./.venv/bin/arq app.jobs.worker.WorkerSettings      # second terminal
```

Set `SCRATCH_DIR=/tmp/dl-scratch` in `.env` — the container default `/scratch`
does not exist on a Mac and the worker will die on a read-only filesystem.

**2. Use ONE hostname everywhere.** `localhost` resolves to `::1` and `127.0.0.1`
is IPv4, so opening the site at `http://localhost:3000` while
`NEXT_PUBLIC_DOWNLOADER_API` points at `http://127.0.0.1:8080` makes Next hash
`::1` and this service hash `127.0.0.1`. Pick one — `127.0.0.1` for both — and
put the same origin in `ALLOWED_ORIGINS`.

(The related `::ffff:127.0.0.1` vs `127.0.0.1` split is handled in code: see
`normalise_ip` in `app/security/quotas.py` and `normaliseIp` in the mint route.
Those two must stay byte-identical.)

Run the suite with `PYTHONPATH=. pytest tests` (190 tests, no network required).

---

## Deploying to Railway

**1. Create a NEW Railway project.** Not a service inside the portfolio project — a new project,
so billing, env vars and suspension are all scoped separately.

**2. Add Redis.** Railway's Redis plugin. Copy its connection string into `REDIS_URL`.

**3. Add this service.** Point it at this repo. It is its own repository, so the
**Root Directory** is `/` and no Watch Paths filter is needed — every commit here
is a change to this service.
Builder is `DOCKERFILE` (see `railway.json`).

**4. Add a volume** mounted at `/scratch`. Without it, downloads land on the ephemeral layer and a
restart mid-job leaves nothing to clean up — the worker clears the directory on startup.

**5. Set the environment variables** from `.env.example`. Generate the two secrets properly:

```bash
openssl rand -hex 32   # TICKET_SECRET
openssl rand -hex 16   # IP_SALT
```

`TICKET_SECRET` must match the value used by whatever mints tickets (`contrib/mint-ticket.ts`).
The service refuses to boot in production if either is unset — that is deliberate: an unset HMAC
secret is an open endpoint with a bill attached.

**6. Create the R2 bucket** and add a lifecycle rule expiring objects after **6 hours**. The
presign TTL (`RESULT_TTL_S`, default 21600s) should never exceed it. Set `R2_ACCOUNT_ID`,
`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`.

**7. Put Cloudflare in front.** Point a domain at the Railway service, proxied. Add a WAF rate
limit on `/v1/*` — the app's per-IP quotas are the second line of defence, and a request Cloudflare
rejects costs you nothing at all. This is also where `CF-Connecting-IP` comes from, which is the
header both the ticket minter and `require_ticket` read.

**8. Verify:**

```bash
curl -s https://<your-domain>/healthz          # {"status":"ok"}
curl -s https://<your-domain>/readyz           # 503 until Redis is reachable
curl -s https://<your-domain>/v1/resolve -X POST -d '{}'   # 401 ticket_missing
```

If `/v1/resolve` returns 401 `ticket_missing` you are wired correctly. If it returns 401
`ticket_bad_signature` with `reason: ip_mismatch` in the logs, the minter and the service are
reading different client IPs — check that Cloudflare proxying is on.

---

## Cost per 1000 downloads

Assumes an average 35 MB file.

| Path | Platforms | Compute | Egress | **Per 1000** |
|---|---|---|---|---|
| Direct CDN handoff | TikTok, Instagram, Facebook, X, Reddit, Pinterest | metadata only, ~1.5s | none — the browser fetches the CDN | **~$0.10** |
| Worker + R2 | anything needing a mux | ~20s @ 2 vCPU | R2 egress is free | **~$2.00** |
| YouTube, audio only | YouTube (default) | ~15s | 3–5 MB via proxy | **~$20** |
| YouTube 1080p on residential proxy | YouTube (opt-in) | ~40s | 35 GB @ ~$5/GB | **~$180** ⚠️ |

That last row is the only line item here that can genuinely hurt you, which is why `mode="audio"`
is the YouTube default and `DAILY_SPEND_CAP_MICRO_USD` exists. `estimate_job_micro_usd()` models
all four and trips `killswitch:global` when the day's total crosses the cap.

---

## What breaks, and how you will know

**yt-dlp extractor rot — the certainty, not a risk.** Platforms rotate signature ciphers and player
code continuously. A pinned yt-dlp works for about a week and then starts failing one platform at a
time, quietly, while `/healthz` still returns 200. Two defences: the worker runs
`pip install --upgrade yt-dlp` on startup, and the **canary** resolves one known-public URL per
platform every 30 minutes. Two consecutive failures mark that platform `degraded` in Redis, and
`/v1/resolve` then answers `platform_degraded` with an honest message instead of a stack trace.
Watch `downloader_platform_degraded` on `/metrics`.

**YouTube blocking datacenter IPs.** Railway's egress is a datacenter range, so YouTube will
throttle it. `app/resolver/proxies.py` escalates that platform's tier automatically after 3
consecutive 403/429s and de-escalates after 24 clean hours. Residential proxies are ~50x the cost
of datacenter, so an escalation that sticks is a bill worth investigating, not ignoring.

**Redis down.** Every quota and the spend cap live in Redis, so the service **fails closed** — 503
`killswitch_active` rather than serving unmetered. `/readyz` goes 503 first, which is what Railway's
healthcheck watches.

**Someone finds the endpoint.** Expect it within days of going live. The stack that stops it:
Cloudflare WAF → Turnstile on `POST /v1/jobs` → single-use 120s tickets bound to `ip_hash` →
per-IP daily resolve and byte quotas → global spend killswitch. Ticket rejections are counted by
reason on `/metrics`; a spike in `ticket_replayed` means someone is scripting against you.

**Privacy, deliberately.** Only URL *hashes* are logged, never URLs — see `app/logging_conf.py`,
which also redacts anything URL-shaped that slips into a message or traceback. There is no record
of who downloaded what. That is a design decision, not an omission: it has no product value and it
is the worst possible thing to hold if a legal request ever arrives.
# downloader-api
