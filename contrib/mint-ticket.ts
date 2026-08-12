/**
 * Next.js edge route handler that mints download tickets.
 *
 * REFERENCE COPY — NOT DEPLOYED FROM HERE.
 *
 * The live implementation is in the web app repo at
 * `src/app/api/tools/download-ticket/route.ts`. This file is kept as the
 * executable spec for anyone reading this repo who needs to see what a client
 * must produce, without opening the other repository.
 *
 * Because it is a second copy of the same protocol in a different repo, it WILL
 * drift. Treat `app/security/tickets.py` in this repo as the authority: it is
 * what actually verifies the ticket, and it is what a mismatch is measured
 * against. If you change the format, change the verifier first.
 *
 * It is
 * the only component that holds TICKET_SECRET besides the downloader service
 * itself, and it is the place where "a human solved a Turnstile challenge"
 * becomes a short-lived, IP-bound credential the downloader can verify offline.
 *
 * Byte-compatibility contract with app/security/tickets.py:
 *   ticket   = base64url(payloadJson) + "." + base64url(hmacSha256(secret, payloadB64))
 *   payload  = {"jti":<32 hex>,"aud":"downloader","exp":<unix s>,"ip_hash":<16 hex>}
 *   ip_hash  = sha256(ip + IP_SALT) hex, first 16 chars
 *   base64url is UNPADDED ("=" stripped) and uses "-" and "_"
 *
 * Three details are load-bearing and easy to break:
 *  1. The MAC covers the base64url TEXT of the payload, not the JSON bytes, so
 *     the verifier never re-serialises anything. Sign exactly the string you
 *     put before the ".".
 *  2. `JSON.stringify` emits no whitespace and preserves insertion order, which
 *     matches Python's `json.dumps(..., separators=(",", ":"))` with the same
 *     key order: jti, aud, exp, ip_hash. Keep that order (see (1) - it does not
 *     strictly have to match for verification to succeed, but a divergence here
 *     is how the two implementations start drifting).
 *  3. `exp` is UNIX SECONDS. `Date.now()` is milliseconds. Forgetting the
 *     divide-by-1000 mints tickets valid until the year 57000, which the
 *     verifier deliberately rejects as `ticket_expired`.
 */

export const runtime = "edge";
export const dynamic = "force-dynamic";

/**
 * WHY the secret must never reach the client.
 *
 * TICKET_SECRET is a symmetric HMAC key: anyone holding it can mint valid
 * tickets forever, for any IP hash they like, without ever loading the site or
 * seeing a Turnstile challenge. Shipping it to the browser would not weaken the
 * protection, it would delete it - and it would do so silently, because every
 * request would still look perfectly legitimate to the downloader.
 *
 * In Next.js, `process.env.X` is inlined into the client bundle whenever the
 * name starts with `NEXT_PUBLIC_`. So: never rename these with that prefix,
 * never read them inside a Client Component, never echo them into a response
 * body or an error message, and never put one in a URL (query strings land in
 * CDN logs, Referer headers and browser history).
 *
 * If it ever does leak: rotate TICKET_SECRET on both sides. Every outstanding
 * ticket dies within 120 seconds, so rotation is close to free.
 */
const TICKET_SECRET = process.env.TICKET_SECRET ?? "";
const IP_SALT = process.env.IP_SALT ?? "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET ?? "";

const TICKET_AUDIENCE = "downloader";
const TICKET_TTL_S = 120;
const IP_HASH_LEN = 16;
const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface TicketPayload {
  jti: string;
  aud: string;
  exp: number;
  ip_hash: string;
}

/** Unpadded base64url over raw bytes. */
function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < view.length; i += 1) {
    binary += String.fromCharCode(view[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** sha256(ip + IP_SALT), hex, truncated - identical to quotas.hash_ip. */
async function hashIp(ip: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${ip}${IP_SALT}`),
  );
  return toHex(digest).slice(0, IP_HASH_LEN);
}

async function hmacSha256(secret: string, message: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
}

/**
 * The client IP as the edge observed it.
 *
 * On Vercel the platform sets `x-forwarded-for` itself and the leftmost entry
 * is the true client - a header the visitor sends is replaced, not appended to,
 * so it cannot be forged here. This is precisely why the ip_hash binding is
 * worth anything: the value is derived at a point the client does not control.
 *
 * The assumption this rests on is that the same visitor reaches the downloader
 * from the same public address. That holds for ordinary browsing; it breaks for
 * a visitor whose traffic egresses through a rotating pool (some VPNs, some
 * corporate proxies, some mobile CGNAT), and those users will see a 401 and
 * have to retry. That is an acceptable trade for making a captured ticket
 * worthless to the machine that captured it.
 */
function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip")?.trim() ?? "";
}

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
  if (!TURNSTILE_SECRET || !token) return false;

  const body = new URLSearchParams({
    secret: TURNSTILE_SECRET,
    response: token,
    remoteip: ip,
  });

  try {
    const response = await fetch(SITEVERIFY_URL, {
      method: "POST",
      body,
      // Fail closed on a slow Cloudflare rather than hanging the request.
      signal: AbortSignal.timeout(6000),
    });
    if (!response.ok) return false;
    const result = (await response.json()) as { success?: boolean };
    return result.success === true;
  } catch {
    return false;
  }
}

/** Build the ticket. Exported so it can be unit-tested against Python vectors. */
export async function mintTicket(ip: string, ttlSeconds = TICKET_TTL_S): Promise<string> {
  const payload: TicketPayload = {
    jti: crypto.randomUUID().replace(/-/g, ""),
    aud: TICKET_AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    ip_hash: await hashIp(ip),
  };

  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = base64url(await hmacSha256(TICKET_SECRET, payloadB64));
  return `${payloadB64}.${signature}`;
}

export async function POST(request: Request): Promise<Response> {
  if (!TICKET_SECRET || !IP_SALT) {
    // Refuse to mint tickets the downloader cannot trust rather than emitting
    // garbage that fails verification with a confusing error two hops away.
    console.error("mint-ticket: TICKET_SECRET or IP_SALT is not configured");
    return json({ error: "misconfigured" }, 500);
  }

  let token = "";
  try {
    const body = (await request.json()) as { turnstileToken?: unknown };
    token = typeof body.turnstileToken === "string" ? body.turnstileToken : "";
  } catch {
    return json({ error: "bad_request" }, 400);
  }

  const ip = clientIp(request);
  if (!(await verifyTurnstile(token, ip))) {
    return json({ error: "turnstile_failed" }, 403);
  }

  const ticket = await mintTicket(ip);
  return json(
    { ticket, expiresIn: TICKET_TTL_S },
    200,
    // A ticket is single-use and IP-bound; a cached copy is at best useless and
    // at worst served to a second visitor behind a shared cache.
    { "cache-control": "no-store, private" },
  );
}

function json(
  body: unknown,
  status: number,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}
