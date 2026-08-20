"""Loads the REAL tickets.py with its heavy dependencies stubbed.

Used by `src/lib/tools/download/ticket.test.ts` in the web repo, which mints a
ticket in TypeScript and compares it against what this produces. The two
implementations live in different languages in different repositories, and the
comment at the top of `contrib/mint-ticket.ts` predicts they *will* drift; this
is how that drift is caught by a test rather than by a 401 in production.

The point is to test against the actual verifier rather than a second copy of
its logic. Only `log` is used from logging_conf (which needs Python 3.11 for
datetime.UTC), and redis is never touched by the pure signing path.
"""
import sys, types, os, json

def stub(name, **attrs):
    m = types.ModuleType(name)
    for k, v in attrs.items(): setattr(m, k, v)
    sys.modules[name] = m
    return m

class _Log:
    def __getattr__(self, _): return lambda *a, **k: None

stub("app.logging_conf", log=_Log())

class _ApiError(Exception):
    def __init__(self, code, detail=None, **kw):
        super().__init__(code); self.code, self.detail = code, detail
stub("app.errors", ApiError=_ApiError)

class _Redis:
    async def set(self, *a, **k): return True
stub("app.redis_conn", get_redis=lambda: _Redis())

class _Settings:
    ticket_secret = os.environ["TICKET_SECRET"]
    ip_salt = os.environ["IP_SALT"]
stub("app.settings", settings=_Settings())

# app.models uses `int | None`, which pydantic cannot evaluate on 3.9. Only
# TicketClaims is needed here, and only as a field carrier.
class _TicketClaims:
    def __init__(self, **kw):
        self.jti = kw["jti"]; self.aud = kw["aud"]
        self.exp = kw["exp"]; self.ip_hash = kw["ip_hash"]
stub("app.models", TicketClaims=_TicketClaims)

sys.path.insert(0, ".")
import app.security.quotas as q
import app.security.tickets as t

cmd = sys.argv[1]
if cmd == "mint":
    ip, exp_now, jti = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    # Force jti/now so the two implementations are comparable.
    payload = {"jti": jti, "aud": t.TICKET_AUDIENCE, "exp": exp_now + t.TICKET_TTL_S,
               "ip_hash": q.hash_ip(ip)}
    b64 = t._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    print(f"{b64}.{t._sign(b64)}")
elif cmd == "verify":
    raw = sys.argv[2]
    b64, payload = t._parse(raw.strip())
    claims = t._claims_from_payload(payload)
    print(json.dumps({"ok": True, "jti": claims.jti, "aud": claims.aud,
                      "exp": claims.exp, "ip_hash": claims.ip_hash}))
elif cmd == "haship":
    print(q.hash_ip(sys.argv[2]))
