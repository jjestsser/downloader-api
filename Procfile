# Both processes run in ONE Railway service, supervised by honcho.
#
# The tradeoff, stated plainly: splitting api and worker into two Railway services would be
# the textbook answer — independent scaling, a worker OOM would not take the API down. It does
# not work here. The worker writes the muxed file to disk and the API/job-status path reads it
# back before it is pushed to R2, and a Railway volume attaches to exactly one service. Two
# services means two disjoint filesystems, so the handoff would have to round-trip through R2
# even for files that are about to be deleted — extra egress, extra latency, extra failure mode.
# One service, one /scratch, one honcho.
#
# The cost of that choice: honcho exits when any child exits, which takes the API down with a
# crashed worker. That is intentional — Railway's restart policy then restarts the whole thing,
# and a half-dead service that accepts jobs it will never run is worse than a brief 502.
#
# --proxy-headers + --forwarded-allow-ips: Railway and Cloudflare both sit in front, and
# quota/ticket ip_hash values are worthless if every request looks like it came from the edge.
# Trusting * is only safe because nothing but the platform proxy can reach this port.

api: uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2 --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 65 --no-server-header
worker: arq app.jobs.worker.WorkerSettings
