api: uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2 --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 65 --no-server-header
worker: arq app.jobs.worker.WorkerSettings
