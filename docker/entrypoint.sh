#!/bin/sh
set -e
if [ -n "$PROBE_DATABASE_URL" ]; then
  echo "Waiting for database..."
  sleep 3
fi
python -c "
from udp_probe.core.database import init_db
init_db()
print('DB ready.')
" 2>/dev/null || true
exec python -m uvicorn udp_probe.api.app:create_app --factory --host 0.0.0.0 --port 8000
