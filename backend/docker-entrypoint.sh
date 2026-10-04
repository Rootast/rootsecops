#!/bin/sh
set -eu

mkdir -p /app/var/scans /app/var/uploads /app/var/file_sandbox /app/var/yara_rules /app/var/tool_locks /app/var/logs /app/var/tmp /app/var/trivy /app/var/grype/db

if [ "${UPDATE_CLAMAV_DB_ON_START:-false}" = "true" ]; then
  freshclam || true
fi

python manage.py migrate --noinput
python manage.py seed_scanners || true

if [ "${BOOTSTRAP_ADMIN_ON_START:-false}" = "true" ]; then
  python manage.py bootstrap_admin
fi

if [ "${SEED_YARA_RULES:-false}" = "true" ]; then
  python manage.py seed_yara_rules || true
fi

exec "$@"
