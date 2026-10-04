#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Run with an existing worker during a maintenance window without active scans.
# Updates may take several GB of disk space. Any failure stops this script.
docker compose exec -T worker sh -eu -c '
  cache="${TRIVY_CACHE_DIR:-/app/var/trivy}"
  mkdir -p "$cache" "$GRYPE_DB_CACHE_DIR"
  trivy image --cache-dir "$cache" --download-db-only
  trivy image --cache-dir "$cache" --download-java-db-only
  GRYPE_DB_AUTO_UPDATE=true grype db update
  test -s "$cache/db/trivy.db"
  test -s "$cache/java-db/trivy-java.db"
  GRYPE_DB_AUTO_UPDATE=false grype db status
'
printf '%s\n' "Trivy vulnerability + Java databases and Grype database are ready."
