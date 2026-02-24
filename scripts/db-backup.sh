#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
BACKUP_DIR="${1:-$ROOT_DIR/backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

POSTGRES_USER="${POSTGRES_USER:-case_study_user}"
POSTGRES_DB="${POSTGRES_DB:-case_study_leave}"
DB_CONTAINER="${DB_CONTAINER:-db}"

mkdir -p "$BACKUP_DIR"
OUTPUT_FILE="$BACKUP_DIR/${POSTGRES_DB}_${TIMESTAMP}.dump"

echo "Creating backup: $OUTPUT_FILE"
docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T "$DB_CONTAINER" \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$OUTPUT_FILE"

echo "Backup completed: $OUTPUT_FILE"
