#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <backup_file.dump> [target_db]"
  exit 1
fi

BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Backup file not found: $BACKUP_FILE"
  exit 1
fi

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

POSTGRES_USER="${POSTGRES_USER:-case_study_user}"
DEFAULT_DB="${POSTGRES_DB:-case_study_leave}"
TARGET_DB="${2:-${DEFAULT_DB}_restore_test}"
DB_CONTAINER="${DB_CONTAINER:-db}"

echo "Preparing target database: $TARGET_DB"
docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T "$DB_CONTAINER" \
  psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS \"$TARGET_DB\";" \
  -c "CREATE DATABASE \"$TARGET_DB\";"

echo "Restoring backup into: $TARGET_DB"
docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T "$DB_CONTAINER" \
  pg_restore -U "$POSTGRES_USER" -d "$TARGET_DB" --no-owner --no-privileges < "$BACKUP_FILE"

echo "Restore completed: $TARGET_DB"
