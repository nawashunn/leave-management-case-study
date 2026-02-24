#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Creating pre-shutdown database backup..."
"$ROOT_DIR/scripts/db-backup.sh"

echo "Backup completed. Running docker compose down $*"
docker compose -f "$ROOT_DIR/docker-compose.yml" down "$@"
