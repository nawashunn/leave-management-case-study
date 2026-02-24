#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting scheduled DB backup"
"$ROOT_DIR/scripts/db-backup.sh" "$BACKUP_DIR"

# Keep recent backups only (default: last 30 days)
find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.dump' -mtime +"$RETENTION_DAYS" -print -delete || true

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scheduled DB backup finished"
