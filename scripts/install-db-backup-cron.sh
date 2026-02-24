#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_SCRIPT="$ROOT_DIR/scripts/scheduled-db-backup.sh"
BACKUP_LOG="$ROOT_DIR/backups/backup-cron.log"
CRON_TAG="# CASE_STUDY_LMS_DB_BACKUP"

# Default schedule: daily 02:30 local machine time
CRON_EXPR="${1:-30 2 * * *}"
CRON_LINE="$CRON_EXPR $BACKUP_SCRIPT >> $BACKUP_LOG 2>&1 $CRON_TAG"

mkdir -p "$ROOT_DIR/backups"

CURRENT_CRON="$(crontab -l 2>/dev/null || true)"
FILTERED_CRON="$(printf '%s\n' "$CURRENT_CRON" | sed '/CASE_STUDY_LMS_DB_BACKUP/d')"
UPDATED_CRON="$(printf '%s\n%s\n' "$FILTERED_CRON" "$CRON_LINE" | sed '/^[[:space:]]*$/d')"

printf '%s\n' "$UPDATED_CRON" | crontab -

echo "Installed cron schedule:"
echo "$CRON_LINE"
