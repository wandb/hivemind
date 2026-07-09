#!/bin/sh
# Nightly ClickHouse backup to object storage, with retention pruning.
#
# Runs in the `clickhouse-backup` sidecar (rclone/rclone image) when the
# `backup` compose profile is active — `hivemind serve setup` enables it after
# you choose object storage. The backup itself is ClickHouse's native
# `BACKUP ... TO S3` (consistent, captures schema + data, works whether tables
# live on the local disk or the S3 storage policy); the prune is
# `rclone delete --min-age`. Both target <bucket>/clickhouse-backups/ and reuse
# the app's S3 credentials. See docs/self-hosting.md ("Backups").
#
# Manual one-off run (e.g. to read the full error on failure):
#   docker compose exec clickhouse-backup /bin/sh /usr/local/bin/clickhouse-backup.sh
set -eu

CH_URL="${CLICKHOUSE_HTTP_URL:-http://clickhouse:8123}"
DB="${CLICKHOUSE_DB:-agentstream}"
KEEP="${CLICKHOUSE_BACKUP_RETENTION_DAYS:-3}"
ENDPOINT="${CLICKHOUSE_BACKUP_S3_ENDPOINT:?set CLICKHOUSE_BACKUP_S3_ENDPOINT (run hivemind serve setup)}"
RCLONE_PATH="${CLICKHOUSE_BACKUP_RCLONE_PATH:?set CLICKHOUSE_BACKUP_RCLONE_PATH}"
: "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}"

log() { echo "[ch-backup] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

run_once() {
    ts=$(date -u +%Y-%m-%dT%H%M%SZ)
    dest="${ENDPOINT%/}/$ts"
    log "backup -> $dest"

    # ClickHouse returns "<id>\tBACKUP_CREATED" on success; a failed BACKUP is
    # an HTTP 500 (wget exits non-zero). Never prune unless the backup landed.
    query="BACKUP DATABASE \`$DB\` TO S3('$dest', '$AWS_ACCESS_KEY_ID', '$AWS_SECRET_ACCESS_KEY') SETTINGS compression_method='zstd'"
    if ! resp=$(wget -q -O - --post-data="$query" "$CH_URL/" 2>/tmp/ch.err); then
        log "BACKUP request failed:"
        cat /tmp/ch.err >&2
        return 1
    fi
    if ! printf '%s' "$resp" | grep -q "BACKUP_CREATED"; then
        log "unexpected BACKUP response: $resp"
        return 1
    fi
    log "backup complete ($resp)"

    # Every object in a given backup folder is written at backup time, so
    # --min-age cleanly drops whole folders older than the retention window.
    # (No pipe here: a `... | sed` would mask rclone's exit status under set -e.)
    log "pruning backups older than ${KEEP}d under $RCLONE_PATH"
    if ! rclone delete "$RCLONE_PATH" --min-age "${KEEP}d" --rmdirs -v; then
        log "prune failed (the backup itself succeeded)"
        return 1
    fi
    log "prune complete"
}

run_daemon() {
    hour="${CLICKHOUSE_BACKUP_HOUR:-3}"
    log "daemon mode: nightly at ${hour}:00 UTC, keeping ${KEEP} day(s)"
    while true; do
        h=$(date -u +%H)
        m=$(date -u +%M)
        s=$(date -u +%S)
        # 10# forces base-10 so leading-zero hours (08, 09) aren't read as octal.
        since=$(( (10#$h * 3600) + (10#$m * 60) + 10#$s ))
        target=$(( hour * 3600 ))
        if [ "$since" -le "$target" ]; then
            naptime=$(( target - since ))
        else
            naptime=$(( 86400 - since + target ))
        fi
        log "next run in ${naptime}s"
        sleep "$naptime"
        run_once || log "backup cycle failed; will retry next cycle"
    done
}

if [ "${1:-}" = "--daemon" ]; then
    run_daemon
else
    run_once
fi
