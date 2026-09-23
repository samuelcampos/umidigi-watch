#!/bin/bash
# Launch the CLI inside Uwatch.app via LaunchServices (so macOS grants it
# Bluetooth) and stream its output back to this terminal.
set -uo pipefail

APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTENTS="$APP/Contents"
MARKER='__UWATCH_EXIT__'
OUT="$(mktemp "${TMPDIR:-/tmp}/uwatch.XXXXXX")"
trap 'rm -f "$OUT"' EXIT

open -n -a "$APP" --args "$CONTENTS/bundle_main.py" "$OUT" "$@" || {
    echo "failed to launch $APP" >&2; exit 1; }

# Tail until the child reports its exit status, or it goes silent for too long.
deadline=$((SECONDS + 600))
idle_limit=240
last_change=$SECONDS
last_size=0
printed=0
while [ $SECONDS -lt $deadline ]; do
    size=$(wc -c < "$OUT" 2>/dev/null | tr -d ' ')
    if [ "${size:-0}" -gt "$last_size" ]; then
        last_change=$SECONDS
        tail -c +$((last_size + 1)) "$OUT" | grep -av "$MARKER"
        last_size=$size
        printed=1
    fi
    if grep -q "$MARKER" "$OUT" 2>/dev/null; then
        # flush whatever was written between the last poll and the exit marker
        size=$(wc -c < "$OUT" | tr -d ' ')
        [ "${size:-0}" -gt "$last_size" ] && \
            tail -c +$((last_size + 1)) "$OUT" | grep -av "$MARKER"
        code=$(grep -a "$MARKER" "$OUT" | tail -1 | sed "s/.*$MARKER//")
        exit "${code:-0}"
    fi
    [ $((SECONDS - last_change)) -gt $idle_limit ] && {
        echo "error: the watch stopped responding" >&2; exit 1; }
    sleep 0.2
done
[ $printed -eq 1 ] || echo "error: timed out waiting for Uwatch.app" >&2
exit 1
