#!/bin/sh
# apt-get for CI, with a time limit and retries: a mirror that stops answering ends the try after
# the limit instead of holding the job until its own timeout, and a failed try prints why.
#
#   sh tools/apt-get.sh update
#   sh tools/apt-get.sh install [--no-install-recommends] PACKAGE...
#
# apt itself retries downloads and gives up on a silent connection after 30 seconds; each try
# as a whole may take APT_LIMIT seconds (default 300); there are 3 tries, 15 seconds apart.
# Runs apt-get directly as root, else through sudo. The output goes to a log that is shown only
# when a try fails.
# SPDX-License-Identifier: Apache-2.0
set -eu

LIMIT=${APT_LIMIT:-300}
TRIES=3
OPTS="-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=120"

case "${1:-}" in
    update) set -- update -qq ;;
    install) shift; set -- install -y -qq "$@" ;;
    *) echo "usage: $0 update | install [--no-install-recommends] PACKAGE..." >&2; exit 64 ;;
esac

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

try=1
while :; do
    rc=0
    # shellcheck disable=SC2086 # $SUDO and $OPTS are lists of words
    $SUDO env DEBIAN_FRONTEND=noninteractive timeout --kill-after=15 "$LIMIT" apt-get $OPTS "$@" > "$LOG" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        exit 0
    fi
    why=""
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        why=" (no end within $LIMIT seconds)"
    fi
    echo "apt-get $1: try $try of $TRIES ended with exit code $rc$why" >&2
    tail -n 20 "$LOG" >&2
    if [ "$try" -ge "$TRIES" ]; then
        exit "$rc"
    fi
    try=$((try + 1))
    sleep 15
done
