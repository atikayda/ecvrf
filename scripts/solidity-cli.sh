#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
_stderr=$(mktemp)
trap 'rm -f "$_stderr"' EXIT

read_alpha() {
    if [ "$1" = "--alpha-file" ]; then
        cat "$2"
    else
        echo "$1"
    fi
}

CMD="$1"; shift

if [ "$CMD" = "prove" ]; then
    SK="$1"; shift
    ALPHA="$(read_alpha "$@")"
    OUTPUT=$(cd "$ROOT/solidity" && \
        ECVRF_CMD=prove ECVRF_SK="0x$SK" ECVRF_ALPHA="0x$ALPHA" \
        forge script script/Cli.s.sol -v 2>"$_stderr") || {
        echo "forge script failed (prove):" >&2
        cat "$_stderr" >&2
        exit 1
    }
    LINE=$(echo "$OUTPUT" | grep 'ECVRF_OUT:' | head -1 | sed 's/^[[:space:]]*//')
    PI=$(echo "$LINE" | cut -d: -f2 | sed 's/^0x//')
    BETA=$(echo "$LINE" | cut -d: -f3 | sed 's/^0x//')
    echo "{\"pi\":\"$PI\",\"beta\":\"$BETA\"}"

elif [ "$CMD" = "verify" ]; then
    PK="$1"; shift
    PI="$1"; shift
    ALPHA="$(read_alpha "$@")"
    OUTPUT=$(cd "$ROOT/solidity" && \
        ECVRF_CMD=verify ECVRF_PK="0x$PK" ECVRF_PI="0x$PI" ECVRF_ALPHA="0x$ALPHA" \
        forge script script/Cli.s.sol -v 2>"$_stderr") || true
    LINE=$(echo "$OUTPUT" | grep 'ECVRF_OUT:' | head -1 | sed 's/^[[:space:]]*//')
    if [ -z "$LINE" ]; then
        echo '{"valid":false,"beta":null}'
        exit 0
    fi
    VALID=$(echo "$LINE" | cut -d: -f2)
    BETA_RAW=$(echo "$LINE" | cut -d: -f3)
    if [ "$VALID" = "true" ]; then
        BETA=$(echo "$BETA_RAW" | sed 's/^0x//')
        echo "{\"valid\":true,\"beta\":\"$BETA\"}"
    else
        echo '{"valid":false,"beta":null}'
    fi
else
    echo "unknown command: $CMD" >&2
    exit 1
fi
