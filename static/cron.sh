#!/bin/bash
#
# Default cron script for RapidBlock.

set -euo pipefail

export PATH="${PATH}:/opt/rapidblock/bin"

declare -i ENABLED=0
declare -i SLEEP_MIN=0
declare -i SLEEP_MAX=3600

if [ -e /etc/default/rapidblock ]; then
  . /etc/default/rapidblock
fi

if (( ! ENABLED )); then
  exit 0
fi

if [ -z "${NOW:+isset}" ]; then
  if (( SLEEP_MIN < SLEEP_MAX )); then
    SLEEP_VALUE=$(( SLEEP_MIN + ( RANDOM % ( SLEEP_MAX - SLEEP_MIN ) ) ))
  else
    SLEEP_VALUE=$(( SLEEP_MIN ))
  fi
  if (( SLEEP_VALUE > 0 )); then
    sleep $SLEEP_VALUE
  fi
fi

# Reload the defaults file after sleeping, in case it has changed.

ENABLED=0

if [ -e /etc/default/rapidblock ]; then
  . /etc/default/rapidblock
fi

if (( ! ENABLED )); then
  exit 0
fi

tmproot="$(mktemp -d -t "rapidblock.$$.XXXXXXXX")"
trap 'cd /; rm -rf "$tmproot"' EXIT
cd "$tmproot"

curl -fsSLR -o blocklist.json     "$BLOCKLIST_URL"
curl -fsSLR -o blocklist.json.sig "$SIGNATURE_URL"

rapidblock -m verify \
  -p "$PUBLIC_KEY_FILE" \
  -d blocklist.json \
  -s blocklist.json.sig \
  -t >/dev/null

for item in "${INSTANCES[@]}"; do
  software="${item%%|*}"
  pgurl="${item#*|}"
  rapidblock -m apply -d blocklist.json -x "$software" -D "$pgurl"
done
