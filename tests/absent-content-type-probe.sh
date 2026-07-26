#!/bin/bash
# Absent-Content-Type fail-open probe for 9530225 (plugin 2.2.1).
#
# WHY THIS IS NOT A go-ftw TEST: go-ftw injects a default Content-Type on every
# request it sends (testoverride), so the "header is entirely absent" case
# cannot be expressed in a .yaml test -- a yaml case written for it would pass
# for the wrong reason. The request has to go over a raw socket. This script is
# the executable record of that check.
#
# WHAT IT PROVES: a POST to /api with NO Content-Type header must still trip
# 9530225. Before 2.2.1 the last chain link tested REQUEST_HEADERS:Content-Type
# directly with a negated operator; a negated operator against an ABSENT
# variable never matches, so the chain broke and the request FAILED OPEN.
# 2.2.1 seeds the value into TX first (9530224), giving it a definite empty
# value when the header is missing.
#
# Requires the integration stack up:
#   docker compose -f tests/integration/docker-compose.yml up -d
# Run from the repo root:  ./tests/absent-content-type-probe.sh
#
# Note: the CI backend answers 200 to almost everything and CRS runs in
# DetectionOnly there, so the HTTP STATUS IS NOT THE SIGNAL. The audit log is.
#
# Checks both engines by default. Pass `apache` or `nginx` to check only one --
# the per-engine CI jobs bring up only their own container, so they scope it.
set -u

case "${1:-both}" in
  apache) ENGINES="apache:8001" ;;
  nginx)  ENGINES="nginx:8002" ;;
  both)   ENGINES="apache:8001 nginx:8002" ;;
  *) echo "usage: $0 [apache|nginx|both]" >&2; exit 2 ;;
esac

fail=0
for eng in $ENGINES; do
  name=${eng%%:*}; port=${eng##*:}
  log="tests/logs/$name/audit.log"

  # Truncate first: re-reading a stale tail would report a PREVIOUS run's hit.
  sudo truncate -s 0 "$log" 2>/dev/null || : > "$log"

  printf 'POST /api/ciphers HTTP/1.1\r\nHost: ci.local\r\nContent-Length: 3\r\n\r\nx=1' \
    | timeout 5 nc localhost "$port" >/dev/null 2>&1
  sleep 1
  sudo chmod -R a+rX tests/logs 2>/dev/null || :

  if sudo grep -q '\[id "9530225"\]' "$log" 2>/dev/null; then
    echo "PASS $name: 9530225 fired on absent Content-Type"
  else
    echo "FAIL $name: 9530225 did NOT fire -- absent-variable fail-open is back"
    fail=1
  fi
done

exit "$fail"
