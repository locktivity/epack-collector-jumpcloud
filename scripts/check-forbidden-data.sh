#!/usr/bin/env bash
set -euo pipefail

# Checks that collector output structs do not accidentally include sensitive
# data fields. Any line matching a forbidden pattern that is NOT annotated
# with "// LINT-ALLOW" is flagged.

FORBIDDEN_PATTERNS=(
  '\.Password'
  '\.ApiKey'
  '\.SecretKey'
  '\.Token\b'
  '\.PrivateKey'
)

EXIT=0

for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  MATCHES=$(grep -rn --include='*.go' -E "$pattern" internal/collector/ || true)
  if [ -n "$MATCHES" ]; then
    FILTERED=$(echo "$MATCHES" | grep -v 'LINT-ALLOW' || true)
    if [ -n "$FILTERED" ]; then
      echo "FORBIDDEN DATA: pattern '$pattern' found without LINT-ALLOW:"
      echo "$FILTERED"
      EXIT=1
    fi
  fi
done

if [ $EXIT -eq 0 ]; then
  echo "check-forbidden-data: OK"
fi
exit $EXIT
