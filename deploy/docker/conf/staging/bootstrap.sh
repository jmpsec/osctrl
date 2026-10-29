#!/bin/bash
set -euo pipefail

export PATH="/opt/osctrl/bin:$PATH"
: "${OSCTRL_USER:?OSCTRL_USER is required}"
: "${OSCTRL_PASS:?OSCTRL_PASS is required}"
: "${STAGING_TLS_HOST:?STAGING_TLS_HOST is required}"

if ! osctrl-cli --db env show --name staging >/dev/null 2>&1; then
  osctrl-cli --db env add --name staging --hostname "$STAGING_TLS_HOST" \
    --certificate /opt/osctrl/config/osctrl.crt
fi

if ! osctrl-cli --db user show --username "$OSCTRL_USER" >/dev/null 2>&1; then
  osctrl-cli --db user add --admin --username "$OSCTRL_USER" \
    --password "$OSCTRL_PASS" --environment staging --fullname "$OSCTRL_USER"
fi

echo 'Staging environment and administrator are ready.'
