#!/bin/sh
# osctrl-frontend container entrypoint.
#
# Selects between the HTTP-only and TLS nginx configs based on the
# OSCTRL_FRONTEND_TLS env var, then execs the official nginx image
# entrypoint so /docker-entrypoint.d/ scripts still run.
#
# TLS mode (OSCTRL_FRONTEND_TLS=1) expects certificates mounted at:
#   /etc/ssl/osctrl/tls.crt
#   /etc/ssl/osctrl/tls.key
# The image never bakes certs in; operators mount them at runtime.
set -eu

CONF_DIR=/etc/nginx/conf.d
HTTP_CONF=osctrl-frontend.conf
TLS_CONF=osctrl-frontend-tls.conf

# Remove any default nginx server block shipped by the base image.
rm -f "$CONF_DIR/default.conf"

if [ "${OSCTRL_FRONTEND_TLS:-0}" = "1" ]; then
    if [ ! -f /etc/ssl/osctrl/tls.crt ] || [ ! -f /etc/ssl/osctrl/tls.key ]; then
        echo "OSCTRL_FRONTEND_TLS=1 but /etc/ssl/osctrl/tls.crt or tls.key is missing." >&2
        echo "Mount your certificate and key at those paths and retry." >&2
        exit 1
    fi
    echo "OSCTRL_FRONTEND_TLS=1 — enabling HTTPS on :443 with HTTP→HTTPS redirect on :80"
    ln -sf /etc/nginx/conf.d-available/$TLS_CONF "$CONF_DIR/$TLS_CONF"
    rm -f "$CONF_DIR/$HTTP_CONF"
else
    echo "OSCTRL_FRONTEND_TLS not set — serving HTTP on :80 (use a reverse proxy for TLS)"
    ln -sf /etc/nginx/conf.d-available/$HTTP_CONF "$CONF_DIR/$HTTP_CONF"
    rm -f "$CONF_DIR/$TLS_CONF"
fi

exec nginx -g 'daemon off;'
