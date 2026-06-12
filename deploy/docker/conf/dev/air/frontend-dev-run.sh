#!/bin/sh
set -eu

mkdir -p /run/nginx /usr/share/nginx/osctrl-frontend

if ! pgrep -x nginx >/dev/null 2>&1; then
  nginx
fi

while true; do
  sleep 3600
done
