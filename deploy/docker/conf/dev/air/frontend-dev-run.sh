#!/bin/sh
set -eu

mkdir -p /run/nginx /usr/share/nginx

exec nginx -g 'daemon off;'
