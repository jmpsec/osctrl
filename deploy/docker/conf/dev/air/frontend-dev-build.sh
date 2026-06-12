#!/bin/sh
set -eu

FRONTEND_DIR="/usr/src/app/frontend"
DOCROOT="/usr/share/nginx/osctrl-frontend"
STAMP_FILE="${FRONTEND_DIR}/node_modules/.osctrl-deps.sha256"

cd "$FRONTEND_DIR"

deps_hash() {
  {
    sha256sum package.json
    if [ -f package-lock.json ]; then
      sha256sum package-lock.json
    fi
  } | sha256sum | awk '{print $1}'
}

CURRENT_HASH="$(deps_hash)"
INSTALLED_HASH=""
if [ -f "$STAMP_FILE" ]; then
  INSTALLED_HASH="$(cat "$STAMP_FILE")"
fi

if [ ! -d node_modules ] || [ "$CURRENT_HASH" != "$INSTALLED_HASH" ]; then
  if [ -f package-lock.json ]; then
    npm ci --no-audit --no-fund
  else
    npm install --no-audit --no-fund
  fi
  printf '%s' "$CURRENT_HASH" > "$STAMP_FILE"
fi

npm run build

mkdir -p "$DOCROOT"

find dist -mindepth 1 -maxdepth 1 ! -name index.html -exec cp -R {} "$DOCROOT/" \;
cp dist/index.html "$DOCROOT/index.html"
