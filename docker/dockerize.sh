#!/usr/bin/env bash
#
# Script to build osctrl in docker
#
# Usage: dockerize.sh [-h|--help] [PARAMETER] [PARAMETER] ...
#
# Parameters:
#  -h	  Shows this help message and exit.
#  -b	  Builds new docker containers.
#  -u	  Runs existing containers.
#  -c	  Generates configuration files.
#  -f	  Forces the generation of new certificates and configuration.
#  -m   Uses mkcert (https://github.com/FiloSottile/mkcert) to generate certificate.
#  -d	  Takes down running containers.
#  -x	  Removes container images.

# Show an informational log message
#   string  message_to_display
function log() {
  echo "[+] $1"
}

# Show an error log message
#   string  message_to_display
function _log() {
  echo "[!] $1"
}

# Noooooo Error!
OHNOES=41414141

# How does it work?
function usage() {
  printf "\nUsage: %s -h [PARAMETER] [PARAMETER] ...\n" "${0}"
  printf "\nParameters:\n"
  printf "  -h\tShows this help message and exit.\n"
  printf "  -b\tBuilds new docker containers.\n"
  printf "  -u\tRun osctrl containers.\n"
  printf "  -c\tGenerates configuration files.\n"
  printf "  -f\tForces the generation of new certificates and configuration.\n"
  printf "  -m\tUses mkcert (https://github.com/FiloSottile/mkcert) to generate certificate.\n"
  printf "  -d\tTakes down running containers.\n"
  printf "  -x\tRemoves container images.\n"
  printf "\nExamples:\n"
  printf "  Run dockerized osctrl building new containers and forcing to generate new configuration/certs:\n"
  printf "\t%s -u -b -f\n" "${0}"
  printf "  Generate only configuration files:\n"
  printf "\t%s -c\n" "${0}"
  printf "\n"
}

# We want the provision script to fail as soon as there are any errors
set -e

# Detection of current directory
ROOTDIR="."
DOCKERDIR="docker"
if [[ -f "docker-compose.yml" ]]; then
  ROOTDIR=".."
  DOCKERDIR="."
fi

# Values not intended to change
NAME="osctrl"
DEPLOYDIR="$ROOTDIR/deploy"
CERTSDIR="$DOCKERDIR/certs"
CONFIGDIR="$DOCKERDIR/config"
COMPOSERFILE="$DOCKERDIR/docker-compose.yml"

# Default values for arguments
SHOW_USAGE=true
_BUILD=false
_UP=false
_FORCE=false
_MKCERT=false
_DOWN=false
_REMOVE=false

# Extract arguments
while getopts 'hbufmdx' c; do
  case $c in
    h)
      usage
      exit 0
      ;;
    b)
      SHOW_USAGE=false
      _BUILD=true
      ;;
    u)
      SHOW_USAGE=false
      _UP=true
      ;;
    f)
      SHOW_USAGE=false
      _FORCE=true
      ;;
    m)
      SHOW_USAGE=false
      _MKCERT=true
      ;;
    d)
      SHOW_USAGE=false
      _DOWN=true
      ;;
    x)
      SHOW_USAGE=false
      _REMOVE=true
      ;;
  esac
done

# No parameters, show usage
if [[ "$SHOW_USAGE" == true ]]; then
  _log "Parameters are needed!"
  usage
  exit $OHNOES
fi

# Take down containers
if [[ "$_DOWN" == true ]]; then
  log "Stopping containers"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" down
  exit 0
fi

# Remove images
if [[ "$_REMOVE" == true ]]; then
  log "Removing container images"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" rm
  exit 0
fi

# Include functions
source "$DEPLOYDIR/lib.sh"

log "Preparing certificates for $NAME-nginx"

# This is for development purposes, in production environments use 2048 or 4096 bits
_BITS="1024"

CSR_FILE="$CERTSDIR/$NAME.csr"
KEY_FILE="$CERTSDIR/$NAME.key"
CRT_FILE="$CERTSDIR/$NAME.crt"
DH_FILE="$CERTSDIR/dhparam.pem"

if [[ "$_MKCERT" == false ]]; then
  if [[ -f "$KEY_FILE" && "$_FORCE" == false ]]; then
    log "Using existing $KEY_FILE"
  else
    log "Generating $KEY_FILE"
    openssl req -nodes -newkey rsa:$_BITS -keyout "$KEY_FILE" -out "$CSR_FILE" -subj "/O=$NAME"
  fi

  if [[ -f "$CRT_FILE" && "$_FORCE" == false ]]; then
    log "Using existing $CRT_FILE"
  else
    log "Generating $CRT_FILE"
    openssl x509 -req -days 365 -in "$CSR_FILE" -signkey "$KEY_FILE" -out "$CRT_FILE"
  fi
else
  log "Generating $KEY_FILE and $CRT_FILE with mkcert"
  mkcert -key-file "$KEY_FILE" -cert-file "$CRT_FILE" "localhost"
fi

if [[ -f "$DH_FILE" && "$_FORCE" == false ]]; then
    log "Using existing $DH_FILE"
  else
    log "Generating $DH_FILE, it may take a bit"
    openssl dhparam -out "$DH_FILE" $_BITS &>/dev/null
  fi

CRT_DST="/etc/certs/$NAME.crt"
KEY_DST="/etc/certs/$NAME.key"
DH_DST="/etc/certs/dhparam.pem"

log "Preparing configuration"

TLS_CONF="$CONFIGDIR/tls.conf"
if [[ -f "$TLS_CONF" && "$_FORCE" == false ]]; then
  log "Using existing $TLS_CONF"
else
  nginx_generate "$DEPLOYDIR/nginx/ssl.conf" "$CRT_DST" "$KEY_DST" "$DH_DST" "443" "9000" "osctrl-tls" "$TLS_CONF"
fi

ADMIN_CONF="$CONFIGDIR/admin.conf"
if [[ -f "$ADMIN_CONF" && "$_FORCE" == false ]]; then
  log "Using existing $ADMIN_CONF"
else
  nginx_generate "$DEPLOYDIR/nginx/ssl.conf" "$CRT_DST" "$KEY_DST" "$DH_DST" "8443" "9001" "osctrl-admin" "$ADMIN_CONF"
fi

TLS_JSON="$CONFIGDIR/tls.json"
if [[ -f "$TLS_JSON" && "$_FORCE" == false ]]; then
  log "Using existing $TLS_JSON"
else
  configuration_service "$DEPLOYDIR/service.json" "$TLS_JSON" "localhost|9000" "tls" "0.0.0.0"
fi

ADMIN_JSON="$CONFIGDIR/admin.json"
if [[ -f "$ADMIN_JSON" && "$_FORCE" == false ]]; then
  log "Using existing $ADMIN_JSON"
else
  configuration_service "$DEPLOYDIR/service.json" "$ADMIN_JSON" "localhost|9001" "admin" "0.0.0.0"
fi

DB_JSON="$CONFIGDIR/db.json"
if [[ -f "$DB_JSON" && "$_FORCE" == false ]]; then
  log "Using existing $DB_JSON"
else
  configuration_db "$DEPLOYDIR/db.json" "$DB_JSON" "osctrl-db" "5432" "osctrl" "osctrl" "osctrl"
fi

if [[ "$_BUILD" == true ]]; then
  log "Building containers"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" build
fi

log "Access $NAME-admin using https://localhost:8443"

if [[ "$_UP" == true ]]; then
  log "Running containers"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" up
fi

exit 0

# kthxbai
