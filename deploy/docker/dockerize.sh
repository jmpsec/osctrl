#!/usr/bin/env bash
#
# Helper script to prepare osctrl configuration to run in docker
#
# Usage: dockerize.sh [-h|--help] [PARAMETER] [PARAMETER] ...
#
# Parameters:
#  -h	  Shows this help message and exit.
#  -b	  Builds new docker containers.
#  -u	  Runs existing osctrl containers.
#  -f	  Forces the generation of new certificates.
#  -J   Generates new JWT secret.
#  -m   Uses mkcert (https://github.com/FiloSottile/mkcert) to generate a certificate and trust it locally.
#  -d	  Takes down running osctrl containers.
#  -x	  Removes container images.
#  -C   Existing certificate to be used with osctrl.
#  -K   Existing private key to be used with osctrl.

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
  printf "  -u\tRun existing osctrl containers.\n"
  printf "  -f\tForces the generation of new certificates.\n"
  printf "  -J\tGenerates new JWT secret.\n"
  printf "  -m\tUses mkcert (https://github.com/FiloSottile/mkcert) to generate a certificate and trust it locally.\n"
  printf "  -d\tTakes down running osctrl containers.\n"
  printf "  -x\tRemoves container images.\n"
  printf "  -C\tExisting certificate to be used with osctrl.\n"
  printf "  -K\tExisting private key to be used with osctrl.\n"
  printf "\nExamples:\n"
  printf "  Run dockerized osctrl building new containers and forcing to generate new certificates:\n"
  printf "\t%s -u -b -f\n" "${0}"
  printf "  Run existing containers with existing certificates:\n"
  printf "\t%s -u -C cert.crt -K private.key\n" "${0}"
  printf "\n"
}

# We want the provision script to fail as soon as there are any errors
set -e

# Detection of current directory
if [[ -f "deploy/docker/docker-compose.yml" ]]; then
  ROOTDIR="."
  log "ROOTDIR=$ROOTDIR"
  DOCKERDIR="deploy/docker"
  log "DOCKERDIR=$DOCKERDIR"
fi
if [[ -f "docker-compose.yml" ]]; then
  ROOTDIR=".."
  log "ROOTDIR=$ROOTDIR"
  DOCKERDIR="."
  log "DOCKERDIR=$DOCKERDIR"
fi

# Values not intended to change
NAME="osctrl"
_HOSTNAME="localhost"
DEPLOYDIR="$ROOTDIR/deploy"
CERTSDIR="$DOCKERDIR/conf/tls"
COMPOSERFILE="$DOCKERDIR/docker-compose.yml"
ENVFILE="$ROOTDIR/.env"
ENVTEMPLATE="$DOCKERDIR/env.example"

# Directories to generate certificates
mkdir -p "$CERTSDIR"

# Default value for certificate and key
KEY_FILE="$CERTSDIR/$NAME.key"
CRT_FILE="$CERTSDIR/$NAME.crt"
CNF_FILE="$CERTSDIR/openssl.cnf"

# Default values for arguments
SHOW_USAGE=true
_BUILD=false
_UP=false
_FORCE=false
_JWT=false
_MKCERT=false
_DOWN=false
_REMOVE=false

# Extract arguments
while getopts 'hbufJmdxCK' c; do
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
    J)
      SHOW_USAGE=false
      _JWT=true
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
    C)
      SHOW_USAGE=false
      CRT_FILE=$2
      ;;
    K)
      SHOW_USAGE=false
      KEY_FILE=$2
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

if [[ "$_FORCE" == true ]]; then
  log "Preparing certificates for osctrl"
  if [[ "$_MKCERT" == true ]]; then
    log "Generating $KEY_FILE and $CRT_FILE with mkcert"
    mkcert -key-file "$KEY_FILE" -cert-file "$CRT_FILE" "$_HOSTNAME"
  else
    log "Generating $KEY_FILE and $CRT_FILE with OpenSSL"
    if [[ ! -f "$CNF_FILE" ]]; then
      _log "OpenSSL configuration $CNF_FILE does not exist"
      exit $OHNOES
    fi
    openssl req -x509 -new -nodes -keyout "$KEY_FILE" -out "$CRT_FILE" -config "$CNF_FILE"
  fi
else
  if [[ ! -f "$KEY_FILE" ]]; then
    _log "Private key file $KEY_FILE does not exist"
    exit $OHNOES
  fi
  if [[ ! -f "$CRT_FILE" ]]; then
    _log "Certificate file $KEY_FILE does not exist"
    exit $OHNOES
  fi
  log "Using existing $KEY_FILE and $CRT_FILE"
fi

if [[ "$_JWT" == true ]]; then
  _JWT_SECRET="$(head -c64 < /dev/random | base64 | head -n 1 | openssl dgst -sha256 | cut -d " " -f2)"
  log "Generated a $(echo $_JWT_SECRET | wc -c | awk '{print $1}') bytes JWT secret"
  cat "$ENVTEMPLATE" | sed "s/JWT_SECRET.*/JWT_SECRET=$_JWT_SECRET/" | tee "$ENVFILE"
fi

if [[ "$_BUILD" == true ]]; then
  log "Building containers from $COMPOSERFILE and using $ENVFILE"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" build
fi

log "Access $NAME-admin using https://$_HOSTNAME:8443"

if [[ "$_UP" == true ]]; then
  log "Running containers"
  docker-compose -f "$COMPOSERFILE" --project-directory "$ROOTDIR" up
fi

exit 0

# kthxbai
