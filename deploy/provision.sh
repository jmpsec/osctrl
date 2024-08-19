#!/usr/bin/env bash
#
# Provisioning script for osctrl
#
# Usage: provision.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...
#
# Parameters:
#   -h, --help            Shows this help message and exit.
#   -m MODE, --mode MODE  Mode of operation. Default value is dev
#   -t TYPE, --type TYPE  Type of certificate to use. Default value is self
#   -p PART, --part PART  Part of the service. Default is all
#
# Arguments for MODE:
#   dev     Provision will run in development mode. Certificate will be self-signed.
#   prod    Provision will run in production mode.
#
# Arguments for TYPE:
#   self    Provision will use a self-signed TLS certificate that will be generated.
#   own     Provision will use the TLS certificate provided by the user.
#   certbot Provision will generate a TLS certificate using letsencrypt/certbot. More info here: https://certbot.eff.org/
#
# Argument for PART:
#   admin   Provision will deploy only the admin interface.
#   tls     Provision will deploy only the TLS endpoint.
#   api     Provision will deploy only the API endpoint.
#   all     Provision will deploy both the admin and the TLS endpoint.
#
# Optional Parameters:
#   --public-tls-port PORT      Port for the TLS endpoint service. Default is 443
#   --public-admin-port PORT    Port for the admin service. Default is 8443
#   --public-api-port PORT      Port for the API service. Default is 8444
#   --private-tls-port PORT     Port for the TLS endpoint service. Default is 9000
#   --private-admin-port PORT   Port for the admin service. Default is 9001
#   --private-api-port PORT     Port for the API service. Default is 9002
#   --all-hostname HOSTNAME     Hostname for all the services. Default is 127.0.0.1
#   --tls-hostname HOSTNAME     Hostname for the TLS endpoint service. Default is 127.0.0.1
#   --admin-hostname HOSTNAME   Hostname for the admin service. Default is 127.0.0.1
#   --api-hostname HOSTNAME     Hostname for the API service. Default is 127.0.0.1
#   -X PASS     --password      Force the admin password for the admin interface. Default is random
#   -k PATH     --keyfile PATH  Path to supplied TLS key file
#   -c PATH     --certfile PATH Path to supplied TLS server PEM certificate(s) bundle
#   -d DOMAIN   --domain DOMAIN Domain for the TLS certificate to be generated using letsencrypt
#   -e EMAIL    --email EMAIL   Domain for the TLS certificate to be generated using letsencrypt
#   -s PATH     --source PATH   Path to code. Default is ~/osctrl
#   -S PATH     --dest PATH     Path to binaries. Default is /opt/osctrl
#   -n          --nginx         Install and configure nginx as TLS termination
#   -P          --postgres      Install and configure PostgreSQL as backend
#   -R          --redis         Install and configure Redis as cache
#   -E          --enroll        Enroll the serve into itself using osquery. Default is disabled
#   -N NAME     --env NAME      Initial environment name to be created. Default is the mode (dev or prod)
#   -U          --upgrade       Keep osctrl upgraded with the latest code from Github
#
# Examples:
#   Provision service in development mode, code is in /code/osctrl and all components (admin, tls, api):
#     provision.sh -m dev -s /code/osctrl -p all
#   Provision service in production mode using my own certificate and only with TLS endpoint:
#     provision.sh -m prod -t own -k /etc/certs/my.key -c /etc/certs/cert.crt -p tls
#   Upgrade service with the latest code from Github. Does not create services nor certificates:
#     provision.sh -U -s /code/osctrl -S /srv/osctrl
#

# Before we begin...
_START_TIME=$(date +%s)

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
  printf "\nUsage: %s [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...\n" "${0}"
  printf "\nParameters:\n"
  printf "  -h, --help \t\tShows this help message and exit.\n"
  printf "  -m MODE, --mode MODE \tMode of operation. Default value is dev\n"
  printf "  -t TYPE, --type TYPE \tType of certificate to use. Default value is self\n"
  printf "  -p PART, --part PART \tPart of the service. Default is all\n"
  printf "\nArguments for MODE:\n"
  printf "  dev \t\tProvision will run in development mode. Certificate will be self-signed.\n"
  printf "  prod \t\tProvision will run in production mode.\n"
  printf "\nArguments for TYPE:\n"
  printf "  self \t\tProvision will use a self-signed TLS certificate that will be generated.\n"
  printf "  own \t\tProvision will use the TLS certificate provided by the user.\n"
  printf "  certbot \tProvision will generate a TLS certificate using letsencrypt/certbot. More info here: https://certbot.eff.org/\n"
  printf "\nArguments for PART:\n"
  printf "  admin \tProvision will deploy only the admin interface.\n"
  printf "  tls \t\tProvision will deploy only the TLS endpoint.\n"
  printf "  api \t\tProvision will deploy only the API endpoint.\n"
  printf "  all \t\tProvision will deploy both the admin and the TLS endpoint.\n"
  printf "\nOptional Parameters:\n"
  printf "  --public-tls-port PORT \tPort for the TLS endpoint service. Default is 443\n"
  printf "  --public-admin-port PORT \tPort for the admin service. Default is 8443\n"
  printf "  --public-api-port PORT \tPort for the API service. Default is 8444\n"
  printf "  --private-tls-port PORT \tPort for the TLS endpoint service. Default is 9000\n"
  printf "  --private-admin-port PORT \tPort for the admin service. Default is 9001\n"
  printf "  --private-api-port PORT \tPort for the API service. Default is 9002\n"
  printf "  --all-hostname HOSTNAME \tHostname for all the services. Default is 127.0.0.1\n"
  printf "  --tls-hostname HOSTNAME \tHostname for the TLS endpoint service. Default is 127.0.0.1\n"
  printf "  --admin-hostname HOSTNAME \tHostname for the admin service. Default is 127.0.0.1\n"
  printf "  --api-hostname HOSTNAME \tHostname for the API service. Default is 127.0.0.1\n"
  printf "  -X PASS     --password \tForce the admin password for the admin interface. Default is random\n"
  printf "  -c PATH     --certfile PATH \tPath to supplied TLS server PEM certificate(s) bundle\n"
  printf "  -d DOMAIN   --domain DOMAIN \tDomain for the TLS certificate to be generated using letsencrypt\n"
  printf "  -e EMAIL    --email EMAIL \tDomain for the TLS certificate to be generated using letsencrypt\n"
  printf "  -s PATH     --source PATH \tPath to code. Default is ~/osctrl\n"
  printf "  -S PATH     --dest PATH \tPath to binaries. Default is /opt/osctrl\n"
  printf "  -n          --nginx \t\tInstall and configure nginx as TLS termination\n"
  printf "  -P          --postgres \tInstall and configure PostgreSQL as backend\n"
  printf "  -R          --redis \t\tInstall and configure Redis as cache\n"
  printf "  -E          --enroll  \tEnroll the serve into itself using osquery. Default is disabled\n"
  printf "  -N NAME     --env NAME \tInitial environment name to be created. Default is the mode (dev or prod)\n"
  printf "  -U          --upgrade \tKeep osctrl upgraded with the latest code from Github\n"
  printf "\nExamples:\n"
  printf "  Provision service in development mode, code is in /code/osctrl and all components (admin, tls, api):\n"
  printf "\t%s -m dev -s /code/osctrl -p all\n" "${0}"
  printf "  Provision service in production mode using my own certificate and only with TLS endpoint:\n"
  printf "\t%s -m prod -t own -k /etc/certs/my.key -c /etc/certs/cert.crt -p tls\n" "${0}"
  printf "  Upgrade service with the latest code from Github. Does not create services nor certificates:\n"
  printf "\t%s -U -s /code/osctrl -S /srv/osctrl\n" "${0}"
  printf "\n"
}

# We want the provision script to fail as soon as there are any errors
set -e

# Values not intended to change
_NAME="osctrl"
TLS_COMPONENT="tls"
ADMIN_COMPONENT="admin"
API_COMPONENT="api"
TLS_CONF="$TLS_COMPONENT.json"
ADMIN_CONF="$ADMIN_COMPONENT.json"
API_CONF="$API_COMPONENT.json"
DB_CONF="db.json"
CACHE_CONF="redis.json"
JWT_CONF="jwt.json"
LOGGER_CONF="logger.json"
SERVICE_TEMPLATE="service.json"
DB_TEMPLATE="db.json"
CACHE_TEMPLATE="redis.json"
JWT_TEMPLATE="jwt.json"
SYSTEMD_TEMPLATE="systemd.service"
DEV_HOST="osctrl.dev"

# Default values for arguments
SHOW_USAGE=false
MODE="dev"
ENVIRONMENT="dev"
TYPE="self"
PART="all"
KEYFILE=""
CERTFILE=""
DOMAIN=""
EMAIL=""
ENROLL=false
UPDATE=false
NGINX=false
POSTGRES=false
REDIS=false
UPGRADE=false
BRANCH="main"
SOURCE_PATH=~/osctrl
DEST_PATH=/opt/osctrl
ALL_HOST="127.0.0.1"
OSQUERY_VERSION="5.12.1"

# Backend values
_DB_HOST="localhost"
_DB_NAME="osctrl"
_DB_SYSTEM_USER="postgres"
_DB_USER="osctrl"
_DB_PASS="osctrl"
_DB_PORT="5432"

# Cache values
_CACHE_HOST="localhost"
_CACHE_PORT="6379"
_CACHE_PASS="osctrl"

# TLS Service
_T_INT_PORT="9000"
_T_PUB_PORT="443"
_T_HOST="$ALL_HOST"
_T_AUTH="none"
_T_LOGGING="stdout"
_T_CARVER="db"

# Admin Service
_A_INT_PORT="9001"
_A_PUB_PORT="8443"
_A_HOST="$ALL_HOST"
_A_AUTH="db"
_A_LOGGING="db"
_A_CARVER="db"

# API Service
_P_INT_PORT="9002"
_P_PUB_PORT="8444"
_P_HOST="$ALL_HOST"
_P_AUTH="jwt"
_P_LOGGING="none"
_P_CARVER="none"

# Default admin credentials with random password
_ADMIN_USER="admin"
_ADMIN_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1 | md5sum | cut -d " " -f1)

# Secret for API JWT
_JWT_SECRET="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1 | sha256sum | cut -d " " -f1)"

# Arrays with valid arguments
VALID_MODE=("dev" "prod")
VALID_TYPE=("self" "own" "certbot")
VALID_PART=("$TLS_COMPONENT" "$ADMIN_COMPONENT" "$API_COMPONENT" "all")

# Extract arguments
ARGS=$(getopt -n "$0" -o hm:t:p:PRk:nEUc:d:e:s:S:X: -l "help,mode:,type:,part:,public-tls-port:,private-tls-port:,public-admin-port:,private-admin-port:,public-api-port:,private-api-port:,all-hostname:,tls-hostname:,admin-hostname:,api-hostname:,keyfile:,nginx,postgres,redis,enroll,upgrade,certfile:,domain:,email:,source:,dest:,password:" -- "$@")

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

eval set -- "$ARGS"

while true; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -m|--mode)
      GIVEN_ARG=$2
      if [[ "${VALID_MODE[@]}" =~ "${GIVEN_ARG}" ]]; then
        SHOW_USAGE=false
        MODE=$2
        ENVIRONMENT=$MODE
        shift 2
      else
        _log "Invalid mode"
        usage
        exit $OHNOES
      fi
      ;;
    -t|--type)
      GIVEN_ARG=$2
      if [[ "${VALID_TYPE[@]}" =~ "${GIVEN_ARG}" ]]; then
        SHOW_USAGE=false
        TYPE=$2
        shift 2
      else
        _log "Invalid certificate type"
        usage
        exit $OHNOES
      fi
      ;;
    -p|--part)
      GIVEN_ARG=$2
      if [[ "${VALID_PART[@]}" =~ "${GIVEN_ARG}" ]]; then
        SHOW_USAGE=false
        PART=$2
        shift 2
      else
        _log "Invalid part"
        usage
        exit $OHNOES
      fi
      ;;
    --public-tls-port)
      SHOW_USAGE=false
      _T_PUB_PORT=$2
      shift 2
      ;;
    --private-tls-port)
      SHOW_USAGE=false
      _T_INT_PORT=$2
      shift 2
      ;;
    --public-admin-port)
      SHOW_USAGE=false
      _A_PUB_PORT=$2
      shift 2
      ;;
    --private-admin-port)
      SHOW_USAGE=false
      _A_INT_PORT=$2
      shift 2
      ;;
    --public-api-port)
      SHOW_USAGE=false
      _P_PUB_PORT=$2
      shift 2
      ;;
    --private-api-port)
      SHOW_USAGE=false
      _P_INT_PORT=$2
      shift 2
      ;;
    --tls-hostname)
      SHOW_USAGE=false
      _T_HOST=$2
      shift 2
      ;;
    --admin-hostname)
      SHOW_USAGE=false
      _A_HOST=$2
      shift 2
      ;;
    --api-hostname)
      SHOW_USAGE=false
      _P_HOST=$2
      shift 2
      ;;
    --all-hostname)
      SHOW_USAGE=false
      ALL_HOST=$2
      _T_HOST=$ALL_HOST
      _A_HOST=$ALL_HOST
      _P_HOST=$ALL_HOST
      shift 2
      ;;
    -n|--nginx)
      SHOW_USAGE=false
      NGINX=true
      shift
      ;;
    -P|--postgres)
      SHOW_USAGE=false
      POSTGRES=true
      shift
      ;;
    -R|--redis)
      SHOW_USAGE=false
      REDIS=true
      shift
      ;;
    -E|--enroll)
      SHOW_USAGE=false
      ENROLL=true
      shift
      ;;
    -U|--upgrade)
      SHOW_USAGE=false
      UPGRADE=true
      shift
      ;;
    -k|--keyfile)
      SHOW_USAGE=false
      KEYFILE=$2
      shift 2
      ;;
    -c|--certfile)
      SHOW_USAGE=false
      CERTFILE=$2
      shift 2
      ;;
    -d|--domain)
      SHOW_USAGE=false
      DOMAIN=$2
      shift 2
      ;;
    -e|--email)
      SHOW_USAGE=false
      EMAIL=$2
      shift 2
      ;;
    -s|--source)
      SHOW_USAGE=false
      SOURCE_PATH=$2
      shift 2
      ;;
    -S|--dest)
      SHOW_USAGE=false
      DEST_PATH=$2
      shift 2
      ;;
    -X|--password)
      SHOW_USAGE=false
      _ADMIN_PASS=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
  esac
done

# No parameters, show usage
if [[ "$SHOW_USAGE" == true ]]; then
  _log "Parameters are needed!"
  usage
  exit $OHNOES
fi

# Include functions
source "$SOURCE_PATH/deploy/lib.sh"

# Detect Linux distro
if [[ -f "/etc/debian_version" ]]; then
  if [[ $(grep "Debian" /etc/issue) ]]; then
    DISTRO="debian"
  else
    DISTRO="ubuntu"
  fi
elif [[ -f "/etc/centos-release" ]]; then
  DISTRO="centos"
fi

# Git is needed
package git

# Update distro
package_repo_update

# Required packages
if [[ "$DISTRO" == "ubuntu" ]]; then
  package build-essential
fi
package sudo
package wget
package curl
package gcc
package make
package openssl
package tmux
package bc
package rsync

# Golang
# package golang-go
if ! [ -x "$(command -v go)" ]; then
  install_go_23
fi

# Upgrade service
if [[ "$UPGRADE" == true ]]; then
  log ""
  log "Upgrading [ $_NAME ][ $MODE ][ $BRANCH ][ $PART ] for $DISTRO"
  log ""

  cd "$SOURCE_PATH"

  # Check for changes to abort if necessary
  if [[ `git status --porcelain` ]]; then
    _log "Detected untracked changes, can not proceed with upgrade"
    exit $OHNOES
  else
    git pull origin "$BRANCH"
  fi

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$TLS_COMPONENT" ]]; then
    # Build TLS service
    make tls

    # Restart service with new binary
    make install_tls
  fi

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$ADMIN_COMPONENT" ]]; then
    # Build Admin service
    make admin

    # Prepare static files for Admin service
    _static_files "$MODE" "$SOURCE_PATH" "$DEST_PATH" "admin/templates" "tmpl_admin"
    _static_files "$MODE" "$SOURCE_PATH" "$DEST_PATH" "admin/static" "static"

    # Copy osquery tables JSON file
    sudo cp "$SOURCE_PATH/deploy/osquery/data/$OSQUERY_VERSION.json" "$DEST_PATH/data"

    # Restart service with new binary
    make install_admin
  fi

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$API_COMPONENT" ]]; then
    # Build API service
    make api

    # Restart service with new binary
    make install_api
  fi

  # Compile CLI
  make cli

  # Install CLI
  DEST="$DEST_PATH" make install_cli
else
  # We are provisioning a new machine
  log ""
  log "Provisioning [ $_NAME ][ $PART ] for $DISTRO"
  log ""
  log "  -> [ $MODE ] mode and with [ $TYPE ] certificate"
  log ""

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$TLS_COMPONENT" ]]; then
    log "  -> Deploying TLS service for ports $_T_PUB_PORT:$_T_INT_PORT"
    log "  -> Hostname for TLS endpoint: $_T_HOST"
  fi
  log ""

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$ADMIN_COMPONENT" ]]; then
    log "  -> Deploying Admin service for ports $_A_PUB_PORT:$_A_INT_PORT"
    log "  -> Hostname for admin: $_A_HOST"
  fi
  log ""

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$API_COMPONENT" ]]; then
    log "  -> Deploying API service for ports $_P_PUB_PORT:$_P_INT_PORT"
    log "  -> Hostname for API: $_P_HOST"
  fi
  log ""

  log "Installing and configuring services for $NAME"

  # nginx as TLS termination
  if [[ "$NGINX" == true ]]; then
    # Some static values for now that can be turned into arguments eventually
    NGINX_PATH="/etc/nginx"
    if [[ "$DISTRO" == "centos" ]]; then
      package epel-release
    fi
    package nginx

    _certificates_dir="$NGINX_PATH/certs"
    sudo mkdir -p "$_certificates_dir"

    _cert_file="$_certificates_dir/$_NAME.crt"
    _key_file="$_certificates_dir/$_NAME.key"
    _cert_file_a="$_certificates_dir/$_NAME-admin.crt"
    _key_file_a="$_certificates_dir/$_NAME-admin.key"
    _dh_file="$_certificates_dir/dhparam.pem"
    _dh_bits="2048"

    # Mode dev checks for existance of certificates
    if [[ "$MODE" == "dev" ]]; then
      # Do we have certificates already for admin/API?
      # This is done just in case we have certificates from a local CA
      if [[ -f "$SOURCE_PATH/certs/$_NAME-admin.crt" ]] && [[ -f "$SOURCE_PATH/certs/$_NAME-admin.key" ]]; then
        log "Using existing certificate"
        sudo cp "$SOURCE_PATH/certs/$_NAME-admin.crt" "$_cert_file_a"
        log "Using existing key"
        sudo cp "$SOURCE_PATH/certs/$_NAME-admin.key" "$_key_file_a"
      fi
    fi

    # Self-generated certificates generation
    if [[ "$TYPE" == "self" ]]; then
      log "Deploying self-signed certificates for admin/API"
      self_signed_cert "$_certificates_dir" "$_NAME-admin" "$_dh_bits" "$DEV_HOST" "$_A_HOST"

      log "Deploying self-signed certificates for TLS"
      self_signed_cert "$_certificates_dir" "$_NAME" "$_dh_bits" "$DEV_HOST" "$_A_HOST"
    fi

    # Own certificates should copy them
    if [[ "$TYPE" == "own" ]]; then
      # Check if certificates exist
      if sudo test -f "$CERTFILE" && sudo test -f "$KEYFILE" ; then
        log "Using existing certificate"
        sudo cp "$CERTFILE" "$_cert_file"
        sudo cp "$CERTFILE" "$_cert_file_a"
        log "Using existing key"
        sudo cp "$KEYFILE" "$_key_file"
        sudo cp "$KEYFILE" "$_key_file_a"
      else
        _log "Certificate or key are missing"
        exit $OHNOES
      fi
    fi

    # Certbot certificates
    if [[ "$TYPE" == "certbot" ]]; then
      #certbot_certificates_nginx "$_certificates_dir" "$_certificate_name" "$EMAIL" "$DOMAIN"
      # FIXME: REMEMBER GENERATE THE CERTIFICATES MANUALLY!
      _log "************** GENERATE THE CERTIFICATES MANUALLY AND USE THEM WITH -t own **************"
      exit $OHNOES
      #sudo cp "/etc/letsencrypt/archive/osctrl/fullchain1.pem" "$_cert_file"
      #sudo cp "/etc/letsencrypt/archive/osctrl/privkey1.pem" "$_key_file"
    fi

    # Diffie-Hellman parameter for DHE ciphersuites
    log "Generating dhparam.pem with $_dh_bits bits... It may take a while"
    sudo openssl dhparam -out "$_dh_file" $_dh_bits &>/dev/null

    # Configuration for nginx
    if [[ "$DISTRO" == "ubuntu" ]]; then
      nginx_main "$SOURCE_PATH/deploy/nginx/nginx.conf" "nginx.conf" "www-data" "/etc/nginx/modules-enabled/*.conf" "$NGINX_PATH"
    elif [[ "$DISTRO" == "centos" ]]; then
      nginx_main "$SOURCE_PATH/deploy/nginx/nginx.conf" "nginx.conf" "nginx" "/usr/share/nginx/modules/*.conf" "$NGINX_PATH"
      # SELinux
      log "Enabling httpd in SELinux"
      sudo setsebool -P httpd_can_network_connect 1
    fi

    # Configuration for TLS service
    nginx_service "$SOURCE_PATH/deploy/nginx/ssl.conf" "$_cert_file" "$_key_file" "$_dh_file" "$_T_PUB_PORT" "$_T_INT_PORT" "tls.conf" "$NGINX_PATH"

    # Configuration for Admin service
    nginx_service "$SOURCE_PATH/deploy/nginx/ssl.conf" "$_cert_file_a" "$_key_file_a" "$_dh_file" "$_A_PUB_PORT" "$_A_INT_PORT" "admin.conf" "$NGINX_PATH"

    # Configuration for API service
    nginx_service "$SOURCE_PATH/deploy/nginx/ssl.conf" "$_cert_file_a" "$_key_file_a" "$_dh_file" "$_P_PUB_PORT" "$_P_INT_PORT" "api.conf" "$NGINX_PATH"

    # Restart nginx
    sudo nginx -t
    sudo service nginx restart
  fi

  # PostgreSQL - Backend
  if [[ "$POSTGRES" == true ]]; then
    if [[ "$DISTRO" == "ubuntu" ]]; then
      # Ubuntu 22.04 uses postgresql 14
      if [[ "$(lsb_release -r | cut -f2 | cut -d'.' -f1)" == "22" ]]; then
        package postgresql-14
        package postgresql-contrib
        package postgresql-client-14
        POSTGRES_SERVICE="postgresql"
        POSTGRES_PSQL="/usr/lib/postgresql/14/bin/psql"
      else
        # Assuming we are in Ubuntu 20.04, which uses postgresql 12
        package postgresql
        package postgresql-contrib
        package postgresql-client-12
        POSTGRES_SERVICE="postgresql"
        POSTGRES_PSQL="/usr/lib/postgresql/12/bin/psql"
      fi
    # Debian uses postgresql 15
    elif [[ "$DISTRO" == "debian" ]]; then
      package postgresql
      package postgresql-contrib
      package postgresql-client-15
      POSTGRES_SERVICE="postgresql"
      POSTGRES_PSQL="/usr/lib/postgresql/15/bin/psql"
    elif [[ "$DISTRO" == "centos" ]]; then
      log "For CentOS, please install Postgres 14 manually"
      exit $OHNOES
    fi
    sudo systemctl enable "$POSTGRES_SERVICE"
    sudo systemctl start "$POSTGRES_SERVICE"
    db_user_postgresql "$_DB_NAME" "$_DB_SYSTEM_USER" "$_DB_USER" "$_DB_PASS" "$POSTGRES_PSQL"
  fi

  # Redis - Cache
  if [[ "$REDIS" == true ]]; then
    REDIS_CONF="$SOURCE_PATH/deploy/redis/redis.conf"
    REDIS_SERVICE="redis-server.service"
    REDIS_ETC="/etc/redis/redis.conf"
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
      package redis-server
    elif [[ "$DISTRO" == "centos" ]]; then
      log "For CentOS, please install Redis manually"
      exit $OHNOES
    fi
    configure_redis "$REDIS_CONF" "$REDIS_SERVICE" "$REDIS_ETC" "$_CACHE_PASS"
  fi

  # Prepare destination and configuration folder
  sudo mkdir -p "$DEST_PATH/config"

  # Generate DB configuration file for services
  configuration_db "$SOURCE_PATH/deploy/config/$DB_TEMPLATE" "$DEST_PATH/config/$DB_CONF" "$_DB_HOST" "$_DB_PORT" "$_DB_NAME" "$_DB_USER" "$_DB_PASS" "sudo"

  # Generate Cache configuration file for services
  configuration_cache "$SOURCE_PATH/deploy/config/$CACHE_TEMPLATE" "$DEST_PATH/config/$CACHE_CONF" "$_CACHE_HOST" "$_CACHE_PORT" "$_CACHE_PASS" "sudo"

  # Prepare DB logger configuration for services
  sudo cp "$DEST_PATH/config/$DB_CONF" "$DEST_PATH/config/$LOGGER_CONF"

  # JWT configuration
  cat "$SOURCE_PATH/deploy/config/$JWT_TEMPLATE" | sed "s|_JWT_SECRET|$_JWT_SECRET|g" | sudo tee "$DEST_PATH/config/$JWT_CONF"

  # Build code
  cd "$SOURCE_PATH"
  make clean

  # Compile CLI
  make cli

  # Install CLI
  DEST="$DEST_PATH" make install_cli

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$TLS_COMPONENT" ]]; then
    # Build TLS service
    make tls

    # Configuration file generation for TLS service
    configuration_service "$SOURCE_PATH/deploy/config/$SERVICE_TEMPLATE" "$DEST_PATH/config/$TLS_CONF" "$_T_HOST|$_T_INT_PORT" "$TLS_COMPONENT" "127.0.0.1" "$_T_AUTH" "$_T_LOGGING" "$_T_CARVER" "sudo"

    # Systemd configuration for TLS service
    _systemd "osctrl" "osctrl" "osctrl-tls" "$SOURCE_PATH" "$DEST_PATH" "--redis --db --config"
  fi

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$ADMIN_COMPONENT" ]]; then
    # Build Admin service
    make admin

    # Configuration file generation for Admin service
    configuration_service "$SOURCE_PATH/deploy/config/$SERVICE_TEMPLATE" "$DEST_PATH/config/$ADMIN_CONF" "$_A_HOST|$_A_INT_PORT" "$ADMIN_COMPONENT" "127.0.0.1" "$_A_AUTH" "$_A_LOGGING" "$_A_CARVER" "sudo"

    # Prepare data folder
    sudo mkdir -p "$DEST_PATH/data"

    # Prepare carved files folder
    sudo mkdir -p "$DEST_PATH/carved_files"
    sudo chown osctrl.osctrl "$DEST_PATH/carved_files"

    # Copy osquery tables JSON file
    sudo cp "$SOURCE_PATH/deploy/osquery/data/$OSQUERY_VERSION.json" "$DEST_PATH/data"

    # Prepare static files for Admin service
    _static_files "$MODE" "$SOURCE_PATH" "$DEST_PATH" "admin/templates" "tmpl_admin"
    _static_files "$MODE" "$SOURCE_PATH" "$DEST_PATH" "admin/static" "static"

    # Systemd configuration for Admin service
    _systemd "osctrl" "osctrl" "osctrl-admin" "$SOURCE_PATH" "$DEST_PATH" "--redis --db --jwt --config"
  fi

  if [[ "$PART" == "all" ]] || [[ "$PART" == "$API_COMPONENT" ]]; then
    # Build API service
    make api

    # Configuration file generation for API service
    configuration_service "$SOURCE_PATH/deploy/config/$SERVICE_TEMPLATE" "$DEST_PATH/config/$API_CONF" "$_P_HOST|$_P_INT_PORT" "$API_COMPONENT" "127.0.0.1" "$_P_AUTH" "$_P_LOGGING" "$_P_CARVER" "sudo"

    # Systemd configuration for API service
    _systemd "osctrl" "osctrl" "osctrl-api" "$SOURCE_PATH" "$DEST_PATH" "--redis --db --jwt --config"
  fi

  # Some needed files
  __db_conf="$DEST_PATH/config/$DB_CONF"
  __osquery_cfg="$SOURCE_PATH/deploy/osquery/osquery-cfg.json"
  __osctrl_crt="/etc/nginx/certs/osctrl.crt"

  # Create initial environment to enroll machines
  log "Creating environment $ENVIRONMENT"
  "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment add -n "$ENVIRONMENT" -host "$_T_HOST" -crt "$__osctrl_crt"

  # Create admin user
  log "Creating admin user"
  "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" user add -u "$_ADMIN_USER" -p "$_ADMIN_PASS" -a -e "$ENVIRONMENT" -n "Admin"

  # If we are in dev, lower intervals
  if [[ "$MODE" == "dev" ]]; then
    log "Decrease intervals for environment $ENVIRONMENT"
    "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment update -n "$ENVIRONMENT" -l "75" -c "45" -q "60"
    log "Enable verbose mode"
    "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment add-osquery-option -n "$ENVIRONMENT" -o "verbose" -t bool -b true
    log "Disable splay for schedule"
    "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment add-osquery-option -n "$ENVIRONMENT" -o "schedule_splay_percent" -t int -i 0
    log "Add uptime query to schedule"
    "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment add-scheduled-query -n "$ENVIRONMENT" -q "SELECT * FROM uptime;" -Q "uptime" -i 60
  fi

  log "Checking if service is ready"
  while true; do
    _readiness=$(curl -k --write-out %{http_code} --head --silent --output /dev/null "https://$_T_HOST")
    if [[ "$_readiness" == "200" ]]; then
      log "Status $_readiness, service ready"
      break
    else
      log "Status $_readiness, not yet"
    fi
    sleep 1
  done

  # Enroll host in environment
  if [[ "$ENROLL" == true ]]; then
    log "Adding host in environment $ENVIRONMENT"
    eval $( "$DEST_PATH"/osctrl-cli --db -D "$__db_conf" environment quick-add -n "$ENVIRONMENT" )
  fi
fi

echo
log "Your osctrl is ready 👌🏽"
echo
if [[ "$MODE" == "dev" ]]; then
  log " -> https://$DEV_HOST:$_A_PUB_PORT"
  echo
fi

if [[ "$UPGRADE" == false ]]; then
  echo
  log " -> https://$_A_HOST:$_A_PUB_PORT"
  log " -> 🔐 Credentials: $_ADMIN_USER / $_ADMIN_PASS"
  echo
fi

# Done
_END_TIME=$(date +%s)
_DIFFERENCE=$(echo "$_END_TIME-$_START_TIME" | bc)
_MINUTES="$(echo "$_DIFFERENCE/60" | bc) minutes"
_SECONDS="$(echo "$_DIFFERENCE%60" | bc) seconds"

echo
log "Completed in $_MINUTES and $_SECONDS"
echo

exit 0

# kthxbai

# Standard deployment in a linux box would be like:
# ./deploy/provision.sh -m dev -s /path/to/code --nginx --postgres --redis -p all --all-hostname "dev.osctrl.net" -E
