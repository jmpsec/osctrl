#!/usr/bin/env bash
#
# [ osctrl 🎛 ]: Provisioning script for prod and dev
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
#   update  Provision will update the service running in the machine.
#
# Arguments for TYPE:
#   self    Provision will use a self-signed TLS certificate that will be generated.
#   own     Provision will use the TLS certificate provided by the user.
#   certbot Provision will generate a TLS certificate using letsencrypt/certbot. More info here: https://certbot.eff.org/
# 
# Argument for PART:
#   admin   Provision will deploy only the admin interface.  
#   tls     Provision will deploy only the TLS endpoint.
#   all     Provision will deploy both the admin and the TLS endpoint.
#
# Optional Parameters:
#   --public-tls-port PORT 	    Port for the TLS endpoint service. Default is 443
#   --public-admin-port PORT 	  Port for the admin service. Default is 8443
#   --private-tls-port PORT 	  Port for the TLS endpoint service. Default is 9000
#   --private-admin-port PORT 	Port for the admin service. Default is 9001
#   --tls-hostname HOSTNAME     Hostname for the TLS endpoint service. Default is 127.0.0.1
#   --admin-hostname HOSTNAME   Hostname for the admin service. Default is 127.0.0.1
#   -U          --update 		    Pull from master and sync files to the current folder.
#   -k PATH     --keyfile PATH 	Path to supplied TLS key file.
#   -c PATH     --certfile PATH Path to supplied TLS server PEM certificate(s) bundle.
#   -d DOMAIN   --domain DOMAIN Domain for the TLS certificate to be generated using letsencrypt.
#   -e EMAIL    --email EMAIL 	Domain for the TLS certificate to be generated using letsencrypt.
#   -s PATH     --source PATH 	Path to code. Default is /vagrant
#   -S PATH     --dest PATH 	  Path to binaries. Default is /opt/osctrl
#   -n          --nginx 		    Install and configure nginx as TLS termination.
#   -P          --postgres 		  Install and configure PostgreSQL as backend.
#   -D          --docker        Runs the service in docker
#
# Examples:
#   Provision service in development mode, code is in /vagrant and both admin and tls:
#     provision.sh -m dev -s /vagrant -p all
#   Provision service in production mode using my own certificate and only with TLS endpoint:
#     provision.sh -m prod -t own -k /etc/certs/my.key -c /etc/certs/cert.crt -p tls
#   Update service in development mode and running admin only from /home/foobar/osctrl:
#     provision.sh -m dev -U -s /home/foobar/osctrl -p admin
#

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
  printf "\n"
  printf "\n"
  printf "\n [ osctrl ] : Provisioning script\n"
  printf "\n"
  printf "\n"
  printf "\nUsage: %s [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...\n" "${0}"
  printf "\nParameters:\n"
  printf "  -h, --help \t\tShows this help message and exit.\n"
  printf "  -m MODE, --mode MODE \tMode of operation. Default value is dev\n"
  printf "  -t TYPE, --type TYPE \tType of certificate to use. Default value is self\n"
  printf "  -p PART, --part PART \tPart of the service. Default is all\n"
  printf "\nArguments for MODE:\n"
  printf "  dev \t\tProvision will run in development mode. Certificate will be self-signed.\n"
  printf "  prod \t\tProvision will run in production mode.\n"
  printf "  update \tProvision will update the service running in the machine.\n"
  printf "\nArguments for TYPE:\n"
  printf "  self \t\tProvision will use a self-signed TLS certificate that will be generated.\n"
  printf "  own \t\tProvision will use the TLS certificate provided by the user.\n"
  printf "  certbot \tProvision will generate a TLS certificate using letsencrypt/certbot. More info here: https://certbot.eff.org/\n"
  printf "\nArguments for PART:\n"
  printf "  admin \t\tProvision will deploy only the admin interface.\n"
  printf "  tls \t\tProvision will deploy only the TLS endpoint.\n"
  printf "  all \t\tProvision will deploy both the admin and the TLS endpoint.\n"
  printf "\nOptional Parameters:\n"
  printf "  --public-tls-port PORT \tPort for the TLS endpoint service. Default is 443\n"
  printf "  --public-admin-port PORT \tPort for the admin service. Default is 8443\n"
  printf "  --private-tls-port PORT \tPort for the TLS endpoint service. Default is 9000\n"
  printf "  --private-admin-port PORT \tPort for the admin service. Default is 9001\n"
  printf "  --tls-hostname HOSTNAME \tHostname for the TLS endpoint service. Default is 127.0.0.1\n"
  printf "  --admin-hostname HOSTNAME \tHostname for the admin service. Default is 127.0.0.1\n"
  printf "  -U          --update \t\tPull from master and sync files to the current folder.\n"
  printf "  -c PATH     --certfile PATH \tPath to supplied TLS server PEM certificate(s) bundle.\n"
  printf "  -d DOMAIN   --domain DOMAIN \tDomain for the TLS certificate to be generated using letsencrypt.\n"
  printf "  -e EMAIL    --email EMAIL \tDomain for the TLS certificate to be generated using letsencrypt.\n"
  printf "  -s PATH     --source PATH \tPath to code. Default is /vagrant\n"
  printf "  -S PATH     --dest PATH \tPath to binaries. Default is /opt/osctrl\n"
  printf "  -n          --nginx \t\tInstall and configure nginx as TLS termination.\n"
  printf "  -P          --postgres \t\tInstall and configure PostgreSQL as backend.\n"
  printf "  -D          --docker \t\tRuns the service in docker.\n"
  printf "\nExamples:\n"
  printf "  Provision service in development mode, code is in /vagrant and both admin and tls:\n"
  printf "\t%s -m dev -s /vagrant -p all\n" "${0}"
  printf "  Provision service in production mode using my own certificate and only with TLS endpoint:\n"
  printf "\t%s -m prod -t own -k /etc/certs/my.key -c /etc/certs/cert.crt -p tls\n" "${0}"
  printf "  Update service in development mode and running admin only from /home/foobar/osctrl:\n"
  printf "\t%s -U -s /home/foobar/osctrl -p admin\n" "${0}"
  printf "\n"
}

# We want the provision script to fail as soon as there are any errors
set -e

# Values not intended to change
TLS_CONF="tls.json"
TLS_TEMPLATE="$TLS_CONF.template"

# Default values for arguments
SHOW_USAGE=false
MODE="dev"
TYPE="self"
KEYFILE=""
CERTFILE=""
DOMAIN=""
EMAIL=""
DOCKER=false
NGINX=false
POSTGRES=false
SOURCE_PATH=/vagrant
DEST_PATH=/opt/osctrl

# Backend values
_DB_HOST="localhost"
_DB_NAME="osctrl"
_DB_SYSTEM_USER="postgres"
_DB_USER="osctrl"
_DB_PASS="osctrl"
_DB_PORT="5432"

# TLS Service
_T_INT_PORT="9000"
_T_PUB_PORT="443"
_T_HOST="127.0.0.1"

# Admin Service
_A_INT_PORT="9001"
_A_PUB_PORT="8443"
_A_HOST="127.0.0.1"

# Default admin credentials
_ADMIN_USER="admin"
_ADMIN_PASS="admin"

# Arrays with valid arguments
VALID_MODE=("dev" "prod" "update")
VALID_TYPE=("self" "own" "certbot")
VALID_PART=("tls" "admin" "all")

# Generate secret for osquery
OSCTRL_SECRET_DEV=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)

# Extract arguments
ARGS=$(getopt -n "$0" -o hm:t:p:UPk:nD:c:d:e:s:S: -l "help,mode:,type:,part:,public-tls-port:,private-tls-port:,public-admin-port:,private-admin-port:,tls-hostname:,admin-hostname:,update,keyfile:,nginx,postgres,docker,certfile:,domain:,email:,source:,dest:" -- "$@")

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
        _log "Invalid server part"
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
    -U|--update)
      SHOW_USAGE=false
      UPDATE=true
      shift
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
    -D|--docker)
      SHOW_USAGE=false
      DOCKER=true
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

log ""
log ""
log "Provisioning [ osctrl ]"
log ""
log "  -> [$MODE] mode and with [$TYPE] certificate"
log ""
log "  -> Deploying TLS service for ports $_T_PUB_PORT:$_T_INT_PORT"
log "  -> Hostname for TLS endpoint: $_T_HOST"
log ""
log "  -> Deploying Admin service for ports $_A_PUB_PORT:$_A_INT_PORT"
log "  -> Hostname for admin: $_A_HOST"
log ""
log ""

package_repo_update

# Required packages
package apt-utils
package sudo
package git
package wget
package build-essential
package gcc
package make
package openssl
package tmux

# nginx as TLS termination
if [[ "$NGINX" == true ]]; then
  # Some static values for now that can be turned into arguments eventually
  NGINX_PATH="/etc/nginx"
  package nginx

  _certificate_name="osctrl"
  _certificates_dir="$NGINX_PATH/certs"
  sudo mkdir -p "$_certificates_dir"

  _cert_file="$_certificates_dir/$_certificate_name.crt"
  _key_file="$_certificates_dir/$_certificate_name.key"
  _dh_file="$_certificates_dir/dhparam.pem"
  _dh_bits="1024"

  # Self-signed certificates for dev
  if [[ "$MODE" == "dev" ]]; then
    self_certificates_nginx "$_certificates_dir" "$_certificate_name"
  fi
  # Certbot certificates for prod and 4096 dhparam file
  if [[ "$MODE" == "prod" ]]; then
    _dh_bits="4096"
    #certbot_certificates_nginx "$_certificates_dir" "$_certificate_name" "$EMAIL" "$DOMAIN"
    # FIXME: REMEMBER GENERATE THE CERTIFICATES MANUALLY!
    sudo cp "/etc/letsencrypt/archive/osctrl/fullchain1.pem" "$_cert_file"
    sudo cp "/etc/letsencrypt/archive/osctrl/privkey1.pem" "$_key_file" 
  fi

  # Diffie-Hellman parameter for DHE ciphersuites
  log "Generating dhparam.pem with $_dh_bits bits... It may take a while"
  sudo openssl dhparam -out "$_dh_file" $_dh_bits &>/dev/null

  # Configuration for nginx
  configure_nginx "$SOURCE_PATH/deploy/nginx.conf" "" "" "" "" "" "osctrl.conf" "$NGINX_PATH"

  # Configuration for TLS service
  configure_nginx "$SOURCE_PATH/deploy/generic.conf" "$_cert_file" "$_key_file" "$_dh_file" "$_T_PUB_PORT" "$_T_INT_PORT" "tls.conf" "$NGINX_PATH" 
  
  # Configuration for Admin service
  configure_nginx "$SOURCE_PATH/deploy/generic.conf" "$_cert_file" "$_key_file" "$_dh_file" "$_A_PUB_PORT" "$_A_INT_PORT" "admin.conf" "$NGINX_PATH"

  # Restart nginx
  sudo nginx -t
  sudo service nginx restart
fi

# PostgreSQL - Backend
if [[ "$DOCKER" == false ]]; then
  if [[ "$POSTGRES" == true ]]; then
    package postgresql 
    package postgresql-contrib

    POSTGRES_CONF="$SOURCE_PATH/deploy/postgres/pg_hba.conf"
    configure_postgres "$POSTGRES_CONF"
    db_user_postgresql "$_DB_NAME" "$_DB_SYSTEM_USER" "$_DB_USER" "$_DB_PASS"
  fi
fi

# Golang
package golang-go
package golang-glide

# Build code
cd "$SOURCE_PATH"
export GOPATH="$SOURCE_PATH"
make clean
make clean-deps
make update-deps
make

# Prepare destination folder
sudo mkdir -p "$DEST_PATH"

# Prepare configuration folder
sudo mkdir -p "$DEST_PATH/config"

# Prepare data folder
sudo mkdir -p "$DEST_PATH/data"

# Configure service
configure_service "$SOURCE_PATH/deploy/$TLS_TEMPLATE" "$DEST_PATH/config/$TLS_CONF" "$_T_HOST|$_T_INT_PORT" "$_DB_HOST" "$_DB_PORT" "$_DB_NAME" "$_DB_USER" "$_DB_PASS" "$_A_HOST|$_A_INT_PORT"

# Copy osquery tables JSON file
sudo cp "$SOURCE_PATH/deploy/data/3.3.0.json" "$DEST_PATH/data"

# Configure credentials to access admin console
configure_credentials "$DEST_PATH/config/$TLS_CONF" "$DEST_PATH/config/$TLS_CONF" "$_ADMIN_USER" "$_ADMIN_PASS"

# Prepare static files for admin
_static_files "$MODE" "$SOURCE_PATH" "$DEST_PATH"

# Prepare osquery configuration files directory
sudo mkdir -p "$DEST_PATH/osquery-confs"

# Copy configuration for dev
sudo cp "$SOURCE_PATH/deploy/osquery-dev.conf" "$DEST_PATH/osquery-confs"

# Install osquery
#repo_osquery_ubuntu
#package_repo_update
#package osquery
OSQUERYDEB="osquery_3.3.0_1.linux.amd64.deb"
sudo curl -s "https://osquery-packages.s3.amazonaws.com/deb/$OSQUERYDEB" -o "/tmp/$OSQUERYDEB" 
sudo dpkg -i "/tmp/$OSQUERYDEB"

# Verify osquery
osqueryi -version

# Prepare flagsfile
cat "$SOURCE_PATH/deploy/osquery-dev.flags" | sed "s|__TLSHOST|$_T_HOST|g" | sudo tee "/etc/osquery/osquery.flags"

# Copy flags for dev
sudo cp "/etc/osquery/osquery.flags" "$DEST_PATH/osquery-confs/osquery-dev.flags"

# Prepare secret for dev
sudo touch "/etc/osquery/osquery.secret"

# Copy server TLS certificate
sudo mkdir -p "/etc/osquery/certs"
sudo cp "/etc/nginx/certs/osctrl.crt" "/etc/osquery/certs/osctrl.crt"

echo "$OSCTRL_SECRET_DEV" | sudo tee "/etc/osquery/osquery.secret"
cat "$DEST_PATH/config/$TLS_CONF" | sed "s|_OSQUERY_SECRET_DEV|$OSCTRL_SECRET_DEV|g" | sudo tee "$DEST_PATH/config/$TLS_CONF"

# MD5 for secret
OSCTRL_SECRETMD5_DEV=$(echo "$OSCTRL_SECRET_DEV" | md5sum | cut -d " " -f1)
cat "$DEST_PATH/config/$TLS_CONF" | sed "s|_OSQUERY_SECRETMD5_DEV|$OSCTRL_SECRETMD5_DEV|g" | sudo tee "$DEST_PATH/config/$TLS_CONF"

# Prepare quick install
cat "$SOURCE_PATH/deploy/osctrl-dev.sh" | sed "s|__TLSHOST|$_T_HOST|g" | sed "s|__OSQUERYSECRET|$OSCTRL_SECRET_DEV|g" | sed "s|__SECRETMD5|$OSCTRL_SECRETMD5_DEV|g" | sed -e '/__CERT_CONTENT/{r /etc/osquery/certs/osctrl.crt' -e 'd}' | sudo tee "$DEST_PATH/osquery-confs/osquery-dev.sh"

# Start osqueryd service
sudo systemctl start osqueryd
# Enable osqueryd to start at boot
sudo systemctl enable osqueryd

# Systemd services for non-docker deployments
if [[ "$DOCKER" == false ]]; then
  _systemd "osctrl" "osctrl-tls" "$SOURCE_PATH" "$DEST_PATH"
  # See logs with sudo journalctl -f -u osctrl-tls or alias '_klogs'
  echo "alias _klogs='sudo journalctl -f -u osctrl-tls'" >> ~/.profile
fi

# Ascii art is always appreciated
if [[ "$DOCKER" == false ]]; then
  set_motd_ubuntu "$SOURCE_PATH/deploy/motd-osctrl.sh"
fi

echo
echo
echo
log "Your osctrl is ready 👌🏽"
echo
if [[ "$MODE" == "dev" ]]; then
  log " -> https://$_A_HOST:$_A_PUB_PORT"
  echo
  log " -> 🔐 Credentials: $_ADMIN_USER/$_ADMIN_PASS"
  echo
fi
exit 0

# kthxbai