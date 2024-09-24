#!/usr/bin/env bash
#
# Provisioning functions for osctrl
#
# Import with: source "PATH_TO/lib.sh"

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

# Update packages
function package_repo_update() {
  if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
    log "Running apt-get update"
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
  elif [[ "$DISTRO" == "centos" ]]; then
    log "Running yum check-update"
    sudo yum -y check-update || { rc=$?; [ "$rc" -eq 100 ] && log "returned $rc"; }
  fi
}

# Install a package in the system
#   string  package_name
function package() {
  if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
    INSTALLED=`dpkg-query -W -f='${Status} ${Version}\n' "$1" || true`
    if [[ -n "$INSTALLED" && ! "$INSTALLED" = *"unknown ok not-installed"* ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo DEBIAN_FRONTEND=noninteractive apt-get install $1 -y -q --no-install-recommends
    fi
  elif [[ "$DISTRO" == "centos" ]]; then
    if [[ ! -n "$(rpm -V $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo yum install $1 -y
    fi
  fi
}

# Install several packages in the system
#   string  package_name0
#   string  package_name1
#   ...
#   string  package_nameN
function packages() {
  for i in "$@"; do
    package "$i"
  done
}

# Add osquery repository for Ubuntu
function repo_osquery_ubuntu() {
  log "Adding osquery repository keys"
  sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B

  log "Adding osquery repository"
  sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
}

# Install fpm to generate packages
function install_fpm() {
  log "Installing fpm dependencies"
  packages ruby ruby-dev rubygems build-essential

  log "Installing fpm"
  sudo gem install --no-ri --no-rdoc fpm
}

# Generate

# Configure main nginx
#   string  configuration_template
#   string  configuration_output
#   string  nginx_user
#   string  nginx_modules
#   string  nginx_folder
function nginx_main() {
  local __conf=$1
  local __out=$2
  local __user=$3
  local __modules=$4
  local __nginx=$5

  cat "$__conf" | sed "s|SERVER_USER|$__user|g" | sed "s|MODULES_CONF|$__modules|g" | sudo tee "$__nginx/$__out"
}

# Configure nginx for a service
#   string  configuration_template
#   string  certificate_file
#   string  certificate_key
#   string  certificate_dh
#   int     public_port
#   int     private_port
#   string  configuration_output
#   string  nginx_folder
function nginx_service() {
  local __conf=$1
  local __cert=$2
  local __key=$3
  local __dh=$4
  local __pport=$5
  local __iport=$6
  local __out=$7
  local __nginx=$8

  local __available="$__nginx/sites-available"
  local __enabled="$__nginx/sites-enabled"

  sudo mkdir -p "$__available"
  sudo mkdir -p "$__enabled"

  nginx_generate "$__conf" "$__cert" "$__key" "$__dh" "$__pport" "$__iport" "localhost" "$__available/$__out" "sudo"

  if [[ -f "$__enabled/default" ]]; then
    sudo rm -f "$__enabled/default"
  fi

  sudo ln -sf "$__available/$__out" "$__enabled/$__out"
}

# Generate nginx configuration for a service
#   string  configuration_template
#   string  certificate_file
#   string  certificate_key
#   string  certificate_dh
#   int     public_port
#   int     private_port
#   string  configuration_output
function nginx_generate() {
  local __conf=$1
  local __cert=$2
  local __key=$3
  local __dh=$4
  local __pport=$5
  local __iport=$6
  local __host=$7
  local __out=$8
  local __sudo=$9

  log "Generating $__out configuration"

  cat "$__conf" | sed "s|PUBLIC_PORT|$__pport|g" | sed "s|CER_FILE|$__cert|g" | sed "s|KEY_FILE|$__key|g" | sed "s|DHPARAM_FILE|$__dh|g" | sed "s|PRIVATE_PORT|$__iport|g" | sed "s|PRIVATE_HOST|$__host|g" | $__sudo tee "$__out"
}

# Generate self-signed certificates
#   string  path_to_certs
#   string  certificate_name
#   int     rsa_bits
#   string  certificate_domain
#   string  certificate_ip
function self_signed_cert() {
  local __certs=$1
  local __name=$2
  local __bits=$3
  local __host=$4
  local __ip=$5

  local __devcert="$__certs/$__name.crt"
  local __devkey="$__certs/$__name.key"

  sudo openssl req -x509 -newkey rsa:$__bits -sha256 -days 365 -nodes \
  -keyout "$__devkey" -out "$__devcert" -subj "/CN=$__host" \
  -addext "subjectAltName=IP:$__ip"
}

# Generate certbot certificates for nginx
#   string  certs_directory
#   string  certificate_name
#   string  email_certbot
#   string  domain_certificate
function certbot_certificates_nginx() {
  local __certs_path=$1
  local __name=$2
  local __email=$3
  local __domain=$4
  local __cert="$__certs_path/$__name.crt"
  local __key="$__certs_path/$__name.key"

  log "Installing certbot components"

  package software-properties-common
  sudo add-apt-repository ppa:certbot/certbot -y
  package_repo_update
  package python-certbot-nginx

  # Just in case nginx is running
  sudo systemctl stop nginx

  # Generating certificate
  log "Generating certificate with certbot for $DOMAIN"
  sudo certbot -n --agree-tos --standalone certonly -m "$__email" -d "$__domain" --cert-name "$__name" --cert-path "$__cert" --key-path "$__key"
}

# Service configuration file generation
#   string  conf_template
#   string  conf_destination
#   string  service_host_port (host|port)
#   string  service_name
#   string  listener
#   string  auth_option
#   string  logging_option
#   string  carver_option
#   string  sudo_command
function configuration_service() {
  local __conf=$1
  local __dest=$2
  local __tlshost=`echo $3 | cut -d"|" -f1`
  local __tlsport=`echo $3 | cut -d"|" -f2`
  local __service=$4
  local __listener=$5
  local __auth=$6
  local __logging=$7
  local __carver=$8
  local __sudo=$9

  log "Generating $__dest configuration"

  cat "$__conf" | sed "s|_SERVICE_PORT|$__tlsport|g" | sed "s|_SERVICE_HOST|$__tlshost|g" | sed "s|_LISTENER|$__listener|g" | sed "s|_SERVICE_NAME|$__service|g" | sed "s|_SERVICE_AUTH|$__auth|g" | sed "s|_SERVICE_LOGGING|$__logging|g" | sed "s|_SERVICE_CARVER|$__carver|g" |  $__sudo tee "$__dest"
}

# DB configuration file generation
#   string  conf_template
#   string  conf_destination
#   string  db_host
#   string  db_port
#   string  db_name
#   string  db_username
#   string  db_password
function configuration_db() {
  local __conf=$1
  local __dest=$2
  local __dbhost=$3
  local __dbport=$4
  local __dbname=$5
  local __dbuser=$6
  local __dbpass=$7
  local __sudo=$8

  log "Generating $__dest configuration"

  cat "$__conf" | sed "s|_DB_HOST|$__dbhost|g" | sed "s|_DB_PORT|$__dbport|g" | sed "s|_DB_NAME|$__dbname|g" | sed "s|_DB_USERNAME|$__dbuser|g" | sed "s|_DB_PASSWORD|$__dbpass|g" | $__sudo tee "$__dest"
}

# Cache configuration file generation
#   string  conf_template
#   string  conf_destination
#   string  cache_host
#   string  cache_port
#   string  cache_password
function configuration_cache() {
  local __conf=$1
  local __dest=$2
  local __cachehost=$3
  local __cacheport=$4
  local __cachepass=$5
  local __sudo=$6

  log "Generating $__dest configuration"

  cat "$__conf" | sed "s|_REDIS_HOST|$__cachehost|g" | sed "s|_REDIS_PORT|$__cacheport|g" | sed "s|_REDIS_PASSWORD|$__cachepass|g" | $__sudo tee "$__dest"
}

# Enable service as systemd
#   string  service_user
#   string  service_group
#   string  service_name
#   string  path_to_code
#   string  path_destination
#   string  service_arguments
function _systemd() {
  local __user=$1
  local __group=$2
  local __service=$3
  local __path=$4
  local __dest=$5
  local __args=$6
  local __template="$__path/deploy/config/systemd.service"
  local __systemd="/lib/systemd/system/$__service.service"

  # Creating user for services
  if [[ $(grep -c "$__user" /etc/passwd) -eq 0 ]]; then
    sudo useradd "$__user" -s /sbin/nologin -M
  fi

  # Adding service
  cat "$__template" | sed "s|_UU|$__user|g" | sed "s|_GG|$__group|g" | sed "s|_DEST|$__dest|g" | sed "s|_NAME|$__service|g" | sed "s|_ARGS|$__args|g" | sudo tee "$__systemd"
  sudo chmod 755 "$__systemd"

  # Copying binaries
  sudo cp "$__path/bin/$__service" "$__dest"

  # Enable and start service
  sudo systemctl enable "$__service.service"
  sudo systemctl start "$__service.service"
}

# Prepare service directories and copy static files
#   string  mode_of_operation
#   string  path_to_code
#   string  path_destination
#   string  server_component
#   string  target_files
function _static_files() {
  local __mode=$1
  local __path=$2
  local __dest=$3
  local __from=$4
  local __target=$5

  # Files will be linked if we are in dev
  if [[ "$__mode" == "dev" ]]; then
    if [[ ! -d "$__dest/$__target" ]]; then
      sudo ln -s "$__path/$__from" "$__dest/$__target"
    fi
  else
    sudo rsync -av "$__path/$__from/" "$__dest/$__target"
  fi
}

# Create empty DB and username
#   string  PostgreSQL_db_name
#   string  PostgreSQL_system_user
#   string  PostgreSQL_db_user
#   string  PostgreSQL_db_pass
#   string  PostgerSQL_psql
function db_user_postgresql() {
  local __pgdb=$1
  local __pguser=$2
  local __dbuser=$3
  local __dbpass=$4
  local __psql=$5

  log "Creating user"
  local _dbstatementuser="CREATE USER $__dbuser;"
  sudo su - "$__pguser" -c "$__psql -c \"$_dbstatementuser\""

  log "Adding password to user"
  local _dbstatementpass="ALTER USER $__dbuser WITH ENCRYPTED PASSWORD '$__dbpass';"
  sudo su - "$__pguser" -c "$__psql -c \"$_dbstatementpass\""

  log "Creating new database"
  sudo su - "$__pguser" -c "$__psql -c 'ALTER ROLE $__dbuser WITH CREATEDB'"
  sudo su - "$__pguser" -c "$__psql -c 'CREATE DATABASE $__pgdb'"

  log "Make user owner of database"
  local _dbstatementowner="ALTER DATABASE $__pgdb OWNER TO $__dbuser;"
  sudo su - "$__pguser" -c "$__psql -c \"$_dbstatementowner\""

  log "Granting privileges to user"
  local _dbstatementgrant="GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $__dbuser;"
  sudo su - "$__pguser" -c "$__psql -d $__pgdb -c '$_dbstatementgrant'"
}

# Configure Redis
#   string  redis_conf_file_location
#   string  redis_service_name
#   string  redis_conf_file
#   string  redis_password
function configure_redis() {
  local __conf=$1
  local __service=$2
  local __redis=$3
  local __password=$4

  log "Redis require password"

  cat "$__conf" | sed "s|REDIS_PASSWORD|$__password|g" | sudo tee "$__redis"

  # For some reason in Ubuntu 20.04 redis does not communicate with systemd, this will fix it
  local _systemd_redis="/lib/systemd/system/redis-server.service"
  cat "$_systemd_redis" | sed "s|Type=forking|Type=notify|g" | sudo tee "$_systemd_redis"

  sudo systemctl daemon-reload
  sudo systemctl restart "$__service"
  sudo systemctl enable "$__service"
}

# Customize the MOTD in CentOS
#   string  path_to_motd_script
function set_motd_centos() {
  local __motd=$1
  local __centosmotd="/etc/motd.sh"

  sudo cp "$__motd" "$__centosmotd"
  sudo chmod +x "$__centosmotd"
  echo "$__centosmotd" | sudo tee -a /etc/profile
}

# Install go 1.23.0 from tgz
function install_go_23() {
  local __version="1.23.0"
  local __arch="$(uname -i)"
  if [[ "$__arch" == "aarch64" ]]; then
    __arch="arm64"
  fi

  if [[ "$__arch" == "x86_64" ]]; then
    __arch="amd64"
  fi
  
  local __file="go$__version.linux-$__arch.tar.gz"
  local __url="https://dl.google.com/go/$__file"
  if ! [[ -d "/usr/local/go" ]]; then
    log  "Installing Golang $__version"
    sudo curl -sO "$__url"
    sudo tar -xf "$__file"
    sudo mv go /usr/local
    echo "export PATH=$PATH:/usr/local/go/bin" | sudo tee -a /etc/profile
    source /etc/profile
    go version
  else
    source /etc/profile
    go version
  fi
}

# Generate self-signed certificate for SAML authentication
#   string  path_to_certs
#   string  certificate_name
#   int     rsa_bits
function self_signed_saml() {
  local __certs=$1
  local __name=$2
  local __bits=$3

  local __samlcert="$__certs/$__name.crt"
  local __samlkey="$__certs/$__name.key"

  sudo openssl req -x509 -newkey rsa:$__bits -sha256 -days 365 -nodes \
  -keyout "$__samlkey" -out "$__samlcert" -subj "/CN=$__name"
}
