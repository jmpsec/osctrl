#!/bin/bash
#
# [ osctrl 🎛 ]: Helper script to generate a deb package
#
# Usage: osctrl-deb.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...
#
# Parameters:
#   -h, --help      Shows this help message and exit.
#   -x SECRET_FILE  Secret file to be used by osquery. Default is /etc/osquery/osquery.secret
#   -c CRT_FILE     TLS Certificate file to be used by osquery. Default is /etc/osquery/certs/osctrl.crt
#   -T HOSTNAME     Hostname for the TLS endpoint service. Default is 127.0.0.1
#   -o OUTPUT_FILE  Path to the output deb file. Default is osctrl.deb
#   -d DIRECTORY    Directory to build the package filesystem. Default is osctrl
#   -C CONTEXT      Context to use in the flagsfile. Default is dev
#   -

# How does it work?
function usage() {
  printf "\n [ osctrl ] : Helper script to generate a deb package\n"
  printf "\nUsage: %s [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...\n" "${0}"
  printf "\nParameters:\n"
  printf "  -h, --help \t\tShows this help message and exit.\n"
  printf "  -x SECRET_FILE \tSecret file to be used by osquery. Default is /etc/osquery/osquery.secret\n"
  printf "  -c CRT_FILE \tTLS Certificate file to be used by osquery. Default is /etc/osquery/certs/osctrl.crt\n"
  printf "  -T HOSTNAME \tHostname for the TLS endpoint service. Default is 127.0.0.1\n"
  printf "  -o OUTPUT_FILE \tPath to the output deb file. Default is osctrl.deb\n"
  printf "  -d DIRECTORY \tDirectory to build the package filesystem. Default is osctrl\n"
  printf "  -C CONTEXT   \tContext to use in the flagsfile. Default is dev\n"
  printf "  -C CONTEXT   \tContext to use in the flagsfile. Default is dev\n"
  printf "  -C CONTEXT   \tContext to use in the flagsfile. Default is dev\n"
  printf "  -C CONTEXT   \tContext to use in the flagsfile. Default is dev\n"
  printf "\n"
}

# We want the provision script to fail as soon as there are any errors
set -e

# Default values for parameters
_S_SECRET_FILE="/etc/osquery/osquery.secret"
_S_CERTFILE="/etc/nginx/certs/osctrl.crt"
_SECRET_FILE="/etc/osquery/osquery.secret"
_CERTFILE="/etc/osquery/certs/osctrl.crt"
_TLS_HOSTNAME="127.0.0.1"
_OUTPUT_FILE="osctrl.deb"
_SOURCE_DIR="osctrl"
_CONTEXT="dev"

# Extract arguments
ARGS=$(getopt -n "$0" -o hx:c:T:o:d:C: -l "help" -- "$@")

eval set -- "$ARGS"

while true; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -x)
      _SECRET_FILE=$2
      shift 2
      ;;
    -c)
      _CERTFILE=$2
      shift 2
      ;;
    -T)
      _TLS_HOSTNAME=$2
      shift 2
      ;;
    -o)
      _OUTPUT_FILE=$2
      shift 2
      ;;
    -d)
      _SOURCE_DIR=$2
      shift 2
      ;;
    -C)
      _CONTEXT=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
  esac
done

echo " [+] Creating directory structure for package in $_SOURCE_DIR"
rm -Rf "$_SOURCE_DIR"
mkdir -p "$_SOURCE_DIR/DEBIAN"

echo " [+] Preparing package control configuration file..."
cat <<EOF > "$_SOURCE_DIR/DEBIAN/control"
Package: osctrl
Depends: osquery
Architecture: all
Maintainer: @javuto
Priority: optional
Version: 1.0
Description: osctrl - Fast and efficient operative system management
EOF

echo " [+] Preparing preinst script..."
cat <<EOF > "$_SOURCE_DIR/DEBIAN/preinst"
#!/bin/bash
/bin/systemctl stop osqueryd
EOF
chmod 755 "$_SOURCE_DIR/DEBIAN/preinst"

echo " [+] Preparing osctrl secret file $_SECRET_FILE"
mkdir -p "$_SOURCE_DIR/etc/osquery"
sudo cat "$_S_SECRET_FILE" > "$_SOURCE_DIR$_SECRET_FILE"
chmod 700 "$_SOURCE_DIR$_SECRET_FILE"

echo " [+] Preparing osquery flags for osctrl..."
cat <<EOF > "$_SOURCE_DIR/etc/osquery/osquery.flags"
--host_identifier=uuid
--force=true
--verbose=true
--debug
--utc
--pidfile=/tmp/osquery.pid
--database_path=/tmp/osquery.db
--enroll_secret_path=$_SECRET_FILE
--enroll_tls_endpoint=/dev/osquery_enroll
--config_plugin=tls
--config_tls_endpoint=/dev/osquery_config
--config_tls_refresh=10
--logger_plugin=tls
--logger_tls_compress=false
--logger_tls_endpoint=/dev/osquery_log
--logger_tls_period=10
--disable_distributed=false
--distributed_interval=10
--distributed_plugin=tls
--distributed_tls_read_endpoint=/dev/osquery_read
--distributed_tls_write_endpoint=/dev/osquery_write
--tls_dump=true
--tls_hostname=$_TLS_HOSTNAME
--tls_server_certs=$_CERTFILE
EOF
chmod 700 "$_SOURCE_DIR/etc/osquery/osquery.flags"

echo " [+] Preparing osctrl certificates..."
mkdir -p "$_SOURCE_DIR/etc/osquery/certs"
sudo cat "$_S_CERTFILE" > "$_SOURCE_DIR$_CERTFILE"
chmod 700 "$_SOURCE_DIR$_CERTFILE"

echo " [+] Preparing postinst script..."
cat <<EOF > "$_SOURCE_DIR/DEBIAN/postinst"
#!/bin/bash
/bin/systemctl start osqueryd
/bin/systemctl enable osqueryd
EOF
chmod 755 "$_SOURCE_DIR/DEBIAN/postinst"

echo " [+] Building package $_OUTPUT_FILE"
dpkg-deb --build "$_SOURCE_DIR" "$_OUTPUT_FILE"

echo " [+] Done"