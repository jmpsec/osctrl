#!/usr/bin/env bash
#
# Script to unpack the official DEB package for osquery and build a new one ready to enroll in osctrl
#
# Usage: ./build-osctrl-deb.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...

# How does it work?
function usage() {
  echo "Usage: $0 [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ..."
  echo
  echo "Options:"
  echo "  -h          Show this help message and exit"
  echo "  -c CERT     Path to the osquery certificate file"
  echo "  -s SECRET   Path to the osquery secret file (default: osquery.secret)"
  echo "  -f FLAGS    Path to the osquery flags file (default: osquery.flags)"
  echo "  -i DEB      Path to the osquery DEB file. Required."
  echo "  -o DEB      Path to the osctrl DEB file. Required."
  echo "  -x          Clear the temporary directory after the process"
  echo "  -v          Enable verbose mode with 'set -x'"
  echo
  echo "Example:"
  echo "  $0 -i osquery_5.14.1-1.linux.amd64.deb -o osquery-osctrl_5.14.1-1_amd64.deb"
}

# Stop script on error
set -e

# If the script is not running in Linux, use gtar instead of tar
TAR="tar"
if [[ "$(uname)" == "Darwin" ]]; then
  TAR="gtar"
fi

# Check if tar/gtar is installed
if ! command -v $TAR &> /dev/null
then
    echo "[!] $TAR could not be found"
    exit 1
fi

# Default values
CERT=""
SECRET="osquery.secret"
FLAGS="osquery.flags"
OSCTRL_FLAGS="osquery.flags"
OSQUERY_DEB=""
OSCTRL_DEB=""
REMOVE_TMP_DIR="false"
VERBOSE_MODE="false"

# Parse command line arguments
while getopts "c:s:f:i:o:xh" opt; do
    case "$opt" in
    c)
      CERT=${OPTARG}
      ;;
    s)
      SECRET=${OPTARG}
      ;;
    f)
      FLAGS=${OPTARG}
      ;;
    i)
      OSQUERY_DEB=${OPTARG}
      ;;
    o)
      OSCTRL_DEB=${OPTARG}
      ;;
    x)
      REMOVE_TMP_DIR="true"
      ;;
    v)
      VERBOSE_MODE="true"
      ;;
    h | *)
      usage
      exit 1
      ;;
  esac
done

# Detect if the script is running as root
if [[ $EUID -ne 0 ]]; then
  echo "[!] This script should run as root to avoid permission issues with the DEB package."
  exit 1
fi

# If no osquery DEB file or no osctrl DEB file, show usage
if [[ -z "$OSQUERY_DEB" ]] || [[ ! -f "$OSQUERY_DEB" ]]; then
  echo "[!] Invalid input for osquery DEB file. Please provide a valid file."
  exit 1
fi

if [[ -z "$OSCTRL_DEB" ]]; then
  echo "[!] Output file for osctrl DEB can not be empty."
fi

echo "[+] Using osquery DEB file: ${OSQUERY_DEB}"
echo "[+] Generating osctrl DEB file: ${OSCTRL_DEB}"
if [[ ! -z "$CERT" ]]; then
  echo "[+] Using osquery certificate file: ${CERT}"
fi
echo "[+] Using osquery secret file: ${SECRET}"
echo "[+] Using osquery flags file: ${FLAGS}"

# Check if dpkg is installed
if ! command -v dpkg &> /dev/null
then
    echo "[!] dpkg could not be found"
    exit 1
fi

# Check if ar is installed
if ! command -v ar &> /dev/null
then
    echo "[!] ar could not be found"
    exit 1
fi

# If we want verbose, set -x to debug the script
if [[ "$VERBOSE_MODE" == "true" ]]; then
  set -x
fi

# Create a temporary directory to unpack the DEB file
TMP_DIR=$(date +'%Y%m%d-%H%M%S')
mkdir -p "$TMP_DIR"
echo "[+] Using temporary directory $TMP_DIR"

cp "$OSQUERY_DEB" "$TMP_DIR"

# Unpack the osquery DEB file
echo "[+] Unpacking osquery DEB file"
cwd=$(pwd)
cd "$TMP_DIR"
############## From here, we are in the temporary directory ##############
ar x "$OSQUERY_DEB"

# Extract the control.tar.gz file
echo "[+] Extracting control.tar.gz to control"
mkdir -p "control"
$TAR -xzf "control.tar.gz" -C "control"

# Extract the data.tar.gz file
echo "[+] Extracting data.tar.gz to data"
mkdir -p "data"
$TAR -xzf "data.tar.gz" -C "data"

# Get paths from the flags file for certificate and secret
echo "[+] Getting paths from the flags file"
CERTPATH=$(grep "tls_server_certs=" "$cwd/$FLAGS" | awk -F'=' '{print $2}')
SECRETPATH=$(grep "enroll_secret_path=" "$cwd/$FLAGS" | awk -F'=' '{print $2}')

# Copy the osctrl files to the data directory
echo "[+] Copying osctrl files to data directory"
if [[ ! -z "$CERT" ]] && [[ ! -z "$CERTPATH" ]]; then
  cp "$cwd/$CERT" "data$CERTPATH"
fi
cp "$cwd/$SECRET" "data$SECRETPATH"
cp "$cwd/$FLAGS" "data/etc/osquery/$OSCTRL_FLAGS"

# Append the new file MD5 hashes to the control file
echo "[+] Appending md5sums for osctrl files to control file"
if [[ ! -z "$CERT" ]]; then
  echo "$(printf "%s  %s\n" "$(md5sum "data$CERTPATH" | awk '{print $1}')" "$(echo $CERTPATH | sed 's/^.//')")" >> "control/md5sums"
fi
echo "$(printf "%s  %s\n" "$(md5sum "data$SECRETPATH" | awk '{print $1}')" "$(echo $SECRETPATH | sed 's/^.//')")" >> "control/md5sums"
echo "$(printf "%s  %s\n" "$(md5sum "data/etc/osquery/$OSCTRL_FLAGS" | awk '{print $1}')" "etc/osquery/$OSCTRL_FLAGS")" >> "control/md5sums"

# Remove old DEB signature, since it won't be valid anymore
echo "[+] Removing old DEB signature"
rm -f "_gpgorigin"

# Repack the control.tar.gz file
echo "[+] Repacking control.tar.gz"
$TAR -czf "control.tar.gz" -C "control" .

# Repack the data.tar.gz file
echo "[+] Repacking data.tar.gz"
$TAR -czf "data.tar.gz" -C "data" .

# Repack the DEB file
echo "[+] Repacking DEB file"
rm -f "$OSQUERY_DEB"
ar r "$OSCTRL_DEB" "debian-binary" "control.tar.gz" "data.tar.gz"

# Move the new DEB file to the original directory
cp "$OSCTRL_DEB" "$cwd"

# Clean up
cd "$cwd"
if [[ "$REMOVE_TMP_DIR" == "true" ]]; then
  echo "[+] Removing temporary directory"
  rm -rf "$TMP_DIR"
fi

echo "✅ Completed repacking osquery DEB file: $OSCTRL_DEB"
