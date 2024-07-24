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
  echo
  echo "Example:"
  echo "  $0 -i osquery_5.12.1-1.linux.amd64.deb -o osctrl_5.12.1-1_amd64.deb"
}

# Stop script on error
set -e

# Default values
CERT=""
OSCTRL_CERT="osctrl.crt"
SECRET="osquery.secret"
OSCTRL_SECRET="osctrl.secret"
FLAGS="osquery.flags"
OSCTRL_FLAGS="osquery.flags"
OSQUERY_DEB=""
OSCTRL_DEB=""

# Parse command line arguments
while getopts "c:s:f:i:o:h" opt; do
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
    h | *)
      usage
      exit 1
      ;;
  esac
done

# If no osquery DEB file or no osctrl DEB file, show usage
if [[ -z "$OSQUERY_DEB" ]] || [[ ! -f "$OSQUERY_DEB" ]]; then
  echo "[!] Invalid input for osquery DEB file. Please provide a valid file."
  exit 1
fi

if [[ -z "$OSCTRL_DEB" ]]; then
  echo "[!] Output file for osctrl DEB can not be empty."
fi

echo "[+] Using osquery DEB file: ${OSQUERY_DEB}"
echo "[+] Using osctrl DEB file: ${OSCTRL_DEB}"
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

# From here, set -x to debug the script
set -x

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
tar -xzf "control.tar.gz" -C "control"

# Extract the data.tar.gz file
echo "[+] Extracting data.tar.gz to data"
mkdir -p "data"
tar -xzf "data.tar.gz" -C "data"

# Copy the osctrl files to the data directory
echo "[+] Copying osctrl files to data directory"
if [[ ! -z "$CERT" ]]; then
  cp "$cwd/$CERT" "data/etc/osquery/$OSCTRL_CERT"
fi
cp "$cwd/$SECRET" "data/etc/osquery/$OSCTRL_SECRET"
cp "$cwd/$FLAGS" "data/etc/osquery/$OSCTRL_FLAGS"

# Append the new file MD5 hashes to the control file
echo "[+] Appending md5sums for osctrl files to control file"
if [[ ! -z "$CERT" ]]; then
  echo "etc/osquery/$OSCTRL_CERT $(md5sum "data/etc/osquery/$OSCTRL_CERT" | awk '{print $1}')" >> "control/md5sums"
fi
echo "etc/osquery/$OSCTRL_SECRET $(md5sum "data/etc/osquery/$OSCTRL_SECRET" | awk '{print $1}')" >> "control/md5sums"
echo "etc/osquery/$OSCTRL_FLAGS $(md5sum "data/etc/osquery/$OSCTRL_FLAGS" | awk '{print $1}')" >> "control/md5sums"

# Remove old DEB signature, since it won't be valid anymore
echo "[+] Removing old DEB signature"
rm -f "_gpgorigin"

# Repack the control.tar.gz file
echo "[+] Repacking control.tar.gz"
tar -czf "control.tar.gz" -C "control" .

# Repack the data.tar.gz file
echo "[+] Repacking data.tar.gz"
tar -czf "data.tar.gz" -C "data" .

# Repack the DEB file
echo "[+] Repacking DEB file"
rm -f "$OSQUERY_DEB"
ar r "$OSCTRL_DEB" "debian-binary" "control.tar.gz" "data.tar.gz"

# Move the new DEB file to the original directory
cp "$OSCTRL_DEB" "$cwd"

# Clean up the temporary directory
cd "$cwd"
rm -rf "$TMP_DIR"


echo "✅ Completed repacking osquery DEB file: $OSCTRL_DEB"
