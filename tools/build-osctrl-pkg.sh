#!/usr/bin/env bash
#
# Script to unpack the official PKG package for osquery and build a new one ready to enroll in osctrl
#
# Usage: ./build-osctrl-pkg.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...

# How does it work?
function usage() {
  echo "Usage: $0 [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ..."
  echo
  echo "Options:"
  echo "  -h          Show this help message and exit"
  echo "  -c CERT     Path to the osquery certificate file"
  echo "  -s SECRET   Path to the osquery secret file (default: osquery.secret)"
  echo "  -f FLAGS    Path to the osquery flags file (default: osquery.flags)"
  echo "  -i PKG      Path to the osquery PKG file. Required."
  echo "  -o PKG      Path to the osctrl PKG file. Required."
  echo "  -x          Clear the temporary directory after the process"
  echo "  -v          Enable verbose mode with 'set -x'"
  echo
  echo "Example:"
  echo "  $0 -i osquery_5.14.1.pkg -o osquery-osctrl_5.14.1.pkg"
}

# Stop script on error
set -e

# Default values
CERT=""
SECRET="osquery.secret"
FLAGS="osquery.flags"
OSCTRL_FLAGS="osquery.flags"
OSQUERY_PKG=""
OSCTRL_PKG=""
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
      OSQUERY_PKG=${OPTARG}
      ;;
    o)
      OSCTRL_PKG=${OPTARG}
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

# If no osquery PKG file or no osctrl PKG file, show usage
if [[ -z "$OSQUERY_PKG" ]] || [[ ! -f "$OSQUERY_PKG" ]]; then
  echo "[!] Invalid input for osquery PKG file. Please provide a valid file."
  exit 1
fi

if [[ -z "$OSCTRL_PKG" ]]; then
  echo "[!] Output file for osctrl PKG can not be empty."
fi

echo "[+] Using osquery PKG file: ${OSQUERY_PKG}"
echo "[+] Generating osctrl PKG file: ${OSCTRL_PKG}"
if [[ ! -z "$CERT" ]]; then
  echo "[+] Using osquery certificate file: ${CERT}"
fi
echo "[+] Using osquery secret file: ${SECRET}"
echo "[+] Using osquery flags file: ${FLAGS}"

# Check if pkgutil is installed
if ! command -v pkgutil &> /dev/null
then
    echo "[!] pkgutil could not be found"
    exit 1
fi

# Check if gzip is installed
if ! command -v gzip &> /dev/null
then
    echo "[!] gzip could not be found"
    exit 1
fi

# Check if cpio is installed
if ! command -v cpio &> /dev/null
then
    echo "[!] cpio could not be found"
    exit 1
fi

# Check if mkbom is installed
if ! command -v mkbom &> /dev/null
then
    echo "[!] mkbom could not be found"
    exit 1
fi

# If we want verbose, set -x to debug the script
if [[ "$VERBOSE_MODE" == "true" ]]; then
  set -x
fi

# Create a temporary directory to unpack the DEB file
TMP_DIR=$(date +'%Y%m%d-%H%M%S')
echo "[+] Using temporary directory $TMP_DIR"

# Extract the osquery PKG file
echo "[+] Extracting osquery PKG file"
pkgutil --expand-full "$OSQUERY_PKG" "$TMP_DIR"

cwd=$(pwd)
cd "$TMP_DIR"
############## From here, we are in the temporary directory ##############

# Get paths from the flags file for certificate and secret
echo "[+] Getting paths from the flags file"
CERTPATH=$(grep "tls_server_certs=" "$cwd/$FLAGS" | awk -F'=' '{print $2}')
SECRETPATH=$(grep "enroll_secret_path=" "$cwd/$FLAGS" | awk -F'=' '{print $2}')

# Extract number of files and size in KB from PackageInfo
echo "[+] Extracting number of files and size from PackageInfo"
NOF=$(cat PackageInfo | grep payload | awk -F'"' '{print $2}')
SIZEKB=$(cat PackageInfo | grep payload | awk -F'"' '{print $4}')
IDENTIFIER=$(cat PackageInfo | grep identifier | awk -F'"' '{print $6}')
VERSION=$(cat PackageInfo | grep 'version=' | awk -F'"' '{print $10}')

counter_file=0
counter_size=0
# Copy the osctrl files to the data directory
echo "[+] Copying osctrl files to Payload directory"
if [[ ! -z "$CERT" ]] && [[ ! -z "$CERTPATH" ]]; then
  cp "$cwd/$CERT" "Payload$CERTPATH"
  counter_file=$((counter_file+1))
  counter_size=$((counter_size+$(du -k "$cwd/$CERT" | cut -f1)))
fi
cp "$cwd/$SECRET" "Payload$SECRETPATH"
counter_file=$((counter_file+1))
counter_size=$((counter_size+$(du -k "$cwd/$SECRET" | cut -f1)))
cp "$cwd/$FLAGS" "Payload/private/var/osquery/$OSCTRL_FLAGS"
counter_file=$((counter_file+1))
counter_size=$((counter_size+$(du -k "$cwd/$FLAGS" | cut -f1)))

# Update the PackageInfo file
echo "[+] Updating PackageInfo file"
sed -i '' "s/$NOF/$((NOF+counter_file))/g" PackageInfo
sed -i '' "s/$SIZEKB/$((SIZEKB+counter_size))/g" PackageInfo

# Update the BOM file
echo "[+] Updating BOM file"
mkbom "Payload/" Bom

# Recompress the Payload directory
echo "[+] Recompressing Payload directory"
find Payload/ | cpio -o --format odc | gzip -c > Payload.gz

# Replace the Payload directory with the new one
echo "[+] Replacing the Payload directory"
rm -rf Payload
mv Payload.gz Payload

# Create the new PKG file
echo "[+] Creating the new PKG file"
#pkgutil --flatten . "$OSCTRL_PKG"
pkgbuild --root . \
        --identifier "$IDENTIFIER" \
        --version "$VERSION" \
        --install-location "/" \
        "$OSCTRL_PKG"

# Move the new PKG file to the original directory
cp "$OSCTRL_PKG" "$cwd"

# Clean up
cd "$cwd"
if [[ "$REMOVE_TMP_DIR" == "true" ]]; then
  echo "[+] Removing temporary directory"
  rm -rf "$TMP_DIR"
fi

echo "✅ Completed repacking osquery PKG file: $OSCTRL_PKG"
