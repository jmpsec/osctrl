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
  echo "  -n NAME     Name to use for the package (default: osctrl)"
  echo "  -V VERSION  Version to use for the package (default: 1.0)"
  echo "  -c CERT     Path to the osquery certificate file"
  echo "  -s SECRET   Path to the osquery secret file (default: osquery.secret)"
  echo "  -f FLAGS    Path to the osquery flags file (default: osquery.flags)"
  echo "  -i PKG      Path to the osquery PKG file. Required."
  echo "  -o PKG      Path to the osctrl PKG file. Required."
  echo "  -k          Generate a PKG without osquery. Only osctrl files."
  echo "  -x          Clear the temporary directory after the process"
  echo "  -v          Enable verbose mode with 'set -x'"
  echo
  echo "Example:"
  echo "  $0 -i osquery_5.17.0.pkg -o osquery-osctrl_5.17.0.pkg"
}

# Stop script on error
set -e

# Default values
CERT=""
SECRET="osquery.secret"
FLAGS="osquery.flags"
OSCTRL_FLAGS="osquery.flags"
NAME="osctrl"
VERSION="1.0"
OSQUERY_PKG=""
OSCTRL_PKG=""
REMOVE_TMP_DIR="false"
VERBOSE_MODE="false"
OSCTRL_ONLY="false"

# Parse command line arguments
while getopts "c:s:f:i:o:kxhv" opt; do
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
    k)
      OSCTRL_ONLY="true"
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
if [[ "$OSCTRL_ONLY" == "false" ]]; then
  if [[ -z "$OSQUERY_PKG" ]] || [[ ! -f "$OSQUERY_PKG" ]]; then
    echo "[!] Invalid input for osquery PKG file. Please provide a valid file."
    exit 1
  fi
fi
if [[ -z "$OSCTRL_PKG" ]]; then
  echo "[!] Output file for osctrl PKG can not be empty."
  exit 1
fi

echo "[+] Generating osctrl PKG file: ${OSCTRL_PKG}"
if [[ ! -z "$CERT" ]]; then
  echo "[+] Using osquery certificate file: ${CERT}"
fi

# Check if secret and flags files exist
if [[ ! -f "$SECRET" ]]; then
  echo "[!] Invalid input for osquery secret file. Please provide a valid file."
  exit 1
fi
if [[ ! -f "$FLAGS" ]]; then
  echo "[!] Invalid input for osquery flags file. Please provide a valid file."
  exit 1
fi
echo "[+] Using osquery secret file: ${SECRET}"
echo "[+] Using osquery flags file: ${FLAGS}"

# If we want verbose, set -x to debug the script
if [[ "$VERBOSE_MODE" == "true" ]]; then
  set -x
fi

# Check if pkgutil is installed
if ! command -v pkgutil &> /dev/null
then
    echo "[!] pkgutil could not be found"
    exit 1
fi

# Create a temporary directory to unpack the DEB file
TMP_DIR=$(date +'%Y%m%d-%H%M%S')
echo "[+] Using temporary directory $TMP_DIR"

# Do we want to generate a PKG without osquery?
if [[ "$OSCTRL_ONLY" == "true" ]]; then
  # Files for osquery
  mkdir -p "$TMP_DIR/private/var/osquery"
  cp "$SECRET" "$TMP_DIR/private/var/osquery"
  cp "$FLAGS" "$TMP_DIR/private/var/osquery"

  # Package scripts
  mkdir -p "$TMP_DIR-scripts"
  cat <<EOF >"$TMP_DIR-scripts/preinstall"
#!/usr/bin/env bash

if launchctl list | grep -qcm1 io.osquery.agent; then
  sudo launchctl unload /Library/LaunchDaemons/io.osquery.agent.plist
fi

exit 0
EOF
  cat <<EOF >"$TMP_DIR-scripts/postinstall"
#!/usr/bin/env bash

sudo cp /private/var/osquery/io.osquery.agent.plist /Library/LaunchDaemons/io.osquery.agent.plist
sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist

exit 0
EOF

  # Prepare identifier string
  _IDENTIFIER="$NAME-$VERSION"

  # Build pkg package natively with pkgbuild
  pkgbuild --root "$TMP_DIR" \
    --scripts "$TMP_DIR-scripts" \
    --identifier "$_IDENTIFIER" \
    --version "$VERSION" \
    "$OSCTRL_PKG"

  echo "✅ Completed creating $_IDENTIFIER PKG file: $OSCTRL_PKG"
else
  # Get the current working directory
  cwd=$(pwd)
  echo "[+] Using osquery PKG file: ${OSQUERY_PKG}"

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
  # Extract the osquery PKG file
  echo "[+] Extracting osquery PKG file"
  pkgutil --expand-full "$OSQUERY_PKG" "$TMP_DIR"

  cd "$TMP_DIR"
  ############## From here, we are in the temporary directory ##############

  # Get paths from the flags file for certificate and secret
  echo "[+] Getting paths from the flags file"
  _FLAGS=$FLAGS
  if [[ ! -f "$FLAGS" ]]; then
    _FLAGS="$cwd/$FLAGS"
  fi
  CERTPATH=$(grep "tls_server_certs=" "$_FLAGS" | awk -F'=' '{print $2}')
  SECRETPATH=$(grep "enroll_secret_path=" "$_FLAGS" | awk -F'=' '{print $2}')

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
    _CERT=$CERT
    if [[ ! -f "$CERT" ]]; then
      _CERT="$cwd/$CERT"
    fi
    cp "$_CERT" "Payload$CERTPATH"
    counter_file=$((counter_file+1))
    counter_size=$((counter_size+$(du -k "$_CERT" | cut -f1)))
  fi
  _SECRET=$SECRET
  if [[ ! -f "$SECRET" ]]; then
    _SECRET="$cwd/$SECRET"
  fi
  cp "$_SECRET" "Payload$SECRETPATH"
  counter_file=$((counter_file+1))
  counter_size=$((counter_size+$(du -k "$_SECRET" | cut -f1)))
  cp "$_FLAGS" "Payload/private/var/osquery/$OSCTRL_FLAGS"
  counter_file=$((counter_file+1))
  counter_size=$((counter_size+$(du -k "$_FLAGS" | cut -f1)))

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

  echo "✅ Completed repacking osquery PKG file: $OSCTRL_PKG"
fi

# Clean up
if [[ "$REMOVE_TMP_DIR" == "true" ]]; then
  echo "[+] Removing temporary directory"
  rm -rf "$TMP_DIR"
fi

exit 0
