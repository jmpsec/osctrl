#!/bin/sh
#
# {{ .Project }} - Tool to quick-add OSX/Linux nodes
#
# IMPORTANT! If osquery is not installed, it will be installed.

_PROJECT="{{ .Project }}"
_SECRET="{{ .Environment.Secret }}"

_SECRET_LINUX=/etc/osquery/${_PROJECT}.secret
_FLAGS_LINUX=/etc/osquery/osquery.flags
_CERT_LINUX=/etc/osquery/certs/${_PROJECT}.crt

_SECRET_OSX=/private/var/osquery/${_PROJECT}.secret
_FLAGS_OSX=/private/var/osquery/osquery.flags
_CERT_OSX=/private/var/osquery/certs/${_PROJECT}.crt
_PLIST_OSX=/Library/LaunchDaemons/com.facebook.osqueryd.plist
_OSQUERY_PLIST=/private/var/osquery/com.facebook.osqueryd.plist

_SECRET_FREEBSD=/usr/local/etc/${_PROJECT}.secret
_FLAGS_FREEBSD=/usr/local/etc/osquery.flags
_CERT_FREEBSD=/usr/local/etc/certs/${_PROJECT}.crt

_DEB_ARCH=`dpkg-architecture -q DEB_BUILD_ARCH`

_OSQUERY_PKG="https://osquery-packages.s3.amazonaws.com/darwin/osquery-4.7.0.pkg"
_OSQUERY_DEB="https://osquery-packages.s3.amazonaws.com/deb/osquery_4.7.0-1.linux_$_DEB_ARCH.deb"
_OSQUERY_RPM="https://osquery-packages.s3.amazonaws.com/rpm/osquery-4.7.0-1.linux.x86_64.rpm"

_OSQUERY_SERVICE_LINUX="osqueryd"
_OSQUERY_SERVICE_OSX="com.facebook.osqueryd"
_OSQUERY_SERVICE_FREEBSD="osqueryd"

_SECRET_FILE=""
_FLAGS=""
_CERT=""
_SERVICE=""

fail() {
  echo "[!] $1"
  exit 1
}

log() {
  echo "[+] $1"
}

installOsquery() {
  log "Installing osquery for $OS"
  if [ "$OS" = "linux" ]; then
    log "Installing osquery in Linux"
    distro=$(/usr/bin/rpm -q -f /usr/bin/rpm >/dev/null 2>&1)
    if [ "$?" = "0" ]; then
      log "RPM based system detected"
      _RPM="$(echo $_OSQUERY_RPM | cut -d"/" -f5)"
      sudo curl -# "$_OSQUERY_RPM" -o "/tmp/$_RPM"
      sudo rpm -ivh "/tmp/$_RPM"
    else
      log "DEB based system detected"
      _DEB="$(echo $_OSQUERY_DEB | cut -d"/" -f5)"
      sudo curl -# "$_OSQUERY_DEB" -o "/tmp/$_DEB"
      sudo dpkg -i "/tmp/$_DEB"
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Installing osquery in OSX"
    _PKG="$(echo $_OSQUERY_PKG | cut -d"/" -f5)"
    sudo curl -# "$_OSQUERY_PKG" -o "/tmp/$_PKG"
    sudo installer -pkg "/tmp/$_PKG" -target /
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Installing osquery in FreeBSD"
    sudo ASSUME_ALWAYS_YES=YES pkg install osquery
  fi
}

verifyOsquery() {
  osqueryi=$(which osqueryi)
  if [ "$?" = "1" ]; then
    #read -p "[+] $_PROJECT needs osquery. Do you want to install it? [y/n]" yn
    #case $yn in
    #  [Yy]* ) installOsquery;;
    #  [Nn]* ) exit 1;;
    #  * ) exit 1;;
    #esac
    log "[+] $_PROJECT needs osquery"
    installOsquery
  else
    osqueryi -version
  fi
}

whatOS() {
  OS=$(echo `uname`|tr '[:upper:]' '[:lower:]')
  log "OS=$OS"
  if [ "$OS" = "linux" ]; then
    _SECRET_FILE="$_SECRET_LINUX"
    _FLAGS="$_FLAGS_LINUX"
    _CERT="$_CERT_LINUX"
    _SERVICE="$_OSQUERY_SERVICE_LINUX"
  fi
  if [ "$OS" = "darwin" ]; then
    _SECRET_FILE="$_SECRET_OSX"
    _FLAGS="$_FLAGS_OSX"
    _CERT="$_CERT_OSX"
    _SERVICE="$_OSQUERY_SERVICE_OSX"
  fi
  if [ "$OS" = "freebsd" ]; then
    _SECRET_FILE="$_SECRET_FREEBSD"
    _FLAGS="$_FLAGS_FREEBSD"
    _CERT="$_CERT_FREEBSD"
    _SERVICE="$_OSQUERY_SERVICE_FREEBSD"
  fi
  log "_SECRET_FILE=$_SECRET_FILE"
  log "_FLAGS=$_FLAGS"
  log "_CERT=$_CERT"
  log "IMPORTANT! If osquery is not installed, it will be installed."
}

stopOsquery() {
  if [ "$OS" = "linux" ]; then
    log "Stopping $_OSQUERY_SERVICE_LINUX"
    if which systemctl >/dev/null; then
      sudo systemctl stop "$_OSQUERY_SERVICE_LINUX"
    elif which service >/dev/null; then
      sudo service "$_OSQUERY_SERVICE_LINUX" stop
    else
      sudo /etc/init.d/"$_OSQUERY_SERVICE_LINUX" stop
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Stopping $_OSQUERY_SERVICE_OSX"
    if launchctl list | grep -qcm1 "$_OSQUERY_SERVICE_OSX"; then
      sudo launchctl unload "$_PLIST_OSX"
    fi
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Stopping $_OSQUERY_SERVICE_FREEBSD"
    if [ "$(service osqueryd onestatus)" = "osqueryd is running." ]; then
      sudo service "$_OSQUERY_SERVICE_FREEBSD" onestop
    fi
  fi
}

prepareSecret() {
  log "Preparing osquery secret"
  echo "$_SECRET" | sudo tee "$_SECRET_FILE"
  sudo chmod 700 "$_SECRET_FILE"
}

prepareFlags() {
  log "Preparing osquery flags"
  sudo sh -c "cat <<EOF | sed -e 's@__SECRET_FILE__@$_SECRET_FILE@g' | sed 's@__CERT_FILE__@$_CERT@g' > $_FLAGS
{{ .Environment.Flags }}
EOF"
}

prepareCert() {
  log "Preparing osquery certificate"
  sudo mkdir -p $(dirname "$_CERT")
  sudo sh -c "cat <<EOF > $_CERT
{{ .Environment.Certificate }}
EOF"
}

startOsquery() {
  if [ "$OS" = "linux" ]; then
    log "Starting $_OSQUERY_SERVICE_LINUX"
    if which systemctl >/dev/null; then
      sudo systemctl start "$_OSQUERY_SERVICE_LINUX"
      sudo systemctl enable "$_OSQUERY_SERVICE_LINUX"
    else
      sudo /etc/init.d/"$_OSQUERY_SERVICE_LINUX" start
      sudo update-rc.d "$_OSQUERY_SERVICE_LINUX" defaults
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Starting $_OSQUERY_SERVICE_OSX"
    sudo cp "$_OSQUERY_PLIST" "$_PLIST_OSX"
    sudo launchctl load "$_PLIST_OSX"
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Starting $_OSQUERY_SERVICE_FREEBSD"
    echo 'osqueryd_enable="YES"' | sudo tee -a /etc/rc.conf
    sudo service "$_OSQUERY_SERVICE_FREEBSD" start
  fi
}

bye() {
  result=$?
  if [ "$result" != "0" ]; then
    echo "[!] Fail to enroll $_PROJECT node"
  fi
  exit $result
}

trap "bye" EXIT
whatOS
verifyOsquery
set -e
stopOsquery
prepareSecret
prepareFlags
prepareCert
startOsquery

log "Congratulations! The node has been enrolled in $_PROJECT"
log "REMINDER! $_SERVICE has been started and enabled."

# EOF
