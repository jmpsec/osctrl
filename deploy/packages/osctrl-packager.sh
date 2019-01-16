#!/bin/bash
#
# [ osctrl ]: Helper script to generate packages to enroll clients
#
# Usage: osctrl-packager.sh [-h|--help] [PARAMETER [ARGUMENT]] [PARAMETER [ARGUMENT]] ...
#
# Parameters:
#   -h, --help      Shows this help message and exit.

# Make sure we have the dependencies
sudo apt-get install ruby ruby-dev rubygems build-essential

# Install FPM
sudo gem install --no-ri --no-rdoc fpm

# Build deb package
fpm -s dir -t deb -n osctrl -a all -d osquery -v 0.0.1 \
  --deb-priority optional \
  --description "osctrl - Fast and efficient operative system management" \
  --config-files /etc/osquery/osquery.flags \
  --config-files /etc/osquery/osquery.secret \
  --config-files /etc/osquery/certs/osctrl.crt \
  --before-install preinst \
  --after-install postinst \
  osquery.flags=/etc/osquery/ \
  osquery.secret=/etc/osquery/ \
  osctrl.crt=/etc/osquery/certs/

# Build rpm package converting the deb
fpm -s deb -t rpm -n osctrl -v 0.0.1

# Prepare locations for OSX pkg
rm -Rf OSX && mkdir OSX
rm -Rf scripts && mkdir scripts

# Files for osquery
mkdir -p OSX/var/private/osquery/certs
cp osquery.secret OSX/var/private/osquery
cp osquery.flags OSX/var/private/osquery
cp osquery.crt OSX/var/private/osquery/certs

# Package scripts
cp preinstall scripts
cp postinstall scripts

# Build pkg package natively with pkgbuild
pkgbuild --root OSX \
  --scripts scripts \
  --identifier osctrl \
  --version 0.0.1 \
  osctrl.pkg