#!/bin/sh
#
# Script to wait for osctrl to be ready and enroll a node
#
# Usage: wait.sh

ENV_NAME="${ENV_NAME:=dev}"
CERT_FILE="${CERT_FILE:=/opt/osctrl/config/osctrl.crt}"
DB_JSON="${DB_JSON:=/opt/osctrl/config/db.json}"
_HOST="${_HOST:=osctrl-nginx}"
_USER="${_USER:=admin}"
WAIT=${WAIT:=5}

# Wait until DB is up
until /opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" check
do
  echo "DB is not ready"
  sleep $WAIT
done

# Create environment dev
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env add -name "$ENV_NAME" -host "$_HOST" -crt "$CRT_FILE"
if [ $? -eq 0 ]; then
  echo "Created environment dev"
else
  echo "Environment dev exists"
fi

# Decrease intervals in dev
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env update -n "$ENV_NAME" -l 75 -c 45 -q 60

# Enable verbose mode
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env add-osquery-option -n dev -o "verbose" -t bool -b true
# Disable splay for schedule
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env add-osquery-option -n dev -o "schedule_splay_percent" -t int -i 0
# Add uptime query to schedule
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env add-scheduled-query -n dev -q "SELECT * FROM uptime;" -Q "uptime" -i 60

# Create admin user
/opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" user add -u "$_USER" -p "$_USER" -a -E "$ENV_NAME" -n "$_USER"
if [ $? -eq 0 ]; then
  echo "Created $_USER user"
else
  echo "The user $_USER exists"
fi

echo "The environment $ENV_NAME is ready"

# Start a shell to avoid re-running this script
/bin/bash
