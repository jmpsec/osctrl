#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for database to initialize osctrl-admin
#
# Usage: wait.sh

NAME="osctrl-admin"
WAIT=3
CONFIG="config"
CERTS="certs"
DATA="data"
DB_JSON="$CONFIG/db.json"
CRT_FILE="$CERTS/osctrl.crt"
OSQUERY_JSON="$DATA/osquery-cfg.json"

# Check if database is ready, otherwise commands will fail
until $(./bin/osctrl-cli -D "$DB_JSON" check); do
  >&2 echo "Postgres is unavailable - Waiting..."
  sleep $WAIT
done
>&2 echo "Postgres is up - Starting $NAME"
sleep $WAIT

# Create environment dev
OUTPUT_ENV="$(./bin/osctrl-cli -D "$DB_JSON" environment add -n dev -host osctrl-nginx -crt "$CRT_FILE" -conf "$OSQUERY_JSON")"
if [ $? -eq 0 ]; then
  echo "Created environment dev"
else
  echo "Environment dev exists"
fi

# Generate flag and secret file for enrolling nodes
FLAGS_FILE="$CONFIG/docker.flags"
SECRET_FILE="$CONFIG/docker.secret"
# Generating flags and rewriting UUID as identifier for ephemeral, otherwise all the containers
# will have the same UUID and it will mess things up
./bin/osctrl-cli -D "$DB_JSON" environment flags -n dev -crt "/$CRT_FILE" -secret "/$SECRET_FILE" | sed 's/=uuid/=ephemeral/g' > "$FLAGS_FILE"
./bin/osctrl-cli -D "$DB_JSON" environment secret -n dev > "$SECRET_FILE"

# Create admin user
OUTPUT_ADMIN="$(./bin/osctrl-cli -D "$DB_JSON" user add -u admin -p admin -a -n Admin)"
if [ $? -eq 0 ]; then
  echo "Created admin user"
else
  echo "Admin user exists"
fi

# Run service
./bin/$NAME
