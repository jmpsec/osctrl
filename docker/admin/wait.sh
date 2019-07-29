#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for database to initialize osctrl-admin
#
# Usage: wait.sh

NAME="osctrl-admin"
WAIT=3
CONFIG="config"
DB_JSON="$CONFIG/db.json"
CRT_FILE="$CONFIG/osctrl.crt"
OSQUERY_JSON="$CONFIG/osquery-dev.json"

# Check if database is ready, otherwise commands will fail
until $(./bin/osctrl-cli -D "$DB_JSON" check); do
  >&2 echo "Postgres is unavailable - Waiting..."
  sleep $WAIT
done
>&2 echo "Postgres is up - Starting $NAME"
sleep $WAIT

# Create environment dev
OUTPUT_ENV="$(./bin/osctrl-cli -D "$DB_JSON" environment add -n dev -host localhost -crt "$CRT_FILE" -conf "$OSQUERY_JSON")"
if [ $? -eq 0 ]; then
  echo "Created environment dev"
else
  echo "Environment dev exists"
fi

echo $OUTPUT_ENV

# Create admin user
OUTPUT_ADMIN="$(./bin/osctrl-cli -D "$DB_JSON" user add -u admin -p admin -a -n Admin)"
if [ $? -eq 0 ]; then
  echo "Created admin user"
else
  echo "Admin user exists"
fi

echo $OUTPUT_ADMIN

# Run service
./bin/osctrl-admin
