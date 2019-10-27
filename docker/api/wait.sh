#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for database to initialize osctrl-api
#
# Usage: wait.sh

NAME="osctrl-api"
WAIT=3
CONFIG="config"
DB_JSON="$CONFIG/db.json"

# Check if database is ready, otherwise commands will fail
until $(./bin/osctrl-cli -D "$DB_JSON" check); do
  >&2 echo "Postgres is unavailable - Waiting..."
  sleep $WAIT
done
>&2 echo "Postgres is up - Starting $NAME"
sleep $WAIT

# Run service
./bin/$NAME
