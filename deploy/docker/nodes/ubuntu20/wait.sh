#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for osctrl to be ready and enroll a node
#
# Usage: wait.sh

NAME="osctrl-ubuntu20"
FLAGS_FILE="/config/docker.flags"
SECRET_FILE="/config/docker.secret"
WAIT=5

# Check if script to enroll
while [ ! -f "$FLAGS_FILE" ] && [ ! -f "$SECRET_FILE" ];
do
  >&2 echo "osctrl is not ready - Waiting"
  sleep $WAIT
done
>&2 echo "osctrl is up - Enrolling $NAME"

sleep $WAIT

# Run osquery
/opt/osquery/bin/osqueryd --flagfile="$FLAGS_FILE" --verbose
