#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for osctrl to be ready and enroll a node
#
# Usage: wait.sh

NAME="osctrl-centos7"
WAIT=3

# Check if script to enroll
while [ ! -f config/docker.flags ] && [ ! -f config/docker.secret ];
do
  >&2 echo "osctrl is not ready - Waiting"
  sleep $WAIT
done
>&2 echo "osctrl is up - Enrolling $NAME"
sleep $WAIT

# Run osquery
/usr/bin/osqueryd --flagfile=config/docker.flags --verbose
