#!/bin/sh
#
# [ osctrl 🎛 ]: Script to wait for osctrl to be ready and enroll a node
#
# Usage: wait.sh

NAME="osctrl-ubuntu20"
FLAGS_FILE="/etc/osquery/osquery.flags"
SECRET_FILE="/etc/osquery/osquery.secret"
WAIT=5

until /opt/osctrl-cli/bin/osctrl-cli -D /opt/osctrl-cli/config/db.json check
do
  sleep 1
done

# Check if script to enroll
while [ ! -f "$FLAGS_FILE" ] && [ ! -f "$SECRET_FILE" ];
do
    /opt/osctrl-cli/bin/osctrl-cli -D /opt/osctrl-cli/config/db.json env secret --name dev > ${SECRET_FILE}
    /opt/osctrl-cli/bin/osctrl-cli -D /opt/osctrl-cli/config/db.json env show-flags --name=dev > ${FLAGS_FILE}
    sed -i "s#--enroll_secret_path=.*#--enroll_secret_path=${SECRET_FILE}#g" ${FLAGS_FILE}
    sed -i "s#--distributed_interval=.*#--distributed_interval=60#g" ${FLAGS_FILE}
    echo "--tls_server_certs=/etc/osquery/osctrl.crt" >> ${FLAGS_FILE}
    >&2 echo "osctrl is not ready - Waiting"
    sleep $WAIT
done
>&2 echo "osctrl is up - Enrolling $NAME"

sleep $WAIT

# Run osquery
/usr/bin/osqueryd --flagfile="$FLAGS_FILE" --verbose