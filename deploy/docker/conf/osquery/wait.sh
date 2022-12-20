#!/bin/sh
#
# Script to wait for osctrl to be ready and enroll a node
#
# Usage: wait.sh

FLAGS_FILE="/etc/osquery/osquery.flags"
SECRET_FILE="/etc/osquery/osquery.secret"
CERT_FILE="/etc/osquery/osctrl.crt"
DB_JSON="/opt/osctrl/config/db.json"
ENV_NAME="dev"
WAIT=5

# Wait until DB is up
until /opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" check
do
  sleep $WAIT
done

# Wait until osctrl environment is up
until /opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env show --name "$ENV_NAME"
do
  sleep $WAIT
done

# To enroll, check existance for flags and secret and they are not empty
while [ ! -f "$FLAGS_FILE" ] && [ ! -s "$FLAGS_FILE" ] && [ ! -f "$SECRET_FILE" ] && [ ! -s "$SECRET_FILE" ];
do
    /opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env secret --name "$ENV_NAME" > ${SECRET_FILE}
    /opt/osctrl/bin/osctrl-cli --db -D "$DB_JSON" env show-flags --name "$ENV_NAME" | sed 's/=uuid/=ephemeral/g' > ${FLAGS_FILE}
    sed -i "s#--enroll_secret_path=.*#--enroll_secret_path=${SECRET_FILE}#g" ${FLAGS_FILE}
    sed -i "s#--enroll_secret_path=.*#--enroll_secret_path=${SECRET_FILE}#g" ${FLAGS_FILE}
    sed -i "s#--distributed_interval=.*#--distributed_interval=60#g" ${FLAGS_FILE}
    sed -i "s#--tls_server_certs=.*#--tls_server_certs=${CERT_FILE}#g" ${FLAGS_FILE}
    >&2 echo "osctrl is not ready - Waiting"
    sleep $WAIT
done
>&2 echo "osctrl is up - Enrolling node in $ENV_NAME"

sleep $WAIT

# Run osquery
/opt/osquery/bin/osqueryd --flagfile="$FLAGS_FILE" --verbose
