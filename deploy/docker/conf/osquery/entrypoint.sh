#!/bin/bash

ENV_NAME="${ENV_NAME:=dev}"
HOST="${HOST:=nginx}"

if [ ! -f "/etc/osquery/osquery.secret" ]; then
    ######################################### Wait until DB is up #########################################
    until /opt/osctrl/bin/osctrl-cli check
    do
        echo "DB is not ready"
        sleep 3
    done

    ######################################### Osquery config #########################################
    # Wait until for env to exist
    until /opt/osctrl/bin/osctrl-cli env show --name "${ENV_NAME}"
    do
        echo "${ENV_NAME} does not exist"
        sleep 3
    done

    # Get enroll secret
    /opt/osctrl/bin/osctrl-cli env secret --name "${ENV_NAME}" > /etc/osquery/osquery.secret

    # Get server cert
    echo "" | openssl s_client -connect ${HOST}:443 2>/dev/null | sed -n -e '/BEGIN\ CERTIFICATE/,/END\ CERTIFICATE/ p' > /etc/osquery/osctrl.crt

    # Get and set Osquery flags
    /opt/osctrl/bin/osctrl-cli env show-flags --name "${ENV_NAME}" > /etc/osquery/osquery.flags
    sed -i "s#__SECRET_FILE__#/etc/osquery/osquery.secret#g" /etc/osquery/osquery.flags
    echo "--tls_server_certs=/etc/osquery/osctrl.crt" >> /etc/osquery/osquery.flags
fi

# Run Osquery
/opt/osquery/bin/osqueryd --flagfile=/etc/osquery/osquery.flags --verbose
