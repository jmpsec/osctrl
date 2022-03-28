#!/bin/bash

ENV_NAME="${ENV_NAME:=dev}"
DB_JSON="${DB_JSON:=/opt/osctrl/config/db.json}"
HOST="${HOST:=osctrl-nginx}"


if [ ! -f "/etc/osquery/osquery.secret" ]; then
    ######################################### Set DB config #########################################
    echo "[*] - Setting DB config"
    sed -i "s/{{ DB_HOST }}/${DB_HOST}/g" /opt/osctrl/config/db.json
    sed -i "s/{{ DB_PORT }}/${DB_PORT}/g" /opt/osctrl/config/db.json
    sed -i "s/{{ DB_USER }}/${DB_USER}/g" /opt/osctrl/config/db.json
    sed -i "s/{{ DB_PASS }}/${DB_PASS}/g" /opt/osctrl/config/db.json
    sed -i "s/{{ DB_NAME }}/${DB_NAME}/g" /opt/osctrl/config/db.json
    echo "[+] - Set DB config"

    ######################################### Wait until DB is up #########################################
    until /opt/osctrl/bin/osctrl-cli -D "${DB_JSON}" check
    do
        echo "DB is not ready"
        sleep 3
    done

    ######################################### Osquery config #########################################
    # Wait until for env to exist
    until /opt/osctrl/bin/osctrl-cli -D "${DB_JSON}" env show --name "${ENV_NAME}"
    do
        echo "${ENV_NAME} does not exist"
        sleep 3
    done

    # Get enroll secret
    /opt/osctrl/bin/osctrl-cli -D "${DB_JSON}" env secret --name "${ENV_NAME}" > /etc/osquery/osquery.secret

    # Get server cert
    echo "" | openssl s_client -connect ${HOST}:443 2>/dev/null | sed -n -e '/BEGIN\ CERTIFICATE/,/END\ CERTIFICATE/ p' > /etc/osquery/osctrl.crt

    # Get and set Osquery flags
    /opt/osctrl/bin/osctrl-cli -D "${DB_JSON}" env show-flags --name "${ENV_NAME}" > /etc/osquery/osquery.flags
    sed -i "s#__SECRET_FILE__#/etc/osquery/osquery.secret#g" /etc/osquery/osquery.flags
    echo "--tls_server_certs=/etc/osquery/osctrl.crt" >> /etc/osquery/osquery.flags
fi

# Run Osquery
/opt/osquery/bin/osqueryd --flagfile=/etc/osquery/osquery.flags --verbose