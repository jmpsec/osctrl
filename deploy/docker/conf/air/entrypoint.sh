#!/bin/bash

if [ "$OSCTRL_COMPONENT" == "admin" ]
then
    mkdir /app/data
    ln -s /app/deploy/osquery/data/${OSQUERY_VERSION}.json /app/data/${OSQUERY_VERSION}.json
    ln -s /app/admin/templates /app/tmpl_admin
    ln -s /app/admin/static /app/static
fi

cp deploy/docker/conf/air/.air-osctrl-${OSCTRL_COMPONENT}.toml /app/.air.toml
echo '[+] copied deploy/docker/.air-osctrl-${OSCTRL_COMPONENT}.toml to /app/.air.toml'

echo "[*] - Starting air on osctrl-${OSCTRL_COMPONENT}"
cd /app
air