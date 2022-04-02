#!/bin/bash

ENV_NAME="${ENV_NAME:=dev}"
CERT_FILE="${CERT_FILE:=/opt/osctrl/config/osctrl.crt}"
HOST="${HOST:=osctrl-nginx}"
OSCTRL_USER="${OSCTRL_USER:=admin}"
OSCTRL_PASS="${OSCTRL_PASS:=admin}"
WAIT="${WAIT:=5}"

######################################### Wait until DB is up #########################################
until /opt/osctrl/bin/osctrl-cli check
do
  echo "DB is not ready"
  sleep $WAIT
done

######################################### Create environment #########################################
/opt/osctrl/bin/osctrl-cli env add \
  --name "${ENV_NAME}" \
  --hostname "${HOST}" \
  --certificate "${CRT_FILE}"
if [ $? -eq 0 ]; then
  echo "Created environment dev"
else
  echo "Environment dev exists"
fi

######################################### Create admin user #########################################
/opt/osctrl/bin/osctrl-cli user add \
  --admin \
  --username "${OSCTRL_USER}" \
  --password "${OSCTRL_PASS}" \
  --environment "${ENV_NAME}" \
  --fullname "${OSCTRL_USER}"

if [ $? -eq 0 ]; then
  echo "Created ${OSCTRL_USER} user"
else
  echo "The user ${OSCTRL_USER} exists"
fi

echo "The environment ${ENV_NAME} is ready"

# Start a shell to avoid re-running this script
/bin/sh