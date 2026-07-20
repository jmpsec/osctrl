#!/bin/bash

ENV_NAME="${ENV_NAME:=dev}"
CERT_FILE="${CERT_FILE:=/opt/osctrl/config/osctrl.crt}"
HOST="${HOST:=nginx}"
OSCTRL_USER="${OSCTRL_USER:=admin}"
OSCTRL_PASS="${OSCTRL_PASS:=admin}"
LOGGING_INTERVAL="${LOGGING_INTERVAL:=90}"
CONFIG_INTERVAL="${CONFIG_INTERVAL:=60}"
QUERY_INTERVAL="${QUERY_INTERVAL:=30}"
POSTURE_PROFILE="${POSTURE_PROFILE:=linux-server}"
POSTURE_INTERVAL="${POSTURE_INTERVAL:=75}"
POSTURE_QUERY_PREFIX="${POSTURE_QUERY_PREFIX:=osctrl:posture:}"
WAIT="${WAIT:=5}"

######################################### OSCTRL_PASS ##############################################
if [[ -n "$OSCTRL_PASS_FILE" ]]; then
  OSCTRL_PASS=$(cat ${OSCTRL_PASS_FILE})
fi

######################################### Wait until DB is up ######################################
until /opt/osctrl/bin/osctrl-cli check-db
do
  echo "DB is not ready"
  sleep $WAIT
done

######################################### Create environment #######################################
/opt/osctrl/bin/osctrl-cli --db env add \
  --name "${ENV_NAME}" \
  --hostname "${HOST}" \
  --certificate "${CERT_FILE}"
if [ $? -eq 0 ]; then
  echo "Created environment ${ENV_NAME}"
else
  echo "Environment ${ENV_NAME} exists"
fi

######################################### Adjust intervals #########################################

/opt/osctrl/bin/osctrl-cli --db env update \
  --name "${ENV_NAME}" \
  --logging "${LOGGING_INTERVAL}" \
  --config "${CONFIG_INTERVAL}" \
  --query "${QUERY_INTERVAL}"
if [ $? -eq 0 ]; then
  echo "Adjusted intervals for ${ENV_NAME}"
else
  echo "Something happened with the intervals for ${ENV_NAME}"
fi

######################################### Add scheduled query ######################################

/opt/osctrl/bin/osctrl-cli --db env add-scheduled-query \
  --name "${ENV_NAME}" \
  --query-name "uptime" \
  --query "SELECT * FROM uptime;" \
  --interval "60"
if [ $? -eq 0 ]; then
  echo "Added query to schedule in ${ENV_NAME}"
else
  echo "Something happened adding query to schedule in ${ENV_NAME}"
fi

######################################### Add posture checks #######################################

/opt/osctrl/bin/osctrl-cli --db env add-posture-queries \
  --name "${ENV_NAME}" \
  --profile "${POSTURE_PROFILE}" \
  --interval "${POSTURE_INTERVAL}" \
  --prefix "${POSTURE_QUERY_PREFIX}"
if [ $? -eq 0 ]; then
  echo "Added posture profile ${POSTURE_PROFILE} to schedule in ${ENV_NAME}"
else
  echo "Something happened adding posture profile ${POSTURE_PROFILE} to schedule in ${ENV_NAME}"
fi

######################################### Create admin user ########################################
/opt/osctrl/bin/osctrl-cli --db user add \
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

echo "
##############################################################################
#                Successfully created an osctrl user and env
#
# osctrl admin user: ${OSCTRL_USER}
# osctrl env name: ${ENV_NAME}
##############################################################################
"

# Start a shell to avoid re-running this script
/bin/bash
