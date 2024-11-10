#!/bin/bash

set -e

OSCTRL_USER="${VARIABLE:-osctrl}"
OSCTRL_GROUP="${VARIABLE:-osctrl}"
WORKING_DIR="${VARIABLE:-/etc/osctrl}"
OSQUERY_VESION="${VARIABLE:-5.14.1}"
OSCTRL_VERSION="${VARIABLE:-0.0.0}"

###################################### Init DEB contents ######################################
DEB_DIR=".debpkg-osctrl-${OSCTRL_COMPONENT}-${COMMIT_SHA}-${GOOS}-${GOARCH}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/local/bin"
mkdir -p "${DEB_DIR}/usr/share/osctrl"
mkdir -p "${DEB_DIR}/etc/osctrl"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/usr/share/osctrl/osctrl-${OSCTRL_COMPONENT}"
mkdir -p "${DEB_DIR}/var/log/osctrl-${OSCTRL_COMPONENT}"


###################################### Pre/post init scripts ######################################
cp deploy/cicd/deb/pre-init.sh "${DEB_DIR}/DEBIAN/preinst" && \
    chmod 755 "${DEB_DIR}/DEBIAN/preinst" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/preinst"

cp deploy/cicd/deb/post-init.sh "${DEB_DIR}/DEBIAN/postinst" && \
    chmod 755 "${DEB_DIR}/DEBIAN/postinst" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/postinst"

###################################### deb-conffiles ######################################
# https://manpages.debian.org/testing/dpkg-dev/deb-conffiles.5.en.html
# https://askubuntu.com/questions/473354/how-to-mark-some-file-in-debian-package-as-config
cp deploy/cicd/deb/deb-conffiles "${DEB_DIR}/DEBIAN/conffiles" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/conffiles"


###################################### Example configs ######################################
mkdir -p "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}"

cp deploy/config/db.json "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/db.json.example" && \
    chmod 640 "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/db.json.example"

cp deploy/config/redis.json "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/redis.json.example" && \
    chmod 640 "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/redis.json.example"


###################################### General components content ######################################
mkdir -p "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}"

cp osctrl-${OSCTRL_COMPONENT}-${GOOS}-${GOARCH}.bin "${DEB_DIR}/usr/local/bin/osctrl-${OSCTRL_COMPONENT}" && \
    chmod 755 "${DEB_DIR}/usr/local/bin/osctrl-${OSCTRL_COMPONENT}"

cp deploy/config/service.json "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/service.json" && \
    chmod 640 "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/service.json"

cp deploy/config/service.json "${DEB_DIR}/usr/share/osctrl/osctrl-${OSCTRL_COMPONENT}/service.json.example" && \
    chmod 640 "${DEB_DIR}/usr/share/osctrl/osctrl-${OSCTRL_COMPONENT}/service.json.example"

###################################### Generate SystemD config ######################################
EXECSTART="/usr/local/bin/osctrl-${OSCTRL_COMPONENT} \\
    --config \\
    --config-file /etc/osctrl/osctrl-${OSCTRL_COMPONENT}/service.json \\
    --redis \\
    --redis-file /etc/osctrl/redis.json \\
    --db \\
    --db-file /etc/osctrl/db.json"

if [ "$OSCTRL_COMPONENT" == "admin" ]
then
    ADMIN_ARGS=" \\
    --jwt \\
    --jwt-file /etc/osctrl/osctrl-admin/jwt.json \\
    --carved /var/osctrl/carves \\
    --templates /usr/share/osctrl/tmpl_admin \\
    --static /usr/share/osctrl/static \\
    --osquery-tables /etc/osctrl/osctrl-admin/osquery-${OSQUERY_VESION}.json"
    EXECSTART+=${ADMIN_ARGS}
fi

if [ "$OSCTRL_COMPONENT" == "api" ]
then
    API_ARGS=" \\
    --jwt \\
    --jwt-file /etc/osctrl/osctrl-admin/jwt.json"
    EXECSTART+=${API_ARGS}
fi

cat > "${DEB_DIR}/etc/systemd/system/osctrl-${OSCTRL_COMPONENT}.service" << EOF
[Unit]
Description=osctrl-${OSCTRL_COMPONENT}
ConditionPathExists=${WORKING_DIR}/osctrl-${OSCTRL_COMPONENT}
After=network.target

[Service]
Type=simple
User=${OSCTRL_USER}
Group=${OSCTRL_GROUP}
Restart=on-failure
RestartSec=10

WorkingDirectory=${WORKING_DIR}/osctrl-${OSCTRL_COMPONENT}
ExecStart=${EXECSTART}

# make sure log directory exists and owned by syslog
PermissionsStartOnly=true
ExecStartPre=/bin/mkdir -p /var/log/osctrl-${OSCTRL_COMPONENT}
ExecStartPre=/bin/chown osctrl:osctrl /var/log/osctrl-${OSCTRL_COMPONENT}
ExecStartPre=/bin/chmod 755 /var/log/osctrl-${OSCTRL_COMPONENT}
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=osctrl-${OSCTRL_COMPONENT}

[Install]
WantedBy=multi-user.target
EOF

###################################### Generate contents of DEB ######################################
if [ "$OSCTRL_COMPONENT" == "admin" ]
then
    #### Copy configs ####
    cp deploy/config/jwt.json "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/jwt.json" && \
        chmod 640 "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/jwt.json"

    # Setup Osctrl-admin file carves
    mkdir -p "${DEB_DIR}/var/osctrl/carves"

    #### Copy Osctrl-admin web assets ####
    cp -r admin/templates "${DEB_DIR}/usr/share/osctrl/tmpl_admin"
    cp -r admin/static "${DEB_DIR}/usr/share/osctrl/static"

    # Copy osquery schema
    cp deploy/osquery/data/${OSQUERY_VESION}.json "${DEB_DIR}/etc/osctrl/osctrl-admin/osquery-${OSQUERY_VESION}.json"

    # Define conffiles
    echo "/etc/osctrl/osctrl-admin/jwt.json" >> "${DEB_DIR}/DEBIAN/conffiles"
    echo "/etc/osctrl/osctrl-admin/osquery-${OSQUERY_VESION}.json" >> "${DEB_DIR}/DEBIAN/conffiles"

fi

if [ "$OSCTRL_COMPONENT" == "api" ]
then
    #### Copy configs ####
    cp deploy/config/jwt.json "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/jwt.json" && \
        chmod 640 "${DEB_DIR}/etc/osctrl/osctrl-${OSCTRL_COMPONENT}/jwt.json"

    # Define conffiles
    echo "/etc/osctrl/osctrl-api/jwt.json" >> "${DEB_DIR}/DEBIAN/conffiles"
fi
