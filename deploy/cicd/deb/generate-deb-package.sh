#!/bin/bash

set -e

OSCTRL_USER="${VARIABLE:-osctrl}"
OSCTRL_GROUP="${VARIABLE:-osctrl}"
WORKING_DIR="${VARIABLE:-/opt/osctrl}"
OSQUERY_VERSION="${VARIABLE:-5.20.0}"
OSCTRL_VERSION="${VARIABLE:-0.0.0}"

# Init DEB contents
DEB_DIR=".debpkg-osctrl-${OSCTRL_COMPONENT}-${COMMIT_SHA}-${GOOS}-${GOARCH}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/opt/osctrl"
mkdir -p "${DEB_DIR}/opt/osctrl/bin"
mkdir -p "${DEB_DIR}/opt/osctrl/config"
mkdir -p "${DEB_DIR}/var/log/osctrl-${OSCTRL_COMPONENT}"


# Pre/post install scripts
cp deploy/cicd/deb/pre-install.sh "${DEB_DIR}/DEBIAN/preinst" && \
    chmod 755 "${DEB_DIR}/DEBIAN/preinst" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/preinst"

cp deploy/cicd/deb/post-install.sh "${DEB_DIR}/DEBIAN/postinst" && \
    chmod 755 "${DEB_DIR}/DEBIAN/postinst" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/postinst"

# deb-conffiles
# https://manpages.debian.org/testing/dpkg-dev/deb-conffiles.5.en.html
# https://askubuntu.com/questions/473354/how-to-mark-some-file-in-debian-package-as-config
cp deploy/cicd/deb/deb-conffiles "${DEB_DIR}/DEBIAN/conffiles" && \
    sed -i "s#{{ OSCTRL_COMPONENT }}#${OSCTRL_COMPONENT}#g" "${DEB_DIR}/DEBIAN/conffiles"


# Example configs
cp deploy/config/db.json "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/db.json.example" && \
    chmod 640 "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/db.json.example"

cp deploy/config/redis.json "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/redis.json.example" && \
    chmod 640 "${DEB_DIR}/tmp/osctrl-${OSCTRL_COMPONENT}/redis.json.example"


# General components content
cp osctrl-${OSCTRL_COMPONENT}-${GOOS}-${GOARCH}.bin "${DEB_DIR}/opt/osctrl/bin/osctrl-${OSCTRL_COMPONENT}" && \
    chmod 755 "${DEB_DIR}/opt/osctrl/bin/osctrl-${OSCTRL_COMPONENT}"

cp deploy/config/service.json "${DEB_DIR}/opt/osctrl/config/${OSCTRL_COMPONENT}.json" && \
    chmod 640 "${DEB_DIR}/opt/osctrl/config/${OSCTRL_COMPONENT}.json"

# Generate systemd config file
EXECSTART="/opt/osctrl/bin/osctrl-${OSCTRL_COMPONENT} \\
    --config \\
    --config-file /opt/osctrl/config/${OSCTRL_COMPONENT}.json \\
    --redis \\
    --redis-file /opt/osctrl/config/redis.json \\
    --db \\
    --db-file /opt/osctrl/config/db.json"

if [ "$OSCTRL_COMPONENT" == "admin" ]
then
    ADMIN_ARGS=" \\
    --jwt \\
    --jwt-file /opt/osctrl/config/jwt.json \\
    --carved /opt/osctrl/carves \\
    --templates /opt/osctrl/tmpl_admin \\
    --static /opt/osctrl/static \\
    --osquery-tables /opt/osctrl/data/osquery-${OSQUERY_VERSION}.json"
    EXECSTART+=${ADMIN_ARGS}
fi

if [ "$OSCTRL_COMPONENT" == "api" ]
then
    API_ARGS=" \\
    --jwt \\
    --jwt-file /opt/osctrl/config/jwt.json"
    EXECSTART+=${API_ARGS}
fi

cat > "${DEB_DIR}/etc/systemd/system/osctrl-${OSCTRL_COMPONENT}.service" << EOF
[Unit]
Description=osctrl-${OSCTRL_COMPONENT}
ConditionPathExists=${WORKING_DIR}
After=network.target

[Service]
Type=simple
User=${OSCTRL_USER}
Group=${OSCTRL_GROUP}
Restart=on-failure
RestartSec=10

WorkingDirectory=${WORKING_DIR}
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

# Generate contents of DEB
if [ "$OSCTRL_COMPONENT" == "admin" ]
then
    # Create additional directories for osctrl-admin
    mkdir -p "${DEB_DIR}/opt/osctrl/data"
    mkdir -p "${DEB_DIR}/opt/osctrl/carves"
    mkdir -p "${DEB_DIR}/opt/osctrl/static"
    mkdir -p "${DEB_DIR}/opt/osctrl/tmpl_admin"

    # Copy configs
    cp deploy/config/jwt.json "${DEB_DIR}/opt/osctrl/config/jwt.json" && \
        chmod 640 "${DEB_DIR}/opt/osctrl/config/jwt.json"

    # Copy Osctrl-admin web assets
    cp -r cmd/admin/templates "${DEB_DIR}/opt/osctrl/tmpl_admin"
    cp -r cmd/admin/static "${DEB_DIR}/opt/osctrl/static"

    # Copy osquery schema
    cp deploy/osquery/data/${OSQUERY_VERSION}.json "${DEB_DIR}/opt/osctrl/data/osquery-${OSQUERY_VERSION}.json"

    # Define conffiles
    echo "/opt/osctrl/config/jwt.json" >> "${DEB_DIR}/DEBIAN/conffiles"
    echo "/opt/osctrl/data/osquery-${OSQUERY_VERSION}.json" >> "${DEB_DIR}/DEBIAN/conffiles"

fi

if [ "$OSCTRL_COMPONENT" == "api" ]
then
    # Copy configs
    cp deploy/config/jwt.json "${DEB_DIR}/opt/osctrl/config/jwt.json" && \
        chmod 640 "${DEB_DIR}/opt/osctrl/config/jwt.json"

    # Define conffiles
    echo "/opt/osctrl/config/jwt.json" >> "${DEB_DIR}/DEBIAN/conffiles"
fi
