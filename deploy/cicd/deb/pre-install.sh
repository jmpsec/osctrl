#!/bin/bash

set -e

################### Create osctrl user and group ###################
id -u osctrl &>/dev/null || adduser --system --no-create-home --group osctrl

################### Create osctrl directory ###################
if [ ! -d "/opt/osctrl" ]
then
    echo "Directory /opt/osctrl DOES NOT exists."
    mkdir /opt/osctrl
    chown root:root -R /opt/osctrl
fi

################### Create osctrl log directory ###################
if [ ! -d "/var/log/osctrl-{{ OSCTRL_COMPONENT }}" ]
then
    echo "Directory /var/log/osctrl-{{ OSCTRL_COMPONENT }} DOES NOT exists."
    mkdir /var/log/osctrl-{{ OSCTRL_COMPONENT }}
    chown osctrl:adm -R /var/log/osctrl-{{ OSCTRL_COMPONENT }}
fi


################### Set perms on config directory ###################
if [ -d "/opt/osctrl/config" ]
then
    chown root:osctrl -R /opt/osctrl/config
fi

################### Copy common configs ###################
if [ ! -f /opt/osctrl/db.json.example ]
then
    cp /tmp/osctrl-{{ OSCTRL_COMPONENT }}/db.json.example /opt/osctrl/db.json.example
    chown root:root /opt/osctrl/db.json.example
fi

if [ ! -f /opt/osctrl/redis.json.example ]
then
    cp /tmp/osctrl-{{ OSCTRL_COMPONENT }}/redis.json.example /opt/osctrl/redis.json.example
    chown root:root /opt/osctrl/redis.json.example
fi
rm -rd /tmp/osctrl-{{ OSCTRL_COMPONENT }}

################### osctrl-admin web assets ###################
if [ -d "/opt/osctrl/tmpl_admin" ]
then
    # set user as the owner
    chown root -R /opt/osctrl/tmpl_admin/

    # set osctrl as the group owner
    chgrp -R osctrl /opt/osctrl/tmpl_admin/

    # 750 permissions for everything
    chmod -R 750 /opt/osctrl/tmpl_admin/

    # new files and folders inherit group ownership from the parent folder
    chmod g+s /opt/osctrl/tmpl_admin/
fi

if [ -d "/opt/osctrl/static" ]
then
    # set user as the owner
    chown root -R /opt/osctrl/static/

    # set osctrl as the group owner
    chgrp -R osctrl /opt/osctrl/static/

    # 750 permissions for everything
    chmod -R 750 /opt/osctrl/static/

    # new files and folders inherit group ownership from the parent folder
    chmod g+s /opt/osctrl/static/
fi
