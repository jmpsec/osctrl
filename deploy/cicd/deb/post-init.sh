#!/bin/bash

set -e

################### Set perms on config directory ###################
if [ -d "/etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}" ] 
then
    chown root:osctrl -R /etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}
fi

################### Copy common configs ###################
if [ ! -f /usr/share/osctrl/db.json.example ]
then
    cp /tmp/osctrl-{{ OSCTRL_COMPONTENT }}/db.json.example /usr/share/osctrl/db.json.example
    chown root:root /usr/share/osctrl/db.json.example
fi

if [ ! -f /usr/share/osctrl/redis.json.example ]
then
    cp /tmp/osctrl-{{ OSCTRL_COMPONTENT }}/redis.json.example /usr/share/osctrl/redis.json.example
    chown root:root /usr/share/osctrl/redis.json.example
fi
rm -rd /tmp/osctrl-{{ OSCTRL_COMPONTENT }}

################### osctrl-admin web assets ###################
if [ -d "/usr/share/osctrl/tmpl_admin" ] 
then
    # set user as the owner
    chown root -R /usr/share/osctrl/tmpl_admin/         
    
    # set osctrl as the group owner
    chgrp -R osctrl /usr/share/osctrl/tmpl_admin/       
    
    # 750 permissions for everything
    chmod -R 750 /usr/share/osctrl/tmpl_admin/          
    
    # new files and folders inherit group ownership from the parent folder
    chmod g+s /usr/share/osctrl/tmpl_admin/


fi

if [ -d "/usr/share/osctrl/static" ] 
then
    # set user as the owner
    chown root -R /usr/share/osctrl/static/
    
    # set osctrl as the group owner
    chgrp -R osctrl /usr/share/osctrl/static/
    
    # 750 permissions for everything
    chmod -R 750 /usr/share/osctrl/static/
    
    # new files and folders inherit group ownership from the parent folder
    chmod g+s /usr/share/osctrl/static/
fi
