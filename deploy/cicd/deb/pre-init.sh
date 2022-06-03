#!/bin/bash

set -e

################### Create osctrl user and group ###################
id -u osctrl &>/dev/null || adduser --system --no-create-home --group osctrl

################### Create osctrl config directory ###################
if [ ! -d "/etc/osctrl" ] 
then
    echo "Directory /etc/osctrl DOES NOT exists." 
    mkdir /etc/osctrl
    chown root:root -R /etc/osctrl
fi

if [ ! -d "/etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}" ] 
then
    echo "Directory /etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }} DOES NOT exists." 
    mkdir /etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}
    chown root:osctrl /etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}
fi

################### Create osctrl log directory ###################
if [ ! -d "/var/log/osctrl" ] 
then
    echo "Directory /var/log/osctrl DOES NOT exists." 
    mkdir /var/log/osctrl
    chown osctrl:adm -R /var/log/osctrl
fi