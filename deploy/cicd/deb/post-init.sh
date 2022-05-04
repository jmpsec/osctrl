#!/bin/bash

set -e

################### Set perms on config directory ###################
if [ -d "/etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}" ] 
then
    chown root:osctrl -R /etc/osctrl/osctrl-{{ OSCTRL_COMPONTENT }}
fi
