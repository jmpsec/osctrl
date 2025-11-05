#!/bin/bash

set -e

################### Reload osctrl-{{ OSCTRL_COMPONENT }} service ###################
systemctl daemon-reload
echo "osctrl-{{ OSCTRL_COMPONENT }} service daemon reloaded successfully."

################### Enable osctrl-{{ OSCTRL_COMPONENT }} service ###################
systemctl enable osctrl-{{ OSCTRL_COMPONENT }}.service
echo "osctrl-{{ OSCTRL_COMPONENT }} service enabled successfully."

################### Start osctrl-{{ OSCTRL_COMPONENT }} service ###################
systemctl start osctrl-{{ OSCTRL_COMPONENT }}.service
echo "osctrl-{{ OSCTRL_COMPONENT }} service started successfully."

################### Check osctrl-{{ OSCTRL_COMPONENT }} service status ###################
systemctl status osctrl-{{ OSCTRL_COMPONENT }}.service --no-pager
echo "osctrl-{{ OSCTRL_COMPONENT }} service status checked successfully."

################### Print osctrl-{{ OSCTRL_COMPONENT }} service logs ###################
journalctl -u osctrl-{{ OSCTRL_COMPONENT }}.service --no-pager --since "10 minutes ago"
echo "osctrl-{{ OSCTRL_COMPONENT }} service logs printed successfully."

################### Print osctrl-{{ OSCTRL_COMPONENT }} version ###################
/opt/osctrl/bin/osctrl-{{ OSCTRL_COMPONENT }} --version
echo "osctrl-{{ OSCTRL_COMPONENT }} version printed successfully."
