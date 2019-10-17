#!/bin/bash
#
# Helper for tmux and osctrl

vagrant ssh -- -t 'tmux new-session -s osctrl -c /opt/osctrl \; split-window -p 70 "sudo journalctl -f -t osctrl-tls; read" \; select-pane -t 0 \; split-window -h -c /vagrant \; attach'
