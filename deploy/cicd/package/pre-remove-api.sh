#!/bin/sh

set -u

case "${1:-}" in
    0|remove)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl disable --now osctrl-api.service || true
        fi
        ;;
esac
