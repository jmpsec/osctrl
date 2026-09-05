#!/bin/sh

set -eu

if ! getent group osctrl >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system osctrl
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup --system osctrl
    else
        echo "Unable to create the osctrl group" >&2
        exit 1
    fi
fi

if ! id -u osctrl >/dev/null 2>&1; then
    nologin_shell="$(command -v nologin || true)"
    if [ -z "${nologin_shell}" ]; then
        nologin_shell=/sbin/nologin
    fi

    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid osctrl --home-dir /opt/osctrl \
            --no-create-home --shell "${nologin_shell}" osctrl
    elif command -v adduser >/dev/null 2>&1; then
        adduser --system --ingroup osctrl --home /opt/osctrl \
            --no-create-home --shell "${nologin_shell}" osctrl
    else
        echo "Unable to create the osctrl user" >&2
        exit 1
    fi
fi

install -d -o root -g osctrl -m 0750 /opt/osctrl/config
