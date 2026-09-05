#!/bin/sh

set -eu

template=deploy/config/systemd.service
output_dir=tmp/goreleaser-package

mkdir -p "${output_dir}"

render_service() {
    component=$1
    service_name="osctrl-${component}"
    config_file="/opt/osctrl/config/${component}.yml"

    sed \
        -e "s|_UU|osctrl|g" \
        -e "s|_GG|osctrl|g" \
        -e "s|_DEST|/opt/osctrl|g" \
        -e "s|_NAME|${service_name}|g" \
        -e "s|_ARGS|--config --config-file ${config_file}|g" \
        "${template}" > "${output_dir}/${service_name}.service"
}

render_service tls
render_service api
