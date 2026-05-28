#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/update-openapi.sh [--check]

Regenerates the Swagger 2 spec from API annotations and converts it to the
root OpenAPI 3 spec.

Options:
  --check  Verify osctrl-api.yaml is up to date without modifying it.
EOF
}

check_mode=0
if [[ "${1:-}" == "--check" ]]; then
  check_mode=1
  shift
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
openapi_yaml="${repo_root}/osctrl-api.yaml"
converter_version="${SWAGGER2OPENAPI_VERSION:-7.0.8}"

if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx is required to run swagger2openapi" >&2
  exit 1
fi

cd "${repo_root}"

tmp_dir="$(mktemp -d)"
tmp_openapi="${tmp_dir}/osctrl-api.yaml"
trap 'rm -rf "${tmp_dir}"' EXIT

if [[ "${check_mode}" -eq 1 ]]; then
  swagger_output_dir="${tmp_dir}/docs"
else
  swagger_output_dir="${repo_root}/cmd/api/docs"
fi

make SWAG_OUTPUT_DIR="${swagger_output_dir}" swagger

swagger_yaml="${swagger_output_dir}/swagger.yaml"

if [[ ! -s "${swagger_yaml}" ]]; then
  echo "error: generated Swagger file is missing or empty: ${swagger_yaml}" >&2
  exit 1
fi

npx --yes "swagger2openapi@${converter_version}" \
  --patch \
  --yaml \
  --outfile "${tmp_openapi}" \
  "${swagger_yaml}"

if [[ "${check_mode}" -eq 1 ]]; then
  if ! cmp -s "${tmp_openapi}" "${openapi_yaml}"; then
    echo "error: ${openapi_yaml} is out of date. Run tools/update-openapi.sh and commit the result." >&2
    exit 1
  fi
  exit 0
fi

mv "${tmp_openapi}" "${openapi_yaml}"
