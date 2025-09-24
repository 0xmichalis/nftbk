#!/bin/sh

# Build a Caddyfile with one or more server blocks.
# VHOSTS format (semicolon-separated):
#   domain.tld=upstream_host:port;domain2.tld=upstream2:port
#   or: domain.tld upstream_host:port;domain2.tld upstream2:port
# Example:
#   example.com=nftbk-server:8080;api.example.com=internal-api:9000

TEMPLATE_PATH=/etc/caddy/Caddyfile.template
OUTPUT_PATH=/etc/caddy/Caddyfile

# Simple template replacement without sed complications
replace_template() {
  local host="$1"
  local upstream="$2"
  # Use @ as delimiter to avoid issues with / in domains
  sed -e "s@\\\${SERVER_NAME}@${host}@g" -e "s@\\\${UPSTREAM}@${upstream}@g" "${TEMPLATE_PATH}"
}

if [ ! -s "${TEMPLATE_PATH}" ]; then
  echo "Caddyfile template not found or empty at ${TEMPLATE_PATH}" >&2
  exit 1
fi

if [ -z "${VHOSTS}" ]; then
  echo "VHOSTS is required. Provide semicolon-separated 'domain=upstream' or 'domain upstream' entries." >&2
  exit 1
fi

: > "${OUTPUT_PATH}"
# Split VHOSTS by semicolon and process each entry
IFS=';'
for line in ${VHOSTS}; do
  # Skip empty lines and comments
  [ -z "${line}" ] && continue
  case "${line}" in
    \#*) continue;;
  esac
  # Parse "host=upstream" or "host upstream"
  if [ "${line#*=}" != "${line}" ]; then
    host=${line%%=*}
    upstream=${line#*=}
  else
    # shellcheck disable=SC2086
    set -- ${line}
    host=${1:-}
    upstream=${2:-}
  fi
  if [ -z "${host}" ] || [ -z "${upstream}" ]; then
    echo "Invalid VHOSTS entry: ${line}" >&2
    exit 1
  fi
  replace_template "${host}" "${upstream}" >> "${OUTPUT_PATH}"
  printf '\n' >> "${OUTPUT_PATH}"
done

caddy run --config "${OUTPUT_PATH}" --adapter caddyfile
