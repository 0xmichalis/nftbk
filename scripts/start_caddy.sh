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
  _host="$1"
  _upstream="$2"
  _template_content=""
  # Remove TLS block if CLOUDFLARE_API_TOKEN is not set
  if [ -z "${CLOUDFLARE_API_TOKEN}" ]; then
    # Remove lines from "tls {" to the matching closing "}" at the same indentation level
    _template_content=$(sed '/^[[:space:]]*tls {$/,/^[[:space:]]*}$/d' "${TEMPLATE_PATH}")
  else
    # https://github.com/caddy-dns/cloudflare
    _template_content=$(cat "${TEMPLATE_PATH}")
  fi
  # Use @ as delimiter to avoid issues with / in domains
  echo "${_template_content}" | sed -e "s@\\\${SERVER_NAME}@${_host}@g" -e "s@\\\${UPSTREAM}@${_upstream}@g"
  unset _host _upstream _template_content
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
