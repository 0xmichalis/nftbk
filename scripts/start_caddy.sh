#!/bin/sh

eval "echo \"$(cat /etc/caddy/Caddyfile.template)\"" > /etc/caddy/Caddyfile
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
