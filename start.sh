#!/bin/sh
set -e

/usr/local/bin/tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &

TS_ARGS="--authkey=${TAILSCALE_AUTHKEY} --hostname=${RENDER_SERVICE_NAME}"
if [ -n "$ADVERTISE_ROUTES" ]; then
  TS_ARGS="$TS_ARGS --advertise-routes=$ADVERTISE_ROUTES"
fi

until /usr/local/bin/tailscale up $TS_ARGS; do
  sleep 0.1
done

echo "Tailscale is up at $(/usr/local/bin/tailscale ip)"

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
