# adopted from https://kofi.sexy/blog/zero-downtime-render-disk
FROM caddy:builder AS caddy-builder

RUN xcaddy build \
    --with github.com/greenpau/caddy-security

FROM debian:stable-slim AS tailscale
WORKDIR /render
ARG TAILSCALE_VERSION=1.96.4
RUN apt-get -qq update \
  && apt-get -qq install -y --no-install-recommends wget ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
RUN TS_FILE=tailscale_${TAILSCALE_VERSION}_amd64.tgz \
  && wget -q "https://pkgs.tailscale.com/stable/${TS_FILE}" \
  && tar xzf "${TS_FILE}" --strip-components=1

FROM caddy:latest
COPY --from=caddy-builder /usr/bin/caddy /usr/bin/caddy
RUN setcap -r /usr/bin/caddy
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
COPY --from=tailscale /render/tailscale /render/tailscaled /usr/local/bin/
COPY Caddyfile /etc/caddy/Caddyfile
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
