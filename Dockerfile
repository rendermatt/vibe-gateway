# adopted from https://kofi.sexy/blog/zero-downtime-render-disk
FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/greenpau/caddy-security

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN setcap -r /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
