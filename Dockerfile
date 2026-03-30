# adopted from https://kofi.sexy/blog/zero-downtime-render-disk
FROM caddy
RUN setcap -r /usr/bin/caddy
ARG DOWNSTREAM_PORT=10000
ARG PORT=10000
ARG GATEWAY_USER
ARG GATEWAY_PASSWORD
COPY Caddyfile /etc/caddy/Caddyfile
