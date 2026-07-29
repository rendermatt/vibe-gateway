# adopted from https://kofi.sexy/blog/zero-downtime-render-disk
FROM caddy
RUN setcap -r /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
