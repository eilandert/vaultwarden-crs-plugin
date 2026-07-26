# ---------------------------------------------------------------------------
# Angie (nginx fork) + libmodsecurity3 — a faithful mirror of production
# (mail.myguard.nl runs eilandert/angie with angie-module-http-modsecurity
# and libmodsecurity3 3.0.14). Engine + connector come straight from the
# deb.myguard.nl apt repo, so this catches v3-specific parse behaviour.
# `angie -t` is the BUILD-TIME gate.
# ---------------------------------------------------------------------------
ARG CRS_IMAGE=vaultwarden-crs:latest
FROM ${CRS_IMAGE} AS crs

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://deb.myguard.nl/deb.myguard.nl.gpg -o /tmp/mg.key \
 && (gpg --dearmor < /tmp/mg.key > /etc/apt/keyrings/deb.myguard.nl.gpg 2>/dev/null \
      || cp /tmp/mg.key /etc/apt/keyrings/deb.myguard.nl.gpg) \
 && echo 'deb [signed-by=/etc/apt/keyrings/deb.myguard.nl.gpg] https://deb.myguard.nl bookworm main' \
      > /etc/apt/sources.list.d/myguard.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      angie angie-module-http-modsecurity libmodsecurity3 \
 && rm -rf /var/lib/apt/lists/* /tmp/mg.key

# Identical CRS + plugin tree as the Apache image.
COPY --from=crs /opt/crs /opt/crs

# Locate the connector .so the package installed and write a complete,
# minimal angie.conf that loads it and points ModSecurity at the shared chain.
#
# The `location /` line satisfies THREE constraints at once; earlier attempts
# each fixed one and broke another (edc3c8a -> cb7473c -> 04e795d):
#   1. ModSecurity must actually run. A bare `return 200` in `location /` is
#      handled in the rewrite phase, before the access phase where the
#      connector runs -- audit log stays empty and go-ftw finds no markers.
#      A try_files lookup keeps the access phase reachable.
#   2. REQUEST_FILENAME must stay the real URI. `try_files $uri /index.html`
#      internally rewrites missing paths to /index.html, which 9530230 allows,
#      so probes like /wp-login.php never trip the rule.
#   3. A non-existent path must NOT be answered by the engine itself.
#      `=404` makes nginx 404 every path that is not a file on disk, so
#      legitimate routes (/api/sync) fail no_expect_ids cases that pass on
#      Apache, whose stub 200s everything.
# `try_files $uri $uri/ @ok` does the filesystem lookup (1), performs no URI
# rewrite (2), and falls back to a named location that always 200s (3).
# The suite asserts on expect_ids/no_expect_ids, never on status, so the
# blanket 200 is not a signal -- see the go-ftw notes in tests/README.
RUN set -eu; \
    SO="$(find /usr/lib /usr/lib64 -name 'ngx_http_modsecurity_module.so' 2>/dev/null | head -n1)"; \
    test -n "$SO"; \
    mkdir -p /var/log/modsec /var/log/angie /var/www/html; \
    printf 'ok\n' > /var/www/html/index.html; \
    { \
      echo "load_module $SO;"; \
      echo 'user www-data;'; \
      echo 'worker_processes auto;'; \
      echo 'error_log /var/log/angie/error.log notice;'; \
      echo 'pid /run/angie.pid;'; \
      echo 'events { worker_connections 1024; }'; \
      echo 'http {'; \
      echo '    modsecurity on;'; \
      echo '    modsecurity_rules_file /opt/crs/crs-main.conf;'; \
      echo '    access_log /var/log/angie/access.log;'; \
      echo '    server {'; \
      echo '        listen 80 default_server;'; \
      echo '        server_name ci.local;'; \
      echo '        root /var/www/html;'; \
      echo '        location / { try_files $uri $uri/ @ok; }'; \
      echo '        location @ok { return 200 "ok"; }'; \
      echo '    }'; \
      echo '}'; \
    } > /etc/angie/angie.conf

# BUILD-TIME GATE: full rule parse via the real engine. Fails on bad rules.
RUN angie -t

EXPOSE 80
STOPSIGNAL SIGQUIT
CMD ["angie", "-g", "daemon off;"]
