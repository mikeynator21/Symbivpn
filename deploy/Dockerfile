# SymbiVPN needs nothing but a Python interpreter, so the image is the base
# image plus the source. No build step, no wheels, no dependency resolution.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iproute2 nftables wireguard-tools iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/symbivpn
COPY symbivpn/ ./symbivpn/
COPY pyproject.toml README.md ./

RUN python -m compileall -q symbivpn \
 && printf '#!/bin/sh\nexec python -m symbivpn.cli "$@"\n' > /usr/local/bin/symbivpn \
 && chmod +x /usr/local/bin/symbivpn

ENV SYMBIVPN_STATE=/var/lib/symbivpn
VOLUME ["/var/lib/symbivpn", "/etc/symbivpn"]

EXPOSE 53/udp 53/tcp 8080/tcp 51820/udp

# The self-test needs no network and no privileges, so it is a genuine health
# signal rather than a liveness ping.
HEALTHCHECK --interval=60s --timeout=30s --start-period=20s --retries=3 \
    CMD python -m symbivpn.cli selftest --port 15353 >/dev/null 2>&1 || exit 1

ENTRYPOINT ["symbivpn"]
CMD ["run"]
