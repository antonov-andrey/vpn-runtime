ARG PYTHON_IMAGE=docker.io/library/python@sha256:6b91e66ab2a880ce9ca5a1b91c70f45963ff71ff68268df056336e1a657d5efd
ARG GLUETUN_IMAGE=docker.io/qmcgaw/gluetun@sha256:1a5bf4b4820a879cdf8d93d7ef0d2d963af56670c9ebff8981860b6804ebc8ab

FROM ${PYTHON_IMAGE} AS python-runtime

WORKDIR /build

COPY pyproject.toml ./
COPY vpn_runtime ./vpn_runtime

RUN python -m pip install --no-cache-dir --prefix=/opt/vpn-runtime .

FROM ${GLUETUN_IMAGE}

RUN apk add --upgrade --no-cache \
        ca-certificates=20260611-r0 \
        dante-server=1.4.4-r0 \
        gdbm=1.24-r0 \
        libbz2=1.0.8-r6 \
        libcrypto3=3.5.7-r0 \
        libffi=3.4.8-r0 \
        libncursesw=6.5_p20250503-r0 \
        libpanelw=6.5_p20250503-r0 \
        libssl3=3.5.7-r0 \
        libuuid=2.41-r9 \
        ncurses-terminfo-base=6.5_p20250503-r0 \
        readline=8.2.13-r1 \
        sqlite-libs=3.49.2-r1 \
        tini=0.19.0-r3 \
        xz-libs=5.8.3-r0 \
        zlib=1.3.2-r0 \
    && addgroup -g 1000 vpnproxy \
    && adduser -D -H -s /sbin/nologin -u 1000 -G vpnproxy vpnproxy \
    && mkdir -p /input /runtime \
    && chmod 700 /runtime

COPY --from=python-runtime /usr/local /usr/local
COPY --from=python-runtime /opt/vpn-runtime /opt/vpn-runtime

ENV PATH=/opt/vpn-runtime/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV PYTHONPATH=/opt/vpn-runtime/lib/python3.14/site-packages

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["vpn-runtime-daemon", "--help"]
