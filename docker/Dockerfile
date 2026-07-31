ARG GLUETUN_IMAGE
ARG PYTHON_IMAGE

FROM ${PYTHON_IMAGE} AS python-runtime

WORKDIR /build

COPY pyproject.toml ./
COPY vpn_runtime ./vpn_runtime
COPY docker/build-requirements.lock docker/requirements.lock /build-lock/

RUN python -m pip install --no-cache-dir --require-hashes \
        -r /build-lock/build-requirements.lock \
        -r /build-lock/requirements.lock \
    && python -m pip install --no-build-isolation --no-cache-dir --no-deps --prefix=/opt/vpn-runtime . \
    && rm -rf /build-lock

FROM ${GLUETUN_IMAGE}

RUN apk add --upgrade --no-cache \
        ca-certificates=20260611-r0 \
        dante-server=1.4.4-r0 \
        dnsmasq=2.91-r1 \
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
    && addgroup -g 1001 vpndns \
    && adduser -D -H -s /sbin/nologin -u 1001 -G vpndns vpndns \
    && mkdir -p /input /runtime \
    && chown root:vpnproxy /runtime \
    && chmod 710 /runtime

COPY --from=python-runtime /usr/local /usr/local
COPY --from=python-runtime /opt/vpn-runtime /opt/vpn-runtime

ENV PATH=/opt/vpn-runtime/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV PYTHONPATH=/opt/vpn-runtime/lib/python3.14/site-packages

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["vpn-runtime-daemon", "--help"]
