"""Behavior tests for the pinned final image."""

from pathlib import Path

VPN_RUNTIME_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_requires_release_owned_bases_and_pins_gateway_packages() -> None:
    """Require exact release inputs while keeping image-local packages reproducible."""

    dockerfile_text = (VPN_RUNTIME_ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")

    assert dockerfile_text.startswith("# check=skip=InvalidDefaultArgInFrom\n\nARG GLUETUN_IMAGE\nARG PYTHON_IMAGE\n")
    assert "FROM ${PYTHON_IMAGE} AS python-runtime" in dockerfile_text
    assert "FROM ${GLUETUN_IMAGE}" in dockerfile_text
    assert "ARG GLUETUN_IMAGE=" not in dockerfile_text
    assert "ARG PYTHON_IMAGE=" not in dockerfile_text
    assert "--require-hashes" in dockerfile_text
    assert "dante-server=1.4.4-r0" in dockerfile_text
    assert "dnsmasq=2.91-r1" in dockerfile_text
    assert "adduser -D -H -s /sbin/nologin -u 1001 -G vpndns vpndns" in dockerfile_text
    assert "chown root:vpnproxy /runtime" in dockerfile_text
    assert "chown root:root /tmp/gluetun" in dockerfile_text
    assert "chmod 710 /runtime" in dockerfile_text
    assert "chmod 700 /tmp/gluetun" in dockerfile_text
    assert 'ENTRYPOINT ["/sbin/tini", "--"]' in dockerfile_text
