"""Behavior tests for the pinned final image and reference gateway Pod."""

from pathlib import Path

import yaml


def test_dockerfile_requires_release_owned_bases_and_pins_gateway_packages() -> None:
    """Require exact release inputs while keeping image-local packages reproducible."""

    dockerfile_text = Path("docker/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile_text.startswith("ARG GLUETUN_IMAGE\nARG PYTHON_IMAGE\n")
    assert "FROM ${PYTHON_IMAGE} AS python-runtime" in dockerfile_text
    assert "FROM ${GLUETUN_IMAGE}" in dockerfile_text
    assert "ARG GLUETUN_IMAGE=" not in dockerfile_text
    assert "ARG PYTHON_IMAGE=" not in dockerfile_text
    assert "--require-hashes" in dockerfile_text
    assert "dante-server=1.4.4-r0" in dockerfile_text
    assert "dnsmasq=2.91-r1" in dockerfile_text
    assert "adduser -D -H -s /sbin/nologin -u 1001 -G vpndns vpndns" in dockerfile_text
    assert "chown root:vpnproxy /runtime" in dockerfile_text
    assert "chmod 710 /runtime" in dockerfile_text
    assert 'ENTRYPOINT ["/sbin/tini", "--"]' in dockerfile_text


def test_kubernetes_gateway_starts_prepared_with_minimal_secret_and_tunnel_access() -> None:
    """Expose SOCKS only after activation while keeping management local and credentials read-only."""

    resource_list = list(yaml.safe_load_all(Path("deploy/k8s/gateway.yaml").read_text(encoding="utf-8")))
    deployment = next(resource for resource in resource_list if resource["kind"] == "Deployment")
    service = next(resource for resource in resource_list if resource["kind"] == "Service")
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    mount_by_path_map = {mount["mountPath"]: mount for mount in container["volumeMounts"]}

    assert pod_spec["automountServiceAccountToken"] is False
    assert container["args"][0] == "vpn-runtime-daemon"
    assert container["securityContext"]["capabilities"] == {
        "add": ["NET_ADMIN", "SETGID", "SETUID"],
        "drop": ["ALL"],
    }
    assert mount_by_path_map["/input/vpn_config"]["readOnly"] is True
    assert mount_by_path_map["/dev/net/tun"]["name"] == "tun-device"
    assert container["readinessProbe"]["exec"]["command"] == [
        "vpn-runtime-readiness",
        "--state-path",
        "/runtime/vpn/status.json",
    ]
    assert container["ports"] == [{"containerPort": 1080, "name": "socks5", "protocol": "TCP"}]
    assert service["spec"]["ports"] == [{"name": "socks5", "port": 1080, "protocol": "TCP", "targetPort": "socks5"}]
    assert all(port["containerPort"] not in {8000, 9999} for port in container["ports"])
