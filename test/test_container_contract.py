"""Behavior tests for the pinned final image and reference gateway Pod."""

from pathlib import Path

import yaml

VPN_RUNTIME_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_selects_python_branch_and_pins_gateway_implementations() -> None:
    """Track Python patch updates while keeping gateway implementations reproducibly selected."""

    dockerfile_text = (VPN_RUNTIME_ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")

    assert "python:3.14-alpine3.22" in dockerfile_text
    assert "gluetun@sha256:1a5bf4b4820a879cdf8d93d7ef0d2d963af56670c9ebff8981860b6804ebc8ab" in dockerfile_text
    assert "dante-server=1.4.4-r0" in dockerfile_text
    assert "dnsmasq=2.91-r1" in dockerfile_text
    assert "adduser -D -H -s /sbin/nologin -u 1001 -G vpndns vpndns" in dockerfile_text
    assert "chown root:vpnproxy /runtime" in dockerfile_text
    assert "chmod 710 /runtime" in dockerfile_text
    assert 'ENTRYPOINT ["/sbin/tini", "--"]' in dockerfile_text


def test_kubernetes_gateway_starts_prepared_with_minimal_secret_and_tunnel_access() -> None:
    """Expose SOCKS only after activation while keeping management local and credentials read-only."""

    resource_list = list(
        yaml.safe_load_all((VPN_RUNTIME_ROOT / "deploy" / "k8s" / "gateway.yaml").read_text(encoding="utf-8"))
    )
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
