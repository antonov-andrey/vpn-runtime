"""Behavior coverage for the target-only stable-proxy measurement scenario."""

import asyncio

from runtime_measurement.stable_proxy import stable_proxy_switch_restart_get


def test_stable_proxy_switch_restart_measurement(tmp_path) -> None:
    """Keep the measurement request aligned with every stable-proxy fence.

    Args:
        tmp_path: Temporary directory path.
    """

    sample = asyncio.run(stable_proxy_switch_restart_get(runtime_root_path=tmp_path))

    assert sample.name == "stable_proxy_switch_restart"
    assert sample.detail_by_name_map == {
        "atomic_switch_proven": True,
        "disabled_restart_proven": True,
        "runtime_instance_fence_rotated": True,
    }
