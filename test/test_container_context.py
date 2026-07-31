"""Verify the exact VPN runtime container build context."""

from pathlib import Path


def test_container_context_includes_locked_python_dependencies() -> None:
    """The clean Git context must contain every hash lock copied by Dockerfile."""

    project_root_path = Path(__file__).resolve().parents[1]
    dockerignore_rule_set = set((project_root_path / ".dockerignore").read_text(encoding="utf-8").splitlines())

    assert "!docker/" in dockerignore_rule_set
    for relative_path in (
        "docker/build-requirements.lock",
        "docker/requirements.lock",
    ):
        assert (project_root_path / relative_path).is_file()
        assert f"!{relative_path}" in dockerignore_rule_set
