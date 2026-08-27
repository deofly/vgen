from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_development_compose_is_loopback_only_and_explicit_about_local_artifacts() -> None:
    compose = (ROOT / "examples" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "127.0.0.1:${VGEN_GATEWAY_BIND_PORT:-8000}:8000" in compose
    assert "VGEN_ARTIFACT_STORE: local" in compose
    assert 'VGEN_ALLOW_LOCAL_ARTIFACT_STORE: "1"' in compose
    assert "caddy:" not in compose


def test_public_docs_and_server_examples_do_not_name_maintainer_operated_domains() -> None:
    examples = (
        ROOT / "docs" / "user-guide.md",
        ROOT / "examples" / "ecs" / "nginx-vgen.conf.example",
        ROOT / "examples" / "ecs" / "nginx-vgen-releases.conf.example",
    )
    for path in examples:
        content = path.read_text(encoding="utf-8")
        assert "zcbiz.com" not in content
        assert "example.com" in content


def test_ci_has_read_only_permissions_pinned_actions_and_security_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow
    assert "actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c" in workflow
    assert "python -m pip_audit ." in workflow
    assert "bandit -c pyproject.toml -r src tools" in workflow
    assert "python tools/check_public_repository.py" in workflow
