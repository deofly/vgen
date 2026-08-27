from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from vgen.market.node_packs import (
    NodePackError,
    build_node_pack_archive,
    materialize_node_pack,
)


def _build(tmp_path: Path, name: str = "node-pack.zip") -> Path:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "__init__.py").write_text("NODE_CLASS_MAPPINGS = {}\n", encoding="utf-8")
    (source / "nodes.py").write_text("class UnetLoaderGGUF: pass\n", encoding="utf-8")
    wheels = tmp_path / "wheels"
    wheels.mkdir(exist_ok=True)
    (wheels / "gguf-0.17.1-py3-none-any.whl").write_bytes(b"wheel bytes")
    archive = tmp_path / name
    build_node_pack_archive(
        source,
        archive,
        node_pack_id="vgen/comfyui-gguf",
        version="1.0.0",
        directory="ComfyUI-GGUF",
        source="https://github.com/city96/ComfyUI-GGUF.git",
        revision="6ea2651e7df66d7585f6ffee804b20e92fb38b8a",
        node_classes=["UnetLoaderGGUF"],
        wheel_root=wheels,
    )
    return archive


def test_node_pack_build_is_deterministic_and_materializes_exact_bytes(
    tmp_path: Path,
) -> None:
    first = _build(tmp_path, "first.zip")
    second = _build(tmp_path, "second.zip")

    assert first.read_bytes() == second.read_bytes()
    manifest, source, wheels, digest = materialize_node_pack(first, tmp_path / "unpacked")
    assert manifest.id == "vgen/comfyui-gguf"
    assert manifest.directory == "ComfyUI-GGUF"
    assert (source / "nodes.py").read_text(encoding="utf-8") == (
        "class UnetLoaderGGUF: pass\n"
    )
    assert (wheels / "gguf-0.17.1-py3-none-any.whl").read_bytes() == b"wheel bytes"
    assert len(digest) == 64


def test_node_pack_rejects_tampered_member(tmp_path: Path) -> None:
    archive = _build(tmp_path)
    rewritten = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(rewritten, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "source/nodes.py":
                data = b"malicious bytes"
            target.writestr(info, data)

    with pytest.raises(NodePackError, match="NODE_PACK_MEMBER_DIGEST_MISMATCH"):
        materialize_node_pack(rewritten, tmp_path / "unpacked")


def test_node_pack_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("../outside.py", b"bad")

    with pytest.raises(NodePackError, match="NODE_PACK_ARCHIVE_INVALID"):
        materialize_node_pack(archive, tmp_path / "unpacked")
    assert not (tmp_path / "outside.py").exists()


def test_node_pack_manifest_rejects_unknown_fields(tmp_path: Path) -> None:
    archive = _build(tmp_path)
    rewritten = tmp_path / "unknown-field.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(rewritten, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "node-pack.json":
                value = json.loads(data)
                value["surprise"] = True
                data = json.dumps(value).encode()
            target.writestr(info, data)

    with pytest.raises(NodePackError, match="NODE_PACK_MANIFEST_INVALID"):
        materialize_node_pack(rewritten, tmp_path / "unpacked")
