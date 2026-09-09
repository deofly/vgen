from pathlib import Path


def test_installer_is_idempotent_and_validates_before_writing(tmp_path):
    import importlib.util

    installer = Path(__file__).resolve().parents[2] / "integrations/toonflow/install.py"
    spec = importlib.util.spec_from_file_location("toonflow_installer", installer)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "src/utils").mkdir(parents=True)
    (tmp_path / "src/lib").mkdir()
    (tmp_path / "package.json").write_text('{"name":"toonflow"}')
    (tmp_path / "src/utils/ai.ts").write_text("class AiVideo { this.result = await fn(input); }")
    (tmp_path / "src/app.ts").write_text(
        "await router.default(app);\nserver.listen(port, async () => {"
    )
    (tmp_path / "src/lib/fixDB.ts").write_text(
        '  const toonflowVer = await u.vendor.getVendor("toonflow").version;'
    )
    (tmp_path / "src/lib/vendor.json").write_text("{}")
    module.install(tmp_path)
    first = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    module.install(tmp_path)
    assert all(p.read_bytes() == data for p, data in first.items())
    assert '"127.0.0.1"' in (tmp_path / "src/app.ts").read_text()
