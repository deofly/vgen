from __future__ import annotations

import stat

from vgen.gateway.main import run


def test_gateway_init_doctor_and_online_backup(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    bootstrap = tmp_path / "bootstrap-code"
    backup = tmp_path / "backup.db"

    assert run(["--database", str(database), "init", "--bootstrap-code-file", str(bootstrap)]) == 0
    assert database.is_file()
    assert bootstrap.is_file()
    assert run(["--database", str(database), "doctor"]) == 0
    assert run(["--database", str(database), "backup", str(backup)]) == 0
    assert backup.is_file()
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_gateway_init_defaults_bootstrap_next_to_database(tmp_path) -> None:
    database = tmp_path / "data" / "gateway.db"
    assert run(["--database", str(database), "init"]) == 0
    bootstrap = database.with_name("bootstrap-code")
    assert bootstrap.is_file()
    assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o600


def test_gateway_backup_refuses_to_overwrite_by_default(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    backup = tmp_path / "backup.db"
    assert run(["--database", str(database), "init"]) == 0
    backup.write_bytes(b"keep-me")

    try:
        run(["--database", str(database), "backup", str(backup)])
    except FileExistsError:
        pass
    else:
        raise AssertionError("backup unexpectedly overwrote an existing file")
    assert backup.read_bytes() == b"keep-me"
    assert run(["--database", str(database), "backup", str(backup), "--overwrite"]) == 0
