"""Build the credential-free Windows Worker artifact for a reviewed release."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from windows_worker_wheelhouse import (
    build_worker_wheelhouse,
    committed_worker_lock_set_sha256,
    validate_committed_worker_wheelhouse,
)

from vgen import __version__
from vgen.cli.worker_bundle import create_public_windows_worker_installer_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the universal Windows Worker ZIP without principal credentials."
    )
    parser.add_argument("--gateway", required=True, help="Gateway HTTPS origin")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="prebuilt reviewed wheelhouse; omitted builds it from the committed hash locks",
    )
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vgen-worker-bundle-") as temporary:
        wheelhouse = arguments.wheelhouse
        if wheelhouse is None:
            wheelhouse = build_worker_wheelhouse(Path(temporary) / "wheelhouse")
        else:
            validate_committed_worker_wheelhouse(wheelhouse)
        result = create_public_windows_worker_installer_bundle(
            gateway_url=arguments.gateway,
            wheelhouse_path=wheelhouse,
            runtime_lock_set_sha256=committed_worker_lock_set_sha256(),
            wheel_path=arguments.wheel,
            output=(
                arguments.output
                or Path("dist") / f"vgen-windows-worker-installer-{__version__}.zip"
            ),
        )
    print(result.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
