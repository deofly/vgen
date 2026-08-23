"""Build the credential-free Windows Worker artifact for a reviewed release."""

from __future__ import annotations

import argparse
from pathlib import Path

from vgen import __version__
from vgen.cli.worker_bundle import create_public_windows_worker_installer_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the universal Windows Worker ZIP without principal credentials."
    )
    parser.add_argument("--gateway", required=True, help="Gateway HTTPS origin")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = create_public_windows_worker_installer_bundle(
        gateway_url=arguments.gateway,
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
