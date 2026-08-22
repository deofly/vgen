#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
VERSION="$(python3 -I -B "${ROOT_DIR}/tools/project_version.py")"
OUTPUT_DIR="${ROOT_DIR}/dist/VGen-macOS-${VERSION}"
OUTPUT_ZIP="${ROOT_DIR}/dist/VGen-macOS-${VERSION}.zip"
GATEWAY_URL=""

if [[ "${1:-}" == "--gateway" ]]; then
  GATEWAY_URL="${2:-}"
  shift 2
fi
if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s [--gateway https://gateway.example]\n' "$0" >&2
  exit 2
fi

WHEEL="${ROOT_DIR}/dist/vgen-${VERSION}-py3-none-any.whl"
if [[ ! -f "${WHEEL}" ]]; then
  printf 'missing release wheel: %s\n' "${WHEEL}" >&2
  exit 1
fi
if [[ -e "${OUTPUT_DIR}" || -e "${OUTPUT_ZIP}" ]]; then
  printf 'refusing to overwrite bundle directory or zip: %s\n' "${OUTPUT_DIR}" >&2
  exit 1
fi

VGEN_EXPECTED_VERSION="${VERSION}" VGEN_WHEEL_PATH="${WHEEL}" python3 -I -B <<'PY'
import os
import zipfile
from email.parser import Parser
from pathlib import Path

path = Path(os.environ["VGEN_WHEEL_PATH"])
version = os.environ["VGEN_EXPECTED_VERSION"]
try:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise SystemExit("wheel contains duplicate paths")
        if any(
            name.startswith(("/", "\\"))
            or ".." in Path(name.replace("\\", "/")).parts
            for name in names
        ):
            raise SystemExit("wheel contains an unsafe path")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise SystemExit("wheel metadata is incomplete")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
    raise SystemExit("wheel is not readable") from exc
if metadata.get("Name", "").casefold() != "vgen":
    raise SystemExit("wheel distribution name must be vgen")
if metadata.get("Version") != version:
    raise SystemExit("wheel metadata version does not match pyproject.toml")
if path.name != f"vgen-{version}-py3-none-any.whl":
    raise SystemExit("wheel filename does not match pyproject.toml")
if "Tag: py3-none-any" not in wheel_metadata.splitlines():
    raise SystemExit("wheel must contain the py3-none-any tag")
PY

mkdir -p "${OUTPUT_DIR}"
cp "${ROOT_DIR}/examples/macos/install.command" "${OUTPUT_DIR}/install.command"
# The bundle keeps an offline README, but its content comes from the single
# user-guide source instead of a separately maintained component document.
cp "${ROOT_DIR}/docs/user-guide.md" "${OUTPUT_DIR}/README.md"
cp "${WHEEL}" "${OUTPUT_DIR}/"
chmod 755 "${OUTPUT_DIR}/install.command"
if [[ -n "${GATEWAY_URL}" ]]; then
  printf '%s\n' "${GATEWAY_URL}" >"${OUTPUT_DIR}/gateway-default.txt"
  chmod 644 "${OUTPUT_DIR}/gateway-default.txt"
fi

MANIFEST_FILES=(
  "README.md"
  "install.command"
  "vgen-${VERSION}-py3-none-any.whl"
)
if [[ -f "${OUTPUT_DIR}/gateway-default.txt" ]]; then
  MANIFEST_FILES+=("gateway-default.txt")
fi
(
  cd "${OUTPUT_DIR}"
  for file in "${MANIFEST_FILES[@]}"; do
    shasum -a 256 "${file}"
  done >SHA256SUMS
)

# Stable file timestamps plus zip -X make identical release inputs produce the
# same downloadable archive and SHA-256.
touch -t 202001010000 "${OUTPUT_DIR}"/*
ZIP_INPUTS=(
  "VGen-macOS-${VERSION}/install.command"
  "VGen-macOS-${VERSION}/README.md"
  "VGen-macOS-${VERSION}/vgen-${VERSION}-py3-none-any.whl"
  "VGen-macOS-${VERSION}/SHA256SUMS"
)
if [[ -f "${OUTPUT_DIR}/gateway-default.txt" ]]; then
  ZIP_INPUTS+=("VGen-macOS-${VERSION}/gateway-default.txt")
fi
(
  cd "${ROOT_DIR}/dist"
  zip -X -q "$(basename "${OUTPUT_ZIP}")" "${ZIP_INPUTS[@]}"
)

printf 'macOS bundle created: %s\n' "${OUTPUT_DIR}"
printf 'download zip: %s\n' "${OUTPUT_ZIP}"
printf 'zip sha256: '
shasum -a 256 "${OUTPUT_ZIP}" | awk '{print $1}'
