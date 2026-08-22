#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
VERSION="$(python3 -I -B "${ROOT_DIR}/tools/project_version.py")"
OUTPUT_DIR="${ROOT_DIR}/dist/VGen-macOS-${VERSION}"
OUTPUT_ZIP="${ROOT_DIR}/dist/VGen-macOS-${VERSION}.zip"
GATEWAY_URL=""
RELEASE_ORIGIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway)
      GATEWAY_URL="${2:-}"
      shift 2
      ;;
    --release-origin)
      RELEASE_ORIGIN="${2:-}"
      shift 2
      ;;
    *)
      printf 'usage: %s [--gateway https://gateway.example] [--release-origin https://download.example]\n' "$0" >&2
      exit 2
      ;;
  esac
done
if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s [--gateway https://gateway.example] [--release-origin https://download.example]\n' "$0" >&2
  exit 2
fi
if [[ -z "${RELEASE_ORIGIN}" ]]; then
  RELEASE_ORIGIN="${GATEWAY_URL}"
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
VGEN_INSTALL_TEMPLATE="${ROOT_DIR}/examples/macos/install.command" \
VGEN_INSTALL_OUTPUT="${OUTPUT_DIR}/install.command" \
VGEN_RELEASE_ORIGIN_VALUE="${RELEASE_ORIGIN}" python3 -I -B <<'PY'
import os
from pathlib import Path
from urllib.parse import urlsplit

source = Path(os.environ["VGEN_INSTALL_TEMPLATE"])
destination = Path(os.environ["VGEN_INSTALL_OUTPUT"])
origin = os.environ["VGEN_RELEASE_ORIGIN_VALUE"].strip().rstrip("/")
parsed = urlsplit(origin)
loopback = (parsed.hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in {"", "/"}
    or parsed.query
    or parsed.fragment
    or (parsed.scheme != "https" and not loopback)
):
    raise SystemExit("--release-origin must be a credential-free HTTPS origin")
template = source.read_text(encoding="utf-8")
token = "__VGEN_RELEASE_ORIGIN__"
if template.count(token) != 1:
    raise SystemExit("install.command release-origin placeholder is invalid")
destination.write_text(template.replace(token, origin), encoding="utf-8")
PY
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
