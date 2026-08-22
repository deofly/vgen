#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
INSTALL_BASE="${HOME}/Library/Application Support/VGen/cli"
LAUNCHER_DIR="${HOME}/.local/bin"
LAUNCHER_PATH="${LAUNCHER_DIR}/vgen"
INSTALL_ONLY=0
RELEASE_ORIGIN="__VGEN_RELEASE_ORIGIN__"

if [[ "${1:-}" == "--install-only" ]]; then
  INSTALL_ONLY=1
  shift
fi

fail() {
  printf '\nVGen 安装未完成：%s\n' "$1" >&2
  exit 1
}

WHEEL_CANDIDATES=()
for candidate in "${SCRIPT_DIR}"/vgen-*-py3-none-any.whl; do
  [[ -e "${candidate}" || -L "${candidate}" ]] || continue
  WHEEL_CANDIDATES+=("${candidate}")
done
if [[ "${#WHEEL_CANDIDATES[@]}" -ne 1 ]]; then
  fail "安装包必须包含且只能包含一个 VGen CLI 文件，请删除整个下载文件夹后重新下载。"
fi
WHEEL_PATH="${WHEEL_CANDIDATES[0]}"
WHEEL_NAME="$(basename "${WHEEL_PATH}")"
MANIFEST_PATH="${SCRIPT_DIR}/SHA256SUMS"
if [[ ! -f "${WHEEL_PATH}" || -L "${WHEEL_PATH}" || \
      ! -f "${MANIFEST_PATH}" || -L "${MANIFEST_PATH}" ]]; then
  fail "安装包不完整或包含不安全的文件，请删除整个下载文件夹后重新下载。"
fi

PYTHON_BIN=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
  if ! command -v "${candidate}" >/dev/null 2>&1; then
    continue
  fi
  if "${candidate}" -I -B -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
    >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "${candidate}")"
    break
  fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
  fail "需要 Python 3.11 或更高版本。请从 python.org 安装 macOS 版 Python，然后重新双击本文件。"
fi

if ! VERSION="$(VGEN_RELEASE_ROOT="${SCRIPT_DIR}" \
  VGEN_WHEEL_PATH="${WHEEL_PATH}" \
  VGEN_MANIFEST_PATH="${MANIFEST_PATH}" "${PYTHON_BIN}" -I -B <<'PY'
import hashlib
import os
import re
import zipfile
from email.parser import Parser
from pathlib import Path

root = Path(os.environ["VGEN_RELEASE_ROOT"])
wheel = Path(os.environ["VGEN_WHEEL_PATH"])
manifest = Path(os.environ["VGEN_MANIFEST_PATH"])
expected_names = {"README.md", "install.command", wheel.name}
gateway_default = root / "gateway-default.txt"
if gateway_default.exists() or gateway_default.is_symlink():
    expected_names.add(gateway_default.name)

entries = {}
try:
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
        if match is None or match.group(2) in entries:
            raise SystemExit("invalid release manifest")
        entries[match.group(2)] = match.group(1)
except (OSError, UnicodeDecodeError) as exc:
    raise SystemExit("unreadable release manifest") from exc
if set(entries) != expected_names:
    raise SystemExit("unexpected release manifest entries")
for name, expected in entries.items():
    path = root / name
    if path.parent != root or path.is_symlink() or not path.is_file():
        raise SystemExit("unsafe release file")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit("release file hash mismatch")

try:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise SystemExit("duplicate wheel path")
        if any(
            name.startswith(("/", "\\"))
            or ".." in Path(name.replace("\\", "/")).parts
            for name in names
        ):
            raise SystemExit("unsafe wheel path")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise SystemExit("incomplete wheel metadata")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
    raise SystemExit("unreadable wheel") from exc

version = metadata.get("Version", "")
if metadata.get("Name", "").casefold() != "vgen":
    raise SystemExit("unexpected distribution")
if re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None:
    raise SystemExit("invalid product version")
if wheel.name != f"vgen-{version}-py3-none-any.whl":
    raise SystemExit("wheel filename and metadata version differ")
if "Tag: py3-none-any" not in wheel_metadata.splitlines():
    raise SystemExit("unexpected wheel tag")
print(version)
PY
)"; then
  fail "CLI 文件校验失败，请删除整个下载文件夹后重新下载。"
fi

WHEEL_SHA256="$(shasum -a 256 "${WHEEL_PATH}" | awk '{print $1}')"
RELEASE_DIR="${INSTALL_BASE}/releases/${VERSION}-${WHEEL_SHA256:0:12}"
MARKER_PATH="${RELEASE_DIR}/.vgen-managed-install"

mkdir -p "${INSTALL_BASE}/releases"
if [[ -e "${RELEASE_DIR}" ]]; then
  if [[ ! -f "${MARKER_PATH}" ]] || \
    [[ "$(<"${MARKER_PATH}")" != "${WHEEL_SHA256}" ]] || \
    [[ ! -x "${RELEASE_DIR}/bin/vgen" ]]; then
    fail "发现一个无法确认归属的安装目录，不会覆盖：${RELEASE_DIR}"
  fi
else
  "${PYTHON_BIN}" -I -B -m venv "${RELEASE_DIR}"
  if ! "${RELEASE_DIR}/bin/python" -I -B -m pip install --disable-pip-version-check "${WHEEL_PATH}"; then
    fail "Python 依赖安装失败。请确认网络可访问 PyPI，然后重新运行。"
  fi
  printf '%s' "${WHEEL_SHA256}" >"${MARKER_PATH}"
  chmod 600 "${MARKER_PATH}"
fi

# The release origin is independent from every Gateway Profile. A built bundle
# replaces the placeholder with the reviewed HTTPS download origin. Keeping it
# in a separate 0600 file lets `vgen upgrade` remain pinned when a Gateway
# endpoint moves to another domain.
if [[ "${RELEASE_ORIGIN}" != "__VGEN_RELEASE_ORIGIN__" ]]; then
  RELEASE_SOURCE_PATH="${INSTALL_BASE}/release-source.json"
  VGEN_RELEASE_SOURCE_PATH="${RELEASE_SOURCE_PATH}" \
  VGEN_RELEASE_ORIGIN_VALUE="${RELEASE_ORIGIN}" "${PYTHON_BIN}" -I -B <<'PY'
import json
import os
import tempfile
from pathlib import Path

path = Path(os.environ["VGEN_RELEASE_SOURCE_PATH"])
origin = os.environ["VGEN_RELEASE_ORIGIN_VALUE"]
expected = {"schema_version": 1, "release_origin": origin}
path.parent.mkdir(parents=True, exist_ok=True)
if path.exists() or path.is_symlink():
    if path.is_symlink() or not path.is_file():
        raise SystemExit("unsafe managed release-source path")
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("unreadable managed release source") from exc
    if current != expected:
        raise SystemExit("managed release origin differs from this reviewed installer")
else:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".release-source-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(expected, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
PY
fi

VGEN_BIN="${RELEASE_DIR}/bin/vgen"
mkdir -p "${LAUNCHER_DIR}"
if [[ -e "${LAUNCHER_PATH}" || -L "${LAUNCHER_PATH}" ]]; then
  SAFE_EXISTING=0
  if [[ -L "${LAUNCHER_PATH}" ]]; then
    EXISTING_TARGET="$(readlink "${LAUNCHER_PATH}")"
    case "${EXISTING_TARGET}" in
      "${INSTALL_BASE}"/releases/*/bin/vgen)
        EXISTING_RELEASE="${EXISTING_TARGET%/bin/vgen}"
        if [[ -f "${EXISTING_RELEASE}/.vgen-managed-install" ]]; then
          SAFE_EXISTING=1
        fi
        ;;
    esac
  fi
  if [[ "${SAFE_EXISTING}" == "1" ]]; then
    ln -sfn "${VGEN_BIN}" "${LAUNCHER_PATH}"
  elif [[ "${LAUNCHER_PATH}" != "${VGEN_BIN}" ]]; then
    printf '提示：%s 已存在且不是 VGen 管理的文件，因此未覆盖。\n' "${LAUNCHER_PATH}" >&2
  fi
else
  ln -s "${VGEN_BIN}" "${LAUNCHER_PATH}"
fi

printf '\n✓ VGen CLI %s 已安装\n' "${VERSION}"
printf '  命令位置：%s\n' "${VGEN_BIN}"

if [[ "${INSTALL_ONLY}" == "1" ]]; then
  printf '\n稍后初始化："%s" setup\n' "${VGEN_BIN}"
  exit 0
fi

# A reviewed CLI upgrade must not create a second identity or ask for another
# bootstrap code. `profile show` is a local, read-only check; it does not open a
# Gateway session or read private key material from Keychain.
if "${RELEASE_DIR}/bin/python" -I -B "${VGEN_BIN}" profile show >/dev/null 2>&1; then
  printf '\n✓ 已保留现有 VGen 身份、Gateway Profile 和 Home Broker 配置\n'
  if ! "${RELEASE_DIR}/bin/python" -I -B "${VGEN_BIN}" broker service-refresh; then
    fail "CLI 已安装，但 Home Broker 未能切换到新版本。请查看上方错误后重新运行。"
  fi
  printf '  CLI 和 Home Broker 升级完成，不需要重新输入恢复词或 Bootstrap code。\n'
  exit 0
fi

SETUP_ARGS=(setup)
GATEWAY_DEFAULT="${SCRIPT_DIR}/gateway-default.txt"
if [[ -f "${GATEWAY_DEFAULT}" && ! -L "${GATEWAY_DEFAULT}" ]]; then
  GATEWAY_URL="$(tr -d '[:space:]' <"${GATEWAY_DEFAULT}")"
  if [[ -n "${GATEWAY_URL}" ]]; then
    SETUP_ARGS+=(--gateway "${GATEWAY_URL}")
  fi
fi

"${RELEASE_DIR}/bin/python" -I -B "${VGEN_BIN}" "${SETUP_ARGS[@]}" "$@"
