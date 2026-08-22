#!/bin/bash

set -Eeuo pipefail

readonly DEFAULT_RELEASE_ROOT="/var/www/vgen-releases"
readonly DEFAULT_BACKUP_ROOT="/var/backups/vgen-v1"
readonly DEFAULT_LOCK_PATH="/run/lock/vgen-public-release.lock"

ARCHIVE=""
VERSION=""
DOMAIN=""
CONFIRM_STABLE=0

log() {
  printf '[vgen-release] %s\n' "$*"
}

die() {
  printf '[vgen-release] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Publish an already reviewed VGen public release without restarting Gateway:

  sudo ./publish-release.sh \
    --archive /root/vgen-public-release-0.3.1.tar.gz \
    --version 0.3.1 \
    --domain vgen.example.com

The script validates every archive entry and digest, publishes the immutable
version directory, replaces install-macos.sh, switches stable.json last, then
checks the public HTTPS endpoints. A failed public check restores the channel.

Options:
  --archive PATH       Reviewed vgen-public-release-X.Y.Z.tar.gz
  --version X.Y.Z      Exact immutable release version
  --domain HOST        Existing lowercase download-site DNS hostname
  --confirm-stable     Non-interactive approval of the stable switch
  -h, --help           Show this help
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --archive)
      [[ "$#" -ge 2 ]] || die "--archive requires a value"
      ARCHIVE="$2"
      shift 2
      ;;
    --version)
      [[ "$#" -ge 2 ]] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --domain)
      [[ "$#" -ge 2 ]] || die "--domain requires a value"
      DOMAIN="$2"
      shift 2
      ;;
    --confirm-stable)
      CONFIRM_STABLE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "${ARCHIVE}" ]] || die "--archive is required"
[[ -n "${VERSION}" ]] || die "--version is required"
[[ -n "${DOMAIN}" ]] || die "--domain is required"
[[ "${VERSION}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
  die "--version must use MAJOR.MINOR.PATCH"
[[ "${DOMAIN}" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] || \
  die "--domain must be a lowercase DNS hostname"
[[ -f "${ARCHIVE}" && ! -L "${ARCHIVE}" ]] || die "archive must be a regular file"

TESTING="${VGEN_PUBLISH_TESTING:-0}"
if [[ "${TESTING}" != "1" && "${EUID}" -ne 0 ]]; then
  die "run this publisher as root"
fi
if [[ "${TESTING}" == "1" ]]; then
  RELEASE_ROOT="${VGEN_RELEASE_ROOT_OVERRIDE:?testing requires VGEN_RELEASE_ROOT_OVERRIDE}"
  BACKUP_ROOT="${VGEN_BACKUP_ROOT_OVERRIDE:?testing requires VGEN_BACKUP_ROOT_OVERRIDE}"
  LOCK_PATH="${VGEN_LOCK_PATH_OVERRIDE:?testing requires VGEN_LOCK_PATH_OVERRIDE}"
else
  [[ -z "${VGEN_RELEASE_ROOT_OVERRIDE:-}" ]] || die "release root overrides require test mode"
  RELEASE_ROOT="${DEFAULT_RELEASE_ROOT}"
  BACKUP_ROOT="${DEFAULT_BACKUP_ROOT}"
  LOCK_PATH="${DEFAULT_LOCK_PATH}"
fi
readonly RELEASE_ROOT BACKUP_ROOT LOCK_PATH TESTING

install_managed() {
  if [[ "${TESTING}" == "1" ]]; then
    install "$@"
  else
    install -o root -g root "$@"
  fi
}

if [[ "${CONFIRM_STABLE}" -ne 1 ]]; then
  printf 'Type %s to publish VGen %s and switch stable: ' "${DOMAIN}" "${VERSION}" >/dev/tty
  IFS= read -r answer </dev/tty || die "stable publication was cancelled"
  [[ "${answer}" == "${DOMAIN}" ]] || die "domain confirmation did not match"
fi

for command in cmp curl find flock install mktemp mv python3 tr wc; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is missing: ${command}"
done

[[ ! -L "${RELEASE_ROOT}" && ! -L "${BACKUP_ROOT}" ]] || \
  die "release and backup roots must not be symbolic links"
install -d -m 0755 "${RELEASE_ROOT}"
install -d -m 0700 "${BACKUP_ROOT}"
[[ ! -L "${RELEASE_ROOT}/channels" ]] || die "release channels must not be a symbolic link"
install -d -m 0755 "${RELEASE_ROOT}/channels"
[[ ! -L "${LOCK_PATH}" ]] || die "release lock must not be a symbolic link"

exec 9>"${LOCK_PATH}"
flock -n 9 || die "another public release is currently being published"

UNPACK_DIR="$(mktemp -d "/tmp/vgen-public-release.${VERSION}.XXXXXXXX")"
BACKUP_DIR=""
CHANNEL_CHANGED=0

cleanup() {
  local status="$?"
  if [[ -n "${UNPACK_DIR:-}" && "${UNPACK_DIR}" == /tmp/vgen-public-release.* ]]; then
    rm -rf -- "${UNPACK_DIR}"
  fi
  return "${status}"
}
trap cleanup EXIT

VGEN_ARCHIVE="${ARCHIVE}" \
VGEN_UNPACK_DIR="${UNPACK_DIR}" \
VGEN_RELEASE_VERSION="${VERSION}" \
python3 -I -B <<'PY'
import hashlib
import json
import os
import re
import tarfile
from pathlib import Path, PurePosixPath

archive_path = Path(os.environ["VGEN_ARCHIVE"])
output_root = Path(os.environ["VGEN_UNPACK_DIR"])
version = os.environ["VGEN_RELEASE_VERSION"]
expected = {
    "install-macos.sh",
    "channels/stable.json",
    f"{version}/manifest.json",
    f"{version}/VGen-macOS-{version}.zip",
    f"{version}/vgen-windows-worker-installer-{version}.zip",
}

with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    names = [member.name for member in members]
    if len(names) != len(set(names)) or set(names) != expected:
        raise SystemExit("deployment archive entries do not match the closed allowlist")
    total = 0
    for member in members:
        path = PurePosixPath(member.name)
        if (
            not member.isfile()
            or member.issym()
            or member.islnk()
            or member.name.startswith("/")
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise SystemExit("deployment archive contains an unsafe entry")
        total += member.size
        if member.size <= 0 or total > 4 * 1024**3:
            raise SystemExit("deployment archive size is invalid")
        target = output_root.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("deployment archive entry could not be read")
        with source, target.open("xb") as destination:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                destination.write(block)
        target.chmod(0o755 if member.name == "install-macos.sh" else 0o644)

version_root = output_root / version
manifest_path = version_root / "manifest.json"
manifest_bytes = manifest_path.read_bytes()
manifest = json.loads(manifest_bytes)
if (
    not isinstance(manifest, dict)
    or set(manifest) != {"schema_version", "audience", "version", "published_at", "artifacts"}
    or manifest.get("schema_version") != 1
    or manifest.get("audience") != "public"
    or manifest.get("version") != version
    or not isinstance(manifest.get("artifacts"), list)
):
    raise SystemExit("immutable release manifest is invalid")
expected_artifacts = {
    f"VGen-macOS-{version}.zip",
    f"vgen-windows-worker-installer-{version}.zip",
}
filenames = set()
for artifact in manifest["artifacts"]:
    if not isinstance(artifact, dict):
        raise SystemExit("release artifact metadata is invalid")
    filename = artifact.get("filename")
    if filename not in expected_artifacts or filename in filenames:
        raise SystemExit("release artifact filename is invalid")
    filenames.add(filename)
    path = version_root / filename
    value = path.read_bytes()
    if artifact.get("size") != len(value) or artifact.get("sha256") != hashlib.sha256(value).hexdigest():
        raise SystemExit("release artifact digest or size does not match")
if filenames != expected_artifacts:
    raise SystemExit("release manifest does not contain both public installers")

manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
stable = json.loads((output_root / "channels" / "stable.json").read_bytes())
if stable != {
    "schema_version": 1,
    "channel": "stable",
    "version": version,
    "manifest_sha256": manifest_digest,
}:
    raise SystemExit("stable pointer is not bound to the immutable manifest")

bootstrap = (output_root / "install-macos.sh").read_text(encoding="utf-8")
if not re.search(rf"(?m)^EXPECTED_VERSION={re.escape(version)}$", bootstrap):
    raise SystemExit("macOS bootstrap is not pinned to this release version")
if not re.search(rf"(?m)^EXPECTED_MANIFEST_SHA256={manifest_digest}$", bootstrap):
    raise SystemExit("macOS bootstrap is not pinned to this manifest digest")
print(f"validated public release {version}")
PY

version_files_identical() {
  local destination="${RELEASE_ROOT}/${VERSION}"
  [[ -d "${destination}" && ! -L "${destination}" ]] || return 1
  [[ "$(find "${destination}" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "3" ]] || \
    return 1
  [[ -z "$(find "${destination}" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] || \
    return 1
  cmp -s "${UNPACK_DIR}/${VERSION}/manifest.json" "${destination}/manifest.json" && \
    cmp -s "${UNPACK_DIR}/${VERSION}/VGen-macOS-${VERSION}.zip" \
      "${destination}/VGen-macOS-${VERSION}.zip" && \
    cmp -s "${UNPACK_DIR}/${VERSION}/vgen-windows-worker-installer-${VERSION}.zip" \
      "${destination}/vgen-windows-worker-installer-${VERSION}.zip"
}

if [[ -e "${RELEASE_ROOT}/${VERSION}" ]]; then
  version_files_identical || die "immutable release ${VERSION} already exists with different bytes"
  log "immutable release ${VERSION} already exists with identical bytes"
else
  VERSION_STAGE="$(mktemp -d "${RELEASE_ROOT}/.${VERSION}.staging.XXXXXXXX")"
  install_managed -m 0644 "${UNPACK_DIR}/${VERSION}/manifest.json" \
    "${VERSION_STAGE}/manifest.json"
  install_managed -m 0644 \
    "${UNPACK_DIR}/${VERSION}/VGen-macOS-${VERSION}.zip" \
    "${VERSION_STAGE}/VGen-macOS-${VERSION}.zip"
  install_managed -m 0644 \
    "${UNPACK_DIR}/${VERSION}/vgen-windows-worker-installer-${VERSION}.zip" \
    "${VERSION_STAGE}/vgen-windows-worker-installer-${VERSION}.zip"
  chmod 0755 "${VERSION_STAGE}"
  VGEN_VERSION_STAGE="${VERSION_STAGE}" \
  VGEN_VERSION_DESTINATION="${RELEASE_ROOT}/${VERSION}" \
    python3 -I -B <<'PY'
import os
from pathlib import Path

source = Path(os.environ["VGEN_VERSION_STAGE"])
destination = Path(os.environ["VGEN_VERSION_DESTINATION"])
if destination.exists() or destination.is_symlink():
    raise SystemExit("immutable release destination appeared during publication")
os.rename(source, destination)
PY
  log "published immutable release ${VERSION}"
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$(mktemp -d "${BACKUP_ROOT}/release-channel-${stamp}.XXXXXXXX")"
if [[ -f "${RELEASE_ROOT}/install-macos.sh" && ! -L "${RELEASE_ROOT}/install-macos.sh" ]]; then
  install -m 0755 "${RELEASE_ROOT}/install-macos.sh" "${BACKUP_DIR}/install-macos.sh"
else
  : >"${BACKUP_DIR}/install-macos.sh.absent"
fi
if [[ -f "${RELEASE_ROOT}/channels/stable.json" && \
      ! -L "${RELEASE_ROOT}/channels/stable.json" ]]; then
  install -m 0644 "${RELEASE_ROOT}/channels/stable.json" "${BACKUP_DIR}/stable.json"
else
  : >"${BACKUP_DIR}/stable.json.absent"
fi

restore_channel() {
  set +e
  if [[ -f "${BACKUP_DIR}/install-macos.sh" ]]; then
    install_managed -m 0755 "${BACKUP_DIR}/install-macos.sh" \
      "${RELEASE_ROOT}/.install-macos.sh.rollback"
    mv -f "${RELEASE_ROOT}/.install-macos.sh.rollback" \
      "${RELEASE_ROOT}/install-macos.sh"
  else
    rm -f -- "${RELEASE_ROOT}/install-macos.sh"
  fi
  if [[ -f "${BACKUP_DIR}/stable.json" ]]; then
    install_managed -m 0644 "${BACKUP_DIR}/stable.json" \
      "${RELEASE_ROOT}/channels/.stable.json.rollback"
    mv -f "${RELEASE_ROOT}/channels/.stable.json.rollback" \
      "${RELEASE_ROOT}/channels/stable.json"
  else
    rm -f -- "${RELEASE_ROOT}/channels/stable.json"
  fi
  log "restored the previous public release channel"
}

handle_failure() {
  local status="$1"
  if [[ "${CHANNEL_CHANGED}" -eq 1 ]]; then
    restore_channel
  fi
  exit "${status}"
}
trap 'handle_failure $?' ERR
trap 'handle_failure 130' INT
trap 'handle_failure 143' TERM

BOOTSTRAP_STAGE="$(mktemp "${RELEASE_ROOT}/.install-macos.sh.XXXXXXXX")"
install_managed -m 0755 \
  "${UNPACK_DIR}/install-macos.sh" "${BOOTSTRAP_STAGE}"
mv -f "${BOOTSTRAP_STAGE}" "${RELEASE_ROOT}/install-macos.sh"
CHANNEL_CHANGED=1

STABLE_STAGE="$(mktemp "${RELEASE_ROOT}/channels/.stable.json.XXXXXXXX")"
install_managed -m 0644 \
  "${UNPACK_DIR}/channels/stable.json" "${STABLE_STAGE}"
mv -f "${STABLE_STAGE}" "${RELEASE_ROOT}/channels/stable.json"
log "stable pointer switched to ${VERSION}"

if [[ "${TESTING}" != "1" || "${VGEN_SKIP_PUBLIC_CHECK:-0}" != "1" ]]; then
  STABLE_RESPONSE="$(mktemp "/tmp/vgen-stable-response.${VERSION}.XXXXXXXX")"
  curl --fail --silent --show-error --max-time 20 \
    "https://${DOMAIN}/releases/channels/stable.json" >"${STABLE_RESPONSE}"
  VGEN_STABLE_RESPONSE="${STABLE_RESPONSE}" VGEN_RELEASE_VERSION="${VERSION}" \
    python3 -I -B <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(Path(os.environ["VGEN_STABLE_RESPONSE"]).read_bytes())
if (
    not isinstance(payload, dict)
    or set(payload) != {"schema_version", "channel", "version", "manifest_sha256"}
    or payload.get("version") != os.environ["VGEN_RELEASE_VERSION"]
):
    raise SystemExit("public stable pointer did not switch to the requested version")
PY
  rm -f -- "${STABLE_RESPONSE}"
  curl --fail --silent --show-error --max-time 20 --range 0-0 --output /dev/null \
    "https://${DOMAIN}/releases/install-macos.sh"
  curl --fail --silent --show-error --max-time 20 --range 0-0 --output /dev/null \
    "https://${DOMAIN}/releases/${VERSION}/manifest.json"
  curl --fail --silent --show-error --max-time 20 --range 0-0 --output /dev/null \
    "https://${DOMAIN}/releases/${VERSION}/VGen-macOS-${VERSION}.zip"
  curl --fail --silent --show-error --max-time 20 --range 0-0 --output /dev/null \
    "https://${DOMAIN}/releases/${VERSION}/vgen-windows-worker-installer-${VERSION}.zip"
fi

trap - ERR INT TERM
log "public release ${VERSION} completed"
log "channel backup: ${BACKUP_DIR}"
