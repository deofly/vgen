#!/usr/bin/env bash
# Install VGen Gateway next to a legacy deployment, then switch Nginx only
# after the new service is healthy. This script intentionally never changes
# OSS/IAM policy. Test reset archives only explicitly managed Gateway paths.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SERVICE_NAME="vgen-gateway.service"
readonly MANIFEST_NAME="SHA256SUMS"
readonly INSTALL_ROOT="/opt/vgen"
readonly DATA_ROOT="/var/lib/vgen"
readonly RELEASE_ROOT="/var/www/vgen-releases"
readonly CONFIG_ROOT="/etc/vgen"
readonly BACKUP_ROOT="/var/backups/vgen"
readonly LEGACY_V1_INSTALL_ROOT="/opt/vgen-v1"
readonly LEGACY_V1_DATA_ROOT="/var/lib/vgen-v1"
readonly LEGACY_V1_CONFIG_ROOT="/etc/vgen-v1"
readonly LEGACY_V1_BACKUP_ROOT="/var/backups/vgen-v1"
readonly DATABASE_PATH="${DATA_ROOT}/vgen-gateway.db"
readonly BOOTSTRAP_PATH="${DATA_ROOT}/bootstrap-code"
readonly ENVIRONMENT_PATH="${CONFIG_ROOT}/gateway.env"
readonly UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
readonly NGINX_CONFIG_PATH="/etc/nginx/conf.d/vgen.conf"
readonly INSTALL_STATE_PATH="${CONFIG_ROOT}/install-state.json"
readonly LEGACY_DATABASE_DEFAULT="/opt/vgen/server/data/vgen.db"
readonly LEGACY_GATEWAY_BRIDGE_VERSION="2.0.0a1"
readonly GATEWAY_PORT="8010"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VGEN_VERSION=""
WHEEL_NAME=""
WHEEL_PATH=""
SERVICE_SOURCE_PATH="${SCRIPT_DIR}/${SERVICE_NAME}"
MANIFEST_PATH="${SCRIPT_DIR}/${MANIFEST_NAME}"

ACTION=""
DOMAIN=""
CONFIRM_DOMAIN=""
CONFIRM_NO_ACTIVE_TASKS=0
CONFIRM_ROLLBACK=0
CONFIRM_ACTIVATE=0
CONFIRM_UPGRADE=0
CONFIRM_RESET_TEST=0
ARTIFACT_STORE="oss"
OSS_ENDPOINT=""
OSS_BUCKET=""
OSS_PREFIX="vgen/v1"
OSS_ECS_ROLE=""
OSS_ACCOUNT_ID=""
OSS_TRANSFER_ROLE="VGenArtifactTransferRole"
OSS_STS_REGION=""
OSS_STS_DURATION_SECONDS="900"
CONFIRM_OSS_CONFIGURED=0
LEGACY_DATABASE_PATH="${LEGACY_DATABASE_DEFAULT}"
NGINX_ROLLBACK_BACKUP=""
NGINX_GENERATED_PATH=""
NGINX_REPLACED=0
ACTIVATION_ALREADY_ACTIVE=0
ACTIVATION_BACKUP_PATH=""
INSTALLED_VGEN_VERSION=""
UPGRADE_ALREADY_TARGET=0
UPGRADE_BACKUP_DIR=""
UPGRADE_CANDIDATE_RUNTIME=""
UPGRADE_PREVIOUS_RUNTIME=""
UPGRADE_DATABASE_BACKUP=""
UPGRADE_CONFIG_BACKED_UP=0
UPGRADE_OLD_RUNTIME_MOVED=0
UPGRADE_NGINX_REPLACED=0
LAYOUT_MIGRATION_BACKUP_DIR=""
LAYOUT_INSTALL_MOVED=0
LAYOUT_DATA_MOVED=0
LAYOUT_CONFIG_MOVED=0
LAYOUT_BACKUP_MOVED=0
LAYOUT_USER_HOME_MOVED=0
LAYOUT_UNIT_REPLACED=0

usage() {
  cat <<'EOF'
VGen Gateway safe installer

The release bundle must contain these files in the same directory:
  setup-gateway.sh
  exactly one vgen-<version>-py3-none-any.whl
  vgen-gateway.service
  SHA256SUMS

Install and switch HTTPS traffic:
  sudo ./setup-gateway.sh install \
    --domain vgen.example.com \
    --artifact-store oss \
    --oss-endpoint https://oss-cn-hangzhou.aliyuncs.com \
    --oss-bucket vgen-private \
    --oss-prefix vgen/v1 \
    --oss-ecs-role VGenGatewayRole \
    --aliyun-account-id 1234567890123456 \
    --oss-transfer-role VGenArtifactTransferRole

Resume only the installer-created partial state (runtime and environment exist,
but database, Bootstrap code, systemd unit and Nginx state do not):
  sudo ./setup-gateway.sh resume --domain vgen.example.com

Activate a fully healthy Gateway after a previous Nginx switch rolled back:
  sudo ./setup-gateway.sh activate --domain vgen.example.com

Upgrade an active Gateway in place using the reviewed release bundle:
  sudo ./setup-gateway.sh upgrade --domain vgen.example.com

Archive an existing development/test Gateway before initializing it again:
  sudo ./setup-gateway.sh reset-test --domain vgen.example.com

The interactive installer asks you to re-enter the domain and confirm that old
tasks have finished. For non-interactive automation, use explicit flags:
  sudo ./setup-gateway.sh install \
    --domain vgen.example.com \
    --confirm-domain vgen.example.com \
    --confirm-no-active-tasks \
    --artifact-store oss \
    --oss-endpoint https://oss-cn-hangzhou.aliyuncs.com \
    --oss-bucket vgen-private \
    --oss-prefix vgen/v1 \
    --oss-ecs-role VGenGatewayRole \
    --aliyun-account-id 1234567890123456 \
    --oss-transfer-role VGenArtifactTransferRole \
    --confirm-oss-configured

Non-interactive activation additionally requires --confirm-activate.
Non-interactive upgrade additionally requires --confirm-upgrade.
Non-interactive test reset additionally requires --confirm-reset-test and
--confirm-no-active-tasks.

Show current service and endpoint status:
  sudo ./setup-gateway.sh status --domain vgen.example.com

Route Nginx back to the saved legacy configuration:
  sudo ./setup-gateway.sh rollback \
    --domain vgen.example.com \
    --confirm-domain vgen.example.com \
    --confirm-rollback

Options:
  --confirm-upgrade      Explicitly approve an in-place Gateway upgrade.
  --artifact-store TYPE  Task media must use oss. Release files remain local.
  --oss-endpoint URL     HTTPS Alibaba Cloud OSS endpoint.
  --oss-bucket NAME      Private bucket containing encrypted task artifacts.
  --oss-prefix PREFIX    Object key prefix. Default: vgen/v1.
  --oss-ecs-role NAME    ECS RAM Role used for temporary credentials. AccessKey
                         values are intentionally not accepted by this installer.
  --aliyun-account-id ID Alibaba Cloud account ID that owns both RAM roles.
  --oss-transfer-role NAME  RAM Role assumed for one-object OSS STS access.
  --sts-region REGION    STS region. Defaults to the region in the OSS endpoint.
  --oss-sts-duration N   STS lifetime in seconds, 900..3600. Default: 900.
  --confirm-oss-configured  Confirm the generated RAM/OSS setup checklist is done.
  --legacy-database PATH  Legacy SQLite database to back up before install.
                          Default: /opt/vgen/server/data/vgen.db

Safety properties:
  * The domain must be provided twice and match exactly.
  * install requires an explicit confirmation that no task is active.
  * the legacy SQLite database is backed up with SQLite's online backup API.
  * the v1 service is checked on 127.0.0.1:8010 before Nginx is changed.
  * HTTPS health retries for at most 30 seconds before restoring the legacy route.
  * upgrade keeps a WAL-consistent database snapshot and the previous runtime/config.
  * a failed upgrade restores the previous database, runtime and service configuration.
  * the legacy pre-v1 service is not stopped or deleted.
  * local task-media storage is prohibited; release downloads remain on ECS.
  * OSS mode uses only an ECS RAM Role and a private bucket; IAM is never modified.
EOF
}

log() {
  printf '[vgen-gateway] %s\n' "$*"
}

warn() {
  printf '[vgen-gateway] WARNING: %s\n' "$*" >&2
}

die() {
  printf '[vgen-gateway] ERROR: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local option="$1"
  local value="${2:-}"
  [[ -n "${value}" && "${value}" != --* ]] || die "${option} requires a value"
}

parse_arguments() {
  [[ $# -gt 0 ]] || {
    usage
    exit 2
  }

  case "$1" in
    install|resume|activate|upgrade|reset-test|status|rollback)
      ACTION="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown action '$1'; expected install, resume, activate, upgrade, reset-test, status, or rollback"
      ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain)
        require_value "$1" "${2:-}"
        DOMAIN="$2"
        shift 2
        ;;
      --confirm-domain)
        require_value "$1" "${2:-}"
        CONFIRM_DOMAIN="$2"
        shift 2
        ;;
      --confirm-no-active-tasks)
        CONFIRM_NO_ACTIVE_TASKS=1
        shift
        ;;
      --confirm-rollback)
        CONFIRM_ROLLBACK=1
        shift
        ;;
      --confirm-activate)
        CONFIRM_ACTIVATE=1
        shift
        ;;
      --confirm-upgrade)
        CONFIRM_UPGRADE=1
        shift
        ;;
      --confirm-reset-test)
        CONFIRM_RESET_TEST=1
        shift
        ;;
      --artifact-store)
        require_value "$1" "${2:-}"
        ARTIFACT_STORE="$2"
        shift 2
        ;;
      --oss-endpoint)
        require_value "$1" "${2:-}"
        OSS_ENDPOINT="$2"
        shift 2
        ;;
      --oss-bucket)
        require_value "$1" "${2:-}"
        OSS_BUCKET="$2"
        shift 2
        ;;
      --oss-prefix)
        require_value "$1" "${2:-}"
        OSS_PREFIX="$2"
        shift 2
        ;;
      --oss-ecs-role)
        require_value "$1" "${2:-}"
        OSS_ECS_ROLE="$2"
        shift 2
        ;;
      --aliyun-account-id)
        require_value "$1" "${2:-}"
        OSS_ACCOUNT_ID="$2"
        shift 2
        ;;
      --oss-transfer-role)
        require_value "$1" "${2:-}"
        OSS_TRANSFER_ROLE="$2"
        shift 2
        ;;
      --sts-region)
        require_value "$1" "${2:-}"
        OSS_STS_REGION="$2"
        shift 2
        ;;
      --oss-sts-duration)
        require_value "$1" "${2:-}"
        OSS_STS_DURATION_SECONDS="$2"
        shift 2
        ;;
      --confirm-oss-configured)
        CONFIRM_OSS_CONFIGURED=1
        shift
        ;;
      --legacy-database)
        require_value "$1" "${2:-}"
        LEGACY_DATABASE_PATH="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option '$1'"
        ;;
    esac
  done
}

validate_domain() {
  [[ -n "${DOMAIN}" ]] || die "--domain is required"
  [[ ${#DOMAIN} -le 253 ]] || die "domain is too long"
  [[ "${DOMAIN}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || \
    die "domain must be a valid lowercase DNS hostname, not a URL or IP address"
}

validate_confirmation() {
  [[ -n "${CONFIRM_DOMAIN}" ]] || die "--confirm-domain is required for ${ACTION}"
  [[ "${CONFIRM_DOMAIN}" == "${DOMAIN}" ]] || \
    die "--confirm-domain must exactly match --domain"
}

validate_artifact_store_options() {
  [[ "${ARTIFACT_STORE}" == "oss" ]] || \
    die "--artifact-store must be oss; local artifact storage is prohibited"
  [[ "${OSS_ENDPOINT}" =~ ^https://[A-Za-z0-9.-]+$ ]] || \
    die "--oss-endpoint must be a credential-free HTTPS origin"
  [[ "${OSS_BUCKET}" =~ ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ ]] || \
    die "--oss-bucket is invalid"
  [[ "${OSS_PREFIX}" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || \
    die "--oss-prefix is invalid"
  [[ "${OSS_ECS_ROLE}" =~ ^[A-Za-z0-9_.@-]{1,128}$ ]] || \
    die "--oss-ecs-role is required and invalid"
  [[ "${OSS_ACCOUNT_ID}" =~ ^[0-9]{8,24}$ ]] || \
    die "--aliyun-account-id is required and invalid"
  [[ "${OSS_TRANSFER_ROLE}" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || \
    die "--oss-transfer-role is invalid"
  if [[ -z "${OSS_STS_REGION}" ]]; then
    OSS_STS_REGION="$(sed -E 's#^https://oss-([a-z0-9-]+)\..*$#\1#' <<<"${OSS_ENDPOINT}")"
  fi
  [[ "${OSS_STS_REGION}" =~ ^[a-z0-9-]{2,64}$ ]] || die "--sts-region is invalid"
  [[ "${OSS_STS_DURATION_SECONDS}" =~ ^[0-9]+$ ]] || die "--oss-sts-duration is invalid"
  (( OSS_STS_DURATION_SECONDS >= 900 && OSS_STS_DURATION_SECONDS <= 3600 )) || \
    die "--oss-sts-duration must be between 900 and 3600"
}

collect_interactive_oss_options() {
  [[ "${ACTION}" == "install" ]] || return 0
  if [[ -n "${OSS_ENDPOINT}" && -n "${OSS_BUCKET}" && -n "${OSS_ECS_ROLE}" && -n "${OSS_ACCOUNT_ID}" ]]; then
    return 0
  fi
  [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || return 0
  if [[ -z "${OSS_ENDPOINT}" ]]; then
    printf 'OSS HTTPS endpoint (for example https://oss-cn-hangzhou.aliyuncs.com): ' >/dev/tty
    IFS= read -r OSS_ENDPOINT </dev/tty || die "OSS configuration was cancelled"
  fi
  if [[ -z "${OSS_BUCKET}" ]]; then
    printf 'Private OSS bucket name for encrypted task artifacts: ' >/dev/tty
    IFS= read -r OSS_BUCKET </dev/tty || die "OSS configuration was cancelled"
  fi
  if [[ -z "${OSS_ECS_ROLE}" ]]; then
    printf 'RAM Role name attached to this ECS instance: ' >/dev/tty
    IFS= read -r OSS_ECS_ROLE </dev/tty || die "OSS configuration was cancelled"
  fi
  if [[ -z "${OSS_ACCOUNT_ID}" ]]; then
    printf 'Alibaba Cloud account ID that owns the ECS and RAM roles: ' >/dev/tty
    IFS= read -r OSS_ACCOUNT_ID </dev/tty || die "OSS configuration was cancelled"
  fi
  printf 'OSS transfer RAM Role [%s]: ' "${OSS_TRANSFER_ROLE}" >/dev/tty
  local entered_transfer_role=""
  IFS= read -r entered_transfer_role </dev/tty || die "OSS configuration was cancelled"
  [[ -z "${entered_transfer_role}" ]] || OSS_TRANSFER_ROLE="${entered_transfer_role}"
}

write_oss_setup_kit() {
  local setup_root="/var/tmp/vgen-oss-setup-${DOMAIN}"
  [[ ! -L "${setup_root}" ]] || die "OSS setup path must not be a symbolic link"
  install -d -o root -g root -m 0700 "${setup_root}"
  VGEN_SETUP_ROOT="${setup_root}" \
  VGEN_SETUP_DOMAIN="${DOMAIN}" \
  VGEN_SETUP_OSS_ENDPOINT="${OSS_ENDPOINT}" \
  VGEN_SETUP_OSS_BUCKET="${OSS_BUCKET}" \
  VGEN_SETUP_OSS_PREFIX="${OSS_PREFIX}" \
  VGEN_SETUP_OSS_ECS_ROLE="${OSS_ECS_ROLE}" \
  VGEN_SETUP_OSS_ACCOUNT_ID="${OSS_ACCOUNT_ID}" \
  VGEN_SETUP_OSS_TRANSFER_ROLE="${OSS_TRANSFER_ROLE}" \
  VGEN_SETUP_STS_REGION="${OSS_STS_REGION}" \
  VGEN_SETUP_STS_DURATION="${OSS_STS_DURATION_SECONDS}" python3.11 <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["VGEN_SETUP_ROOT"])
account = os.environ["VGEN_SETUP_OSS_ACCOUNT_ID"]
caller_role = os.environ["VGEN_SETUP_OSS_ECS_ROLE"]
transfer_role = os.environ["VGEN_SETUP_OSS_TRANSFER_ROLE"]
bucket = os.environ["VGEN_SETUP_OSS_BUCKET"]
prefix = os.environ["VGEN_SETUP_OSS_PREFIX"]
caller_arn = f"acs:ram::{account}:role/{caller_role}"
transfer_arn = f"acs:ram::{account}:role/{transfer_role}"

documents = {
    "01-ecs-role-assume-policy.json": {
        "Version": "1",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": transfer_arn}],
    },
    "02-transfer-role-trust-policy.json": {
        "Version": "1",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"RAM": [caller_arn]},
            "Action": "sts:AssumeRole",
        }],
    },
    "03-transfer-role-oss-policy.json": {
        "Version": "1",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["oss:GetObject", "oss:PutObject", "oss:AbortMultipartUpload", "oss:ListParts"],
            "Resource": f"acs:oss:*:*:{bucket}/{prefix}/*",
        }],
    },
}
for name, value in documents.items():
    (root / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

env = "\n".join([
    "VGEN_ARTIFACT_STORE=oss",
    f"VGEN_OSS_ENDPOINT={os.environ['VGEN_SETUP_OSS_ENDPOINT']}",
    f"VGEN_OSS_BUCKET={bucket}",
    f"VGEN_OSS_PREFIX={prefix}",
    f"VGEN_OSS_TRANSFER_ROLE_ARN={transfer_arn}",
    f"VGEN_OSS_STS_DURATION_SECONDS={os.environ['VGEN_SETUP_STS_DURATION']}",
    f"VGEN_STS_REGION={os.environ['VGEN_SETUP_STS_REGION']}",
    "VGEN_STS_ENDPOINT=sts.aliyuncs.com",
]) + "\n"
(root / "gateway-oss.env.example").write_text(env)

readme = f"""VGen Gateway OSS initialization checklist

This kit was generated for https://{os.environ['VGEN_SETUP_DOMAIN']}.
It contains no AccessKey or other secret.

1. Create or select private OSS bucket: {bucket}
   Endpoint: {os.environ['VGEN_SETUP_OSS_ENDPOINT']}
   Keep public access blocked. VGen stores encrypted task artifacts under: {prefix}/
2. Attach 01-ecs-role-assume-policy.json to ECS role: {caller_role}
3. Create RAM role: {transfer_role}
4. Set its trust policy to 02-transfer-role-trust-policy.json
5. Attach 03-transfer-role-oss-policy.json to that transfer role
6. Attach ECS role {caller_role} to this Gateway ECS instance.
7. Configure OSS lifecycle rules for prefix {prefix}/ according to your retention policy,
   and enable cleanup of incomplete multipart uploads. Do not enable public read/write.
8. Rerun the same install command with --confirm-oss-configured.

At runtime Gateway uses its ECS role only to call STS AssumeRole. Each returned token
is further restricted to one object and one transfer direction. CLI/Worker transfers
task bytes directly with OSS. Gateway uses HEAD only to confirm object size.
"""
(root / "README.txt").write_text(readme)
for path in root.iterdir():
    path.chmod(0o600)
PY
  log "generated deployer-specific OSS/RAM setup kit: ${setup_root}"
  log "read it with: sudo less ${setup_root}/README.txt"
  if [[ "${CONFIRM_OSS_CONFIGURED}" -ne 1 ]]; then
    log "configure Alibaba Cloud with that kit, then rerun with --confirm-oss-configured"
    exit 3
  fi
}

collect_interactive_confirmations() {
  local answer=""
  if [[ -z "${CONFIRM_DOMAIN}" ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive ${ACTION} requires --confirm-domain ${DOMAIN}"
    printf 'Please re-enter the Gateway domain to confirm [%s]: ' "${DOMAIN}" >/dev/tty
    IFS= read -r CONFIRM_DOMAIN </dev/tty || die "domain confirmation was cancelled"
  fi
  validate_confirmation

  if [[ ("${ACTION}" == "install" || "${ACTION}" == "resume" || "${ACTION}" == "reset-test") && "${CONFIRM_NO_ACTIVE_TASKS}" -ne 1 ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive ${ACTION} requires --confirm-no-active-tasks"
    printf 'Have all old tasks finished and has the old Worker been stopped? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die "active-task confirmation was cancelled"
    case "${answer}" in
      y|Y|yes|YES|Yes)
        CONFIRM_NO_ACTIVE_TASKS=1
        ;;
      *)
        die "installation cancelled; finish old tasks and stop the old Worker first"
        ;;
    esac
  fi

  if [[ "${ACTION}" == "rollback" && "${CONFIRM_ROLLBACK}" -ne 1 ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive rollback requires --confirm-rollback"
    printf 'Route public traffic back to the saved legacy service? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die "rollback confirmation was cancelled"
    case "${answer}" in
      y|Y|yes|YES|Yes)
        CONFIRM_ROLLBACK=1
        ;;
      *)
        die "rollback cancelled"
        ;;
    esac
  fi

  if [[ "${ACTION}" == "activate" && "${CONFIRM_ACTIVATE}" -ne 1 ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive activate requires --confirm-activate"
    printf 'Activate public HTTPS traffic on Gateway v1 now? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die "activation confirmation was cancelled"
    case "${answer}" in
      y|Y|yes|YES|Yes)
        CONFIRM_ACTIVATE=1
        ;;
      *)
        die "activation cancelled"
        ;;
    esac
  fi

  if [[ "${ACTION}" == "upgrade" && "${CONFIRM_UPGRADE}" -ne 1 ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive upgrade requires --confirm-upgrade"
    printf 'Upgrade the active Gateway using this reviewed release bundle now? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die "upgrade confirmation was cancelled"
    case "${answer}" in
      y|Y|yes|YES|Yes)
        CONFIRM_UPGRADE=1
        ;;
      *)
        die "upgrade cancelled"
        ;;
    esac
  fi

  if [[ "${ACTION}" == "reset-test" && "${CONFIRM_RESET_TEST}" -ne 1 ]]; then
    [[ -t 0 && -t 1 && -r /dev/tty && -w /dev/tty ]] || \
      die "non-interactive reset-test requires --confirm-reset-test"
    printf 'Archive and remove the active TEST Gateway runtime and data now? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die "test reset confirmation was cancelled"
    case "${answer}" in
      y|Y|yes|YES|Yes)
        CONFIRM_RESET_TEST=1
        ;;
      *)
        die "test reset cancelled"
        ;;
    esac
  fi
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "${ACTION} must run as root (use sudo)"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' was not found"
}

acquire_mutation_lock() {
  exec 9>/run/vgen-gateway-setup.lock
  flock -n 9 || die "another Gateway install or rollback is already running"
}

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

verify_root_owned_not_writable() {
  local path="$1"
  local label="$2"
  local owner mode
  owner="$(stat -c '%u:%g' "${path}")"
  mode="$(stat -c '%a' "${path}")"
  [[ "${owner}" == "0:0" ]] || die "${label} must be owned by root:root"
  (( (8#${mode} & 0022) == 0 )) || die "${label} must not be writable by group or others"
}

verify_nginx_backup_path() {
  local backup_path="$1"
  VGEN_BACKUP_ROOT="${BACKUP_ROOT}" VGEN_BACKUP_PATH="${backup_path}" python3.11 <<'PY'
import os
import re
from pathlib import Path

root = Path(os.environ["VGEN_BACKUP_ROOT"])
backup = Path(os.environ["VGEN_BACKUP_PATH"])
name = backup.name
if backup.parent != root:
    raise SystemExit("Nginx backup must be a direct child of the backup root")
if re.fullmatch(r"nginx-vgen-[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{6}\.conf", name) is None:
    raise SystemExit("Nginx backup basename does not match the installer format")
PY
}

verify_regular_release_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || die "${label} is missing or is a symlink: ${path}"
  local mode
  mode="$(stat -c '%a' "${path}")"
  (( (8#${mode} & 0022) == 0 )) || die "${label} must not be writable by group or others: ${path}"
}

verify_release_bundle() {
  verify_regular_release_file "${BASH_SOURCE[0]}" "installer"
  verify_regular_release_file "${SERVICE_SOURCE_PATH}" "systemd unit"
  verify_regular_release_file "${MANIFEST_PATH}" "release manifest"

  local candidate metadata_version
  local -a wheel_candidates=()
  for candidate in "${SCRIPT_DIR}"/vgen-*-py3-none-any.whl; do
    [[ -e "${candidate}" || -L "${candidate}" ]] || continue
    wheel_candidates+=("${candidate}")
  done
  [[ "${#wheel_candidates[@]}" -eq 1 ]] || \
    die "release bundle must contain exactly one VGen py3-none-any wheel"

  WHEEL_PATH="${wheel_candidates[0]}"
  WHEEL_NAME="$(basename -- "${WHEEL_PATH}")"
  verify_regular_release_file "${WHEEL_PATH}" "Gateway wheel"

  if ! metadata_version="$(VGEN_WHEEL_PATH="${WHEEL_PATH}" python3.11 <<'PY'
import os
import re
import zipfile
from email.parser import Parser
from pathlib import Path

path = Path(os.environ["VGEN_WHEEL_PATH"])
try:
    with zipfile.ZipFile(path) as archive:
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
if path.name != f"vgen-{version}-py3-none-any.whl":
    raise SystemExit("wheel filename and metadata version differ")
if "Tag: py3-none-any" not in wheel_metadata.splitlines():
    raise SystemExit("unexpected wheel tag")
print(version)
PY
  )"; then
    die "Gateway wheel metadata validation failed"
  fi
  VGEN_VERSION="${metadata_version}"

  if ! VGEN_RELEASE_ROOT="${SCRIPT_DIR}" \
    VGEN_RELEASE_WHEEL_NAME="${WHEEL_NAME}" \
    VGEN_RELEASE_MANIFEST="${MANIFEST_PATH}" python3.11 <<'PY'
import hashlib
import os
import re
from pathlib import Path

root = Path(os.environ["VGEN_RELEASE_ROOT"])
manifest = Path(os.environ["VGEN_RELEASE_MANIFEST"])
wheel_name = os.environ["VGEN_RELEASE_WHEEL_NAME"]
expected_names = {
    "INSTALL.txt",
    "setup-gateway.sh",
    "setup-release-site.sh",
    "vgen-gateway.service",
    wheel_name,
}
entries = {}
for line in manifest.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
    if match is None or match.group(2) in entries:
        raise SystemExit("invalid release manifest")
    entries[match.group(2)] = match.group(1)
if set(entries) != expected_names:
    raise SystemExit("unexpected release manifest entries")
for name, expected in entries.items():
    path = root / name
    if path.parent != root or path.is_symlink() or not path.is_file():
        raise SystemExit("unsafe release file")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit("release file hash mismatch")
PY
  then
    die "release manifest validation failed"
  fi
}

verify_nginx_config_and_tls() {
  [[ -f "${NGINX_CONFIG_PATH}" && ! -L "${NGINX_CONFIG_PATH}" ]] || \
    die "expected an existing regular Nginx config at ${NGINX_CONFIG_PATH}"
  verify_root_owned_not_writable "${NGINX_CONFIG_PATH}" "current Nginx config"
  grep -Fq "server_name ${DOMAIN};" "${NGINX_CONFIG_PATH}" || \
    die "existing Nginx config does not declare 'server_name ${DOMAIN};'"

  verify_gateway_tls_certificate
}

verify_gateway_tls_certificate() {
  local certificate_root="/etc/letsencrypt/live/${DOMAIN}"
  [[ -f "${certificate_root}/fullchain.pem" ]] || \
    die "TLS certificate not found at ${certificate_root}/fullchain.pem"
  [[ -f "${certificate_root}/privkey.pem" ]] || \
    die "TLS private key not found at ${certificate_root}/privkey.pem"
}

verify_legacy_nginx_and_tls() {
  verify_nginx_config_and_tls
  grep -Fq "proxy_pass http://127.0.0.1:8000;" "${NGINX_CONFIG_PATH}" || \
    die "existing Nginx config is not the expected legacy route to 127.0.0.1:8000"
}

verify_install_nginx_and_tls() {
  verify_gateway_tls_certificate
  if [[ ! -e "${NGINX_CONFIG_PATH}" ]]; then
    return
  fi
  verify_nginx_config_and_tls
  if grep -Fq "proxy_pass http://127.0.0.1:8000;" "${NGINX_CONFIG_PATH}"; then
    return
  fi
  local expected_config
  expected_config="$(mktemp "${NGINX_CONFIG_PATH}.install-expected.XXXXXX")"
  render_nginx_config "${expected_config}"
  if ! cmp --silent -- "${NGINX_CONFIG_PATH}" "${expected_config}"; then
    rm -f -- "${expected_config}"
    die "existing Nginx config is neither the legacy route nor deterministic VGen Gateway route"
  fi
  rm -f -- "${expected_config}"
}

verify_gateway_base_preconditions() {
  [[ "${CONFIRM_NO_ACTIVE_TASKS}" -eq 1 ]] || \
    die "${ACTION} requires --confirm-no-active-tasks after all old tasks have finished"
  [[ "${LEGACY_DATABASE_PATH}" == /* ]] || die "--legacy-database must be an absolute path"
  verify_install_nginx_and_tls

  if python3.11 - "${GATEWAY_PORT}" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.settimeout(0.5)
    if sock.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0:
        raise SystemExit(0)
raise SystemExit(1)
PY
  then
    die "127.0.0.1:${GATEWAY_PORT} is already in use"
  fi
}

verify_install_preconditions() {
  verify_gateway_base_preconditions
  [[ ! -e "${DATABASE_PATH}" ]] || die "Gateway database already exists; use status and inspect it"
  [[ ! -e "${BOOTSTRAP_PATH}" ]] || die "Gateway bootstrap code already exists; use status and inspect it"
  [[ ! -e "${ENVIRONMENT_PATH}" ]] || die "Gateway environment already exists; use resume or status"
  [[ ! -e "${UNIT_PATH}" ]] || die "Gateway systemd unit already exists; use status and inspect it"
  [[ ! -e "${INSTALL_ROOT}/venv" ]] || die "Gateway runtime already exists; use resume or inspect it"
  [[ ! -e "${INSTALL_STATE_PATH}" ]] || die "Gateway install state already exists; use status or rollback"
}

verify_resume_preconditions() {
  verify_gateway_base_preconditions
  [[ -d "${INSTALL_ROOT}/venv" && ! -L "${INSTALL_ROOT}/venv" ]] || \
    die "resume requires the existing installer-created runtime at ${INSTALL_ROOT}/venv"
  [[ -f "${ENVIRONMENT_PATH}" && ! -L "${ENVIRONMENT_PATH}" ]] || \
    die "resume requires the existing installer-created environment at ${ENVIRONMENT_PATH}"
  [[ ! -e "${DATABASE_PATH}" ]] || die "resume refused: Gateway database already exists"
  [[ ! -e "${BOOTSTRAP_PATH}" ]] || die "resume refused: Gateway Bootstrap code already exists"
  [[ ! -e "${UNIT_PATH}" ]] || die "resume refused: Gateway systemd unit already exists"
  [[ ! -e "${INSTALL_STATE_PATH}" ]] || die "resume refused: Nginx install state already exists"
}

gateway_local_health_is_ok() {
  local health_file
  health_file="$(mktemp /tmp/vgen-local-health.XXXXXX)"
  if curl --fail --silent --max-time 3 \
    --connect-timeout 1 \
    --http1.1 \
    --header 'Connection: close' \
    --output "${health_file}" \
    "http://127.0.0.1:${GATEWAY_PORT}/api/v1/health" 2>/dev/null && \
    health_payload_is_ok <"${health_file}"; then
    rm -f -- "${health_file}"
    return 0
  fi
  rm -f -- "${health_file}"
  return 1
}

gateway_local_health_with_retry() {
  local deadline attempt consecutive
  deadline=$((SECONDS + 30))
  attempt=0
  consecutive=0
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    if gateway_local_health_is_ok; then
      consecutive=$((consecutive + 1))
      if ((consecutive >= 2)); then
        log "Gateway local health passed 2 consecutive fresh checks after ${attempt} attempt(s)"
        return 0
      fi
    else
      consecutive=0
    fi
    ((SECONDS + 1 < deadline)) && sleep 1
  done
  return 1
}

verify_activation_preconditions() {
  [[ "${CONFIRM_ACTIVATE}" -eq 1 ]] || die "activate requires --confirm-activate"
  verify_nginx_config_and_tls
  [[ -d "${INSTALL_ROOT}/venv" && ! -L "${INSTALL_ROOT}/venv" ]] || \
    die "activate refused: Gateway runtime is missing or unsafe"
  [[ -f "${ENVIRONMENT_PATH}" && ! -L "${ENVIRONMENT_PATH}" ]] || \
    die "activate refused: Gateway environment is missing or unsafe"
  [[ -f "${DATABASE_PATH}" && ! -L "${DATABASE_PATH}" ]] || \
    die "activate refused: Gateway database is missing or unsafe"
  [[ -f "${BOOTSTRAP_PATH}" && ! -L "${BOOTSTRAP_PATH}" ]] || \
    die "activate refused: Gateway Bootstrap code is missing or unsafe"
  [[ -f "${UNIT_PATH}" && ! -L "${UNIT_PATH}" ]] || \
    die "activate refused: Gateway systemd unit is missing or unsafe"
  [[ -f "${INSTALL_STATE_PATH}" && ! -L "${INSTALL_STATE_PATH}" ]] || \
    die "activate refused: install state is missing or unsafe"
  [[ "$(stat -c '%a %U:%G' "${DATABASE_PATH}")" == "600 vgen:vgen" ]] || \
    die "activate refused: Gateway database permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${BOOTSTRAP_PATH}")" == "600 vgen:vgen" ]] || \
    die "activate refused: Gateway Bootstrap code permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${UNIT_PATH}")" == "644 root:root" ]] || \
    die "activate refused: Gateway systemd unit permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${INSTALL_STATE_PATH}")" == "600 root:root" ]] || \
    die "activate refused: install state must be mode 0600 and owned by root:root"
  cmp --silent "${SERVICE_SOURCE_PATH}" "${UNIT_PATH}" || \
    die "activate refused: installed systemd unit does not match the reviewed release"

  VGEN_STATE_PATH="${INSTALL_STATE_PATH}" python3.11 <<'PY'
import json
import os

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate install-state key: {key}")
        result[key] = value
    return result

with open(os.environ["VGEN_STATE_PATH"], encoding="utf-8") as handle:
    payload = json.load(handle, object_pairs_hook=unique_object)
expected = {"version", "domain", "nginx_config", "nginx_backup", "installed_at"}
if set(payload) != expected or payload.get("version") != 1:
    raise SystemExit("activate refused: install state does not match version 1")
if not isinstance(payload.get("installed_at"), str) or not payload["installed_at"]:
    raise SystemExit("activate refused: install timestamp is invalid")
PY

  local state_domain state_config backup_path expected_config
  state_domain="$(read_install_state_field domain)"
  state_config="$(read_install_state_field nginx_config)"
  backup_path="$(read_install_state_field nginx_backup)"
  [[ "${state_domain}" == "${DOMAIN}" ]] || \
    die "activate refused: install state belongs to ${state_domain}, not ${DOMAIN}"
  [[ "${state_config}" == "${NGINX_CONFIG_PATH}" ]] || \
    die "activate refused: install state names an unexpected Nginx config"
  verify_nginx_backup_path "${backup_path}"
  [[ -f "${backup_path}" && ! -L "${backup_path}" ]] || \
    die "activate refused: saved legacy Nginx backup is missing or unsafe"
  verify_root_owned_not_writable "${backup_path}" "saved Nginx backup"
  grep -Fq "server_name ${DOMAIN};" "${backup_path}" || \
    die "activate refused: saved backup belongs to a different domain"
  local expected_backup uninitialized_backup
  expected_backup="$(mktemp "${NGINX_CONFIG_PATH}.activate-backup.XXXXXX")"
  uninitialized_backup="$(mktemp "${NGINX_CONFIG_PATH}.activate-uninitialized.XXXXXX")"
  render_nginx_config "${expected_backup}"
  render_uninitialized_nginx_config "${uninitialized_backup}"
  if ! grep -Fq "proxy_pass http://127.0.0.1:8000;" "${backup_path}" && \
     ! cmp --silent -- "${backup_path}" "${expected_backup}" && \
     ! cmp --silent -- "${backup_path}" "${uninitialized_backup}"; then
    rm -f -- "${expected_backup}" "${uninitialized_backup}"
    die "activate refused: saved backup is neither legacy nor a deterministic VGen baseline"
  fi
  rm -f -- "${expected_backup}" "${uninitialized_backup}"
  systemctl is-active --quiet "${SERVICE_NAME}" || \
    die "activate refused: Gateway service is not active"
  systemctl is-enabled --quiet "${SERVICE_NAME}" || \
    die "activate refused: Gateway service is not enabled"
  gateway_local_health_is_ok || die "activate refused: local Gateway health is not ready"

  expected_config="$(mktemp "${NGINX_CONFIG_PATH}.expected.XXXXXX")"
  render_nginx_config "${expected_config}"
  if cmp --silent -- "${NGINX_CONFIG_PATH}" "${backup_path}"; then
    ACTIVATION_ALREADY_ACTIVE=0
  elif cmp --silent -- "${NGINX_CONFIG_PATH}" "${expected_config}"; then
    ACTIVATION_ALREADY_ACTIVE=1
  else
    rm -f -- "${expected_config}"
    die "activate refused: current Nginx config is neither the saved legacy baseline nor deterministic v1"
  fi
  rm -f -- "${expected_config}"
  ACTIVATION_BACKUP_PATH="${backup_path}"

  if [[ "${ACTIVATION_ALREADY_ACTIVE}" -eq 1 ]]; then
    gateway_https_health_with_retry || \
      die "activate refused: deterministic v1 config is present but public health is not ready"
  fi
}

check_legacy_task_status() {
  local status_file
  status_file="$(mktemp /tmp/vgen-legacy-status.XXXXXX)"
  if curl --noproxy '*' --fail --silent --show-error --max-time 10 \
    "https://${DOMAIN}/api/status" >"${status_file}"; then
    if ! python3.11 - "${status_file}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
workers = payload.get("workers")
if not isinstance(workers, list):
    raise SystemExit(2)
busy = [worker for worker in workers if worker.get("current_task") is not None]
if busy:
    print(f"legacy endpoint reports {len(busy)} active task(s)", file=sys.stderr)
    raise SystemExit(1)
PY
    then
      rm -f -- "${status_file}"
      die "legacy task status is busy or invalid; stop and inspect before installing"
    fi
    log "legacy endpoint reports no active task"
  else
    warn "legacy /api/status could not be read; relying on your explicit no-active-task confirmation"
  fi
  rm -f -- "${status_file}"
}

ensure_service_user_and_directories() {
  if ! getent group vgen >/dev/null 2>&1; then
    groupadd --system vgen
  fi
  if ! id vgen >/dev/null 2>&1; then
    useradd --system --gid vgen --home-dir "${DATA_ROOT}" --shell /usr/sbin/nologin vgen
  elif ! id -nG vgen | tr ' ' '\n' | grep -Fxq vgen; then
    die "existing user 'vgen' is not a member of group 'vgen'; inspect it manually"
  fi
  install -d -o root -g root -m 0755 "${INSTALL_ROOT}" "${RELEASE_ROOT}"
  install -d -o vgen -g vgen -m 0700 "${DATA_ROOT}"
  install -d -o root -g root -m 0700 "${CONFIG_ROOT}" "${BACKUP_ROOT}"
}

backup_legacy_database() {
  if [[ ! -e "${LEGACY_DATABASE_PATH}" ]]; then
    warn "legacy database does not exist at ${LEGACY_DATABASE_PATH}; no legacy database backup was created"
    return
  fi
  [[ -f "${LEGACY_DATABASE_PATH}" && ! -L "${LEGACY_DATABASE_PATH}" ]] || \
    die "legacy database must be a regular file, not a symlink"

  local stamp backup_path
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_path="${BACKUP_ROOT}/legacy-vgen-${stamp}-$$.db"
  VGEN_LEGACY_DATABASE="${LEGACY_DATABASE_PATH}" \
  VGEN_LEGACY_BACKUP="${backup_path}" \
    python3.11 <<'PY'
import os
import sqlite3
from pathlib import Path

source_path = Path(os.environ["VGEN_LEGACY_DATABASE"])
backup_path = Path(os.environ["VGEN_LEGACY_BACKUP"])
descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.close(descriptor)
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
target = sqlite3.connect(backup_path)
try:
    source.backup(target)
    result = target.execute("PRAGMA quick_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"legacy backup quick_check failed: {result}")
finally:
    target.close()
    source.close()
os.chmod(backup_path, 0o600)
PY
  log "legacy SQLite backup: ${backup_path}"
  log "legacy SQLite backup SHA-256: $(sha256_of "${backup_path}")"
}

install_python_runtime() {
  log "creating isolated Python runtime"
  (
    umask 022
    python3.11 -m venv "${INSTALL_ROOT}/venv"
    "${INSTALL_ROOT}/venv/bin/python" -m pip install --disable-pip-version-check \
      "${WHEEL_PATH}[gateway,oss]"
  )
  normalize_and_verify_python_runtime
}

verify_existing_python_runtime() {
  verify_existing_python_runtime_security
  "${INSTALL_ROOT}/venv/bin/python" -c \
    'import importlib.metadata, sys; assert importlib.metadata.version("vgen") == sys.argv[1]' \
    "${VGEN_VERSION}"
  [[ -f "${INSTALL_ROOT}/venv/bin/vgen-gateway" && ! -L "${INSTALL_ROOT}/venv/bin/vgen-gateway" ]] || \
    die "resume refused: vgen-gateway executable is missing or is a symlink"
}

normalize_and_verify_python_runtime() {
  normalize_and_verify_runtime_at "${INSTALL_ROOT}/venv" "${VGEN_VERSION}"
}

relocate_python_runtime_scripts() {
  local source_root="$1"
  local destination_root="$2"
  VGEN_RUNTIME_SOURCE_ROOT="${source_root}" \
    VGEN_RUNTIME_DESTINATION_ROOT="${destination_root}" python3.11 <<'PY'
import os
import stat
import tempfile
from pathlib import Path

source_root = Path(os.environ["VGEN_RUNTIME_SOURCE_ROOT"])
destination_root = Path(os.environ["VGEN_RUNTIME_DESTINATION_ROOT"])
if not source_root.is_absolute() or not destination_root.is_absolute():
    raise SystemExit("runtime relocation requires absolute paths")
if source_root == destination_root:
    raise SystemExit("runtime relocation source and destination must differ")
if not destination_root.is_dir() or destination_root.is_symlink():
    raise SystemExit("relocated runtime destination is missing or unsafe")
runtime_owner = destination_root.stat()

source_bytes = os.fsencode(source_root)
destination_bytes = os.fsencode(destination_root)
targets = [destination_root / "pyvenv.cfg"]
bin_root = destination_root / "bin"
if not bin_root.is_dir() or bin_root.is_symlink():
    raise SystemExit("relocated runtime bin directory is missing or unsafe")
targets.extend(sorted(bin_root.iterdir(), key=lambda path: path.name))

rewritten = []
for path in targets:
    if path.is_symlink() or not path.is_file():
        continue
    metadata = path.stat()
    if (
        metadata.st_uid != runtime_owner.st_uid
        or metadata.st_gid != runtime_owner.st_gid
    ):
        raise SystemExit(f"runtime relocation target ownership differs from its runtime: {path}")
    payload = path.read_bytes()
    if source_bytes not in payload or b"\x00" in payload[:4096]:
        continue
    replacement = payload.replace(source_bytes, destination_bytes)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.relocate.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(replacement)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    rewritten.append(path.name)

gateway = bin_root / "vgen-gateway"
if not gateway.is_file() or gateway.is_symlink():
    raise SystemExit("relocated Gateway entry point is missing or unsafe")
if source_bytes in gateway.read_bytes()[:4096]:
    raise SystemExit("relocated Gateway entry point still references the staging runtime")
if "vgen-gateway" not in rewritten:
    raise SystemExit("Gateway entry point did not contain the expected staging runtime path")

for path in bin_root.iterdir():
    if path.is_symlink() or not path.is_file():
        continue
    payload = path.read_bytes()
    if b"\x00" not in payload[:4096] and source_bytes in payload[:4096]:
        raise SystemExit(f"runtime script still references the staging runtime: {path}")
PY
}

normalize_and_verify_runtime_at() {
  local runtime_root="$1"
  local expected_version="$2"
  chown -R root:root "${runtime_root}"
  chmod 0755 "${INSTALL_ROOT}"
  make_runtime_tree_readable "${runtime_root}"
  runuser -u vgen -- test -x "${runtime_root}/bin/python"
  runuser -u vgen -- "${runtime_root}/bin/python" -c \
    'import importlib.metadata, sys; assert importlib.metadata.version("vgen") == sys.argv[1]' \
    "${expected_version}"
  [[ -f "${runtime_root}/bin/vgen-gateway" && ! -L "${runtime_root}/bin/vgen-gateway" ]] || \
    die "Gateway runtime executable is missing or is a symlink"
  runuser -u vgen -- "${runtime_root}/bin/vgen-gateway" --help >/dev/null
}

make_runtime_tree_readable() {
  local runtime_root="$1"
  chmod -R u=rwX,go=rX "${runtime_root}"
}

verify_existing_gateway_environment() {
  local environment_path="${1:-${ENVIRONMENT_PATH}}"
  [[ "$(stat -c '%a' "${environment_path}")" == "600" ]] || \
    die "${ACTION} refused: ${environment_path} must have mode 0600"
  [[ "$(stat -c '%U:%G' "${environment_path}")" == "root:root" ]] || \
    die "${ACTION} refused: ${environment_path} must be owned by root:root"
  VGEN_GATEWAY_ENVIRONMENT_PATH="${environment_path}" VGEN_SETUP_ACTION="${ACTION}" \
    python3.11 <<'PY'
import os
from pathlib import Path

action = os.environ["VGEN_SETUP_ACTION"]
values = {}
for line in Path(os.environ["VGEN_GATEWAY_ENVIRONMENT_PATH"]).read_text().splitlines():
    if not line or line.startswith("#") or "=" not in line:
        raise SystemExit(f"{action} refused: Gateway environment has an invalid line")
    key, value = line.split("=", 1)
    if key in values:
        raise SystemExit(f"{action} refused: duplicate Gateway environment key: {key}")
    values[key] = value
expected = {
    "VGEN_ARTIFACT_STORE",
    "VGEN_GATEWAY_DOCS",
    "VGEN_REQUIRE_REQUEST_SIGNATURES",
    "VGEN_ARTIFACT_TICKET_KEY",
    "VGEN_OSS_ENDPOINT",
    "VGEN_OSS_BUCKET",
    "VGEN_OSS_PREFIX",
    "VGEN_OSS_TRANSFER_ROLE_ARN",
    "VGEN_OSS_STS_DURATION_SECONDS",
    "VGEN_STS_REGION",
    "VGEN_STS_ENDPOINT",
}
if set(values) != expected or values.get("VGEN_ARTIFACT_STORE") != "oss":
    raise SystemExit(f"{action} refused: OSS ArtifactStore configuration is required")
if not values["VGEN_OSS_ENDPOINT"].startswith("https://"):
    raise SystemExit(f"{action} refused: OSS endpoint must use HTTPS")
if not values["VGEN_OSS_BUCKET"] or not values["VGEN_OSS_PREFIX"] or not values["VGEN_OSS_TRANSFER_ROLE_ARN"]:
    raise SystemExit(f"{action} refused: OSS ArtifactStore configuration is incomplete")
if values["VGEN_GATEWAY_DOCS"] != "0" or values["VGEN_REQUIRE_REQUEST_SIGNATURES"] != "1":
    raise SystemExit(f"{action} refused: Gateway security settings do not match")
if len(values["VGEN_ARTIFACT_TICKET_KEY"]) < 48:
    raise SystemExit(f"{action} refused: Artifact ticket key is missing or too short")
PY
}

write_gateway_environment() {
  VGEN_GATEWAY_ENVIRONMENT_PATH="${ENVIRONMENT_PATH}" \
  VGEN_SETUP_ARTIFACT_STORE="${ARTIFACT_STORE}" \
  VGEN_SETUP_OSS_ENDPOINT="${OSS_ENDPOINT}" \
  VGEN_SETUP_OSS_BUCKET="${OSS_BUCKET}" \
  VGEN_SETUP_OSS_PREFIX="${OSS_PREFIX}" \
  VGEN_SETUP_OSS_TRANSFER_ROLE_ARN="acs:ram::${OSS_ACCOUNT_ID}:role/${OSS_TRANSFER_ROLE}" \
  VGEN_SETUP_OSS_STS_DURATION="${OSS_STS_DURATION_SECONDS}" \
  VGEN_SETUP_STS_REGION="${OSS_STS_REGION}" python3.11 <<'PY'
import os
import secrets

destination = os.environ["VGEN_GATEWAY_ENVIRONMENT_PATH"]
lines = [
    "VGEN_ARTIFACT_STORE=oss",
    f"VGEN_OSS_ENDPOINT={os.environ['VGEN_SETUP_OSS_ENDPOINT']}",
    f"VGEN_OSS_BUCKET={os.environ['VGEN_SETUP_OSS_BUCKET']}",
    f"VGEN_OSS_PREFIX={os.environ['VGEN_SETUP_OSS_PREFIX']}",
    f"VGEN_OSS_TRANSFER_ROLE_ARN={os.environ['VGEN_SETUP_OSS_TRANSFER_ROLE_ARN']}",
    f"VGEN_OSS_STS_DURATION_SECONDS={os.environ['VGEN_SETUP_OSS_STS_DURATION']}",
    f"VGEN_STS_REGION={os.environ['VGEN_SETUP_STS_REGION']}",
    "VGEN_STS_ENDPOINT=sts.aliyuncs.com",
]
lines.extend(
    [
        "VGEN_GATEWAY_DOCS=0",
        "VGEN_REQUIRE_REQUEST_SIGNATURES=1",
        f"VGEN_ARTIFACT_TICKET_KEY={secrets.token_urlsafe(48)}",
    ]
)
payload = ("\n".join(lines) + "\n").encode("utf-8")
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, payload)
finally:
    os.close(descriptor)
PY
}

verify_artifact_store_access_at() {
  local runtime_root="$1"
  log "verifying ECS RAM Role can assume the configured object-transfer role"
  # gateway.env is deliberately root:root 0600. This installer preflight runs
  # as root so it can read that file; the long-running Gateway still runs as
  # the unprivileged vgen service user through systemd's EnvironmentFile.
  env VGEN_GATEWAY_ENVIRONMENT_PATH="${ENVIRONMENT_PATH}" \
    "${runtime_root}/bin/python" - <<'PY'
import os
from pathlib import Path

from vgen.gateway.artifacts import OssArtifactStore

for line in Path(os.environ["VGEN_GATEWAY_ENVIRONMENT_PATH"]).read_text().splitlines():
    key, value = line.split("=", 1)
    os.environ[key] = value
OssArtifactStore.from_environment().verify_access()
PY
  log "STS AssumeRole validation passed; no OSS object bytes were transferred"
}

prepare_resume_runtime() {
  verify_existing_python_runtime_security
  local installed_version backup_runtime
  installed_version="$("${INSTALL_ROOT}/venv/bin/python" -c \
    'import importlib.metadata; print(importlib.metadata.version("vgen"))')"
  [[ "${installed_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
    die "resume refused: partial runtime version is invalid"
  if [[ "${installed_version}" == "${VGEN_VERSION}" ]]; then
    verify_existing_python_runtime
    normalize_and_verify_python_runtime
    return
  fi
  backup_runtime="${BACKUP_ROOT}/partial-runtime-${installed_version}-$(date -u +%Y%m%dT%H%M%SZ)"
  [[ ! -e "${backup_runtime}" ]] || die "resume runtime backup already exists"
  mv -- "${INSTALL_ROOT}/venv" "${backup_runtime}"
  install_python_runtime
  log "replaced incomplete Gateway runtime ${installed_version} with ${VGEN_VERSION}"
  log "previous partial runtime retained at ${backup_runtime}"
}

verify_existing_python_runtime_security() {
  VGEN_RUNTIME_ROOT="${INSTALL_ROOT}/venv" python3.11 <<'PY'
import os
import stat
from pathlib import Path

root = Path(os.environ["VGEN_RUNTIME_ROOT"])
for path in (root, *root.rglob("*")):
    metadata = path.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"resume refused: runtime entry is not root-owned: {path}")
    if not stat.S_ISLNK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit(f"resume refused: runtime entry is group/other writable: {path}")
PY
}

initialize_gateway() {
  runuser -u vgen -- "${INSTALL_ROOT}/venv/bin/vgen-gateway" \
    --database "${DATABASE_PATH}" init
  runuser -u vgen -- "${INSTALL_ROOT}/venv/bin/vgen-gateway" \
    --database "${DATABASE_PATH}" doctor
  chmod 0600 "${DATABASE_PATH}" "${BOOTSTRAP_PATH}"
}

install_and_start_service() {
  install -o root -g root -m 0644 "${SERVICE_SOURCE_PATH}" "${UNIT_PATH}"
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"

  local attempt
  for ((attempt = 1; attempt <= 30; attempt++)); do
    if curl --fail --silent --show-error --max-time 2 \
      "http://127.0.0.1:${GATEWAY_PORT}/api/v1/health" | health_payload_is_ok; then
      log "Gateway v1 is healthy on 127.0.0.1:${GATEWAY_PORT}"
      return
    fi
    sleep 1
  done
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
  journalctl -u "${SERVICE_NAME}" -n 50 --no-pager || true
  die "Gateway v1 did not become healthy; Nginx was not changed"
}

health_payload_is_ok() {
  python3.11 -c '
import json
import sys
try:
    payload = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError):
    raise SystemExit(1)
valid = (
    isinstance(payload, dict)
    and payload.get("ok") is True
    and payload.get("schema_version") == 1
    and payload.get("journal_mode") == "wal"
)
raise SystemExit(0 if valid else 1)
'
}

gateway_https_health_with_retry() {
  local deadline response_file attempt remaining max_time consecutive
  deadline=$((SECONDS + 30))
  response_file="$(mktemp /tmp/vgen-https-health.XXXXXX)"
  attempt=0
  consecutive=0
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    remaining=$((deadline - SECONDS))
    max_time=2
    ((remaining < max_time)) && max_time="${remaining}"
    if curl --noproxy '*' --fail --silent --max-time "${max_time}" \
      --connect-timeout 1 \
      --http1.1 \
      --header 'Connection: close' \
      --output "${response_file}" \
      --resolve "${DOMAIN}:443:127.0.0.1" \
      "https://${DOMAIN}/api/v1/health" 2>/dev/null && \
      health_payload_is_ok <"${response_file}"; then
      consecutive=$((consecutive + 1))
      if ((consecutive >= 2)); then
        rm -f -- "${response_file}"
        log "Gateway HTTPS health passed 2 consecutive fresh checks after ${attempt} attempt(s)"
        return 0
      fi
    else
      consecutive=0
    fi
    : >"${response_file}"
    remaining=$((deadline - SECONDS))
    ((remaining > 1)) && sleep 1
  done
  rm -f -- "${response_file}"
  return 1
}

render_nginx_config_profile() {
  local destination="$1"
  local include_public_releases="$2"
  cat >"${destination}" <<EOF
# Generated by the VGen Gateway v1 safe installer for ${DOMAIN}.
server {
  listen 80;
  server_name ${DOMAIN};

  location /.well-known/acme-challenge/ {
    root /var/www/certbot;
  }

  location / {
    return 301 https://\$host\$request_uri;
  }
}

server {
  listen 443 ssl http2;
  server_name ${DOMAIN};

  ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "no-referrer" always;

  client_max_body_size 5g;
  client_body_timeout 30m;
  send_timeout 30m;
  proxy_request_buffering off;
  proxy_buffering off;
  proxy_connect_timeout 10s;
  proxy_read_timeout 30m;
  proxy_send_timeout 30m;
  proxy_http_version 1.1;
  proxy_set_header Connection "";

EOF
  if [[ "${include_public_releases}" == "1" ]]; then
    cat >>"${destination}" <<'EOF'
  location = /releases/channels/stable.json {
    alias /var/www/vgen-releases/channels/stable.json;
    default_type application/json;
    add_header Cache-Control "public, max-age=0, must-revalidate" always;
  }

  location = /releases/install-macos.sh {
    alias /var/www/vgen-releases/install-macos.sh;
    default_type text/x-shellscript;
    add_header Cache-Control "public, max-age=0, must-revalidate" always;
    add_header Content-Disposition 'attachment; filename="install-macos.sh"' always;
  }

  location ~ "^/releases/(?<vgen_release_version>[0-9]+(?:\.[0-9]+){2}(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,63})?)/(?<vgen_release_file>[A-Za-z0-9][A-Za-z0-9._+-]{0,191})$" {
    alias /var/www/vgen-releases/$vgen_release_version/$vgen_release_file;
    add_header Cache-Control "public, max-age=31536000, immutable" always;
  }

  location /releases/ {
    return 404;
  }

EOF
  fi
  cat >>"${destination}" <<EOF
  location / {
    proxy_pass http://127.0.0.1:${GATEWAY_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Request-Id \$request_id;
  }
}
EOF
  chmod 0600 "${destination}"
}

render_nginx_config() {
  # The Gateway hostname is API-only. Public installers are served by the
  # independently configured release hostname.
  render_nginx_config_profile "$1" 0
}

render_uninitialized_nginx_config() {
  local destination="$1"
  cat >"${destination}" <<EOF
# Generated by the VGen Gateway installer as a safe pre-initialization fallback.
server {
  listen 80;
  server_name ${DOMAIN};
  location /.well-known/acme-challenge/ { root /var/www/certbot; }
  location / { return 301 https://\$host\$request_uri; }
}
server {
  listen 443 ssl http2;
  server_name ${DOMAIN};
  ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "no-referrer" always;
  location / { return 503; }
}
EOF
  chmod 0600 "${destination}"
}

render_previous_gateway_nginx_config() {
  # 0.3.x through 0.5.x served public releases on the Gateway hostname.
  # Accept that exact profile only during the one-way split-domain upgrade.
  render_nginx_config_profile "$1" 1
}

write_install_state() {
  local nginx_backup_path="$1"
  VGEN_STATE_PATH="${INSTALL_STATE_PATH}" \
  VGEN_STATE_DOMAIN="${DOMAIN}" \
  VGEN_STATE_NGINX_CONFIG="${NGINX_CONFIG_PATH}" \
  VGEN_STATE_NGINX_BACKUP="${nginx_backup_path}" \
    python3.11 <<'PY'
import json
import os
from datetime import datetime, timezone

payload = {
    "version": 1,
    "domain": os.environ["VGEN_STATE_DOMAIN"],
    "nginx_config": os.environ["VGEN_STATE_NGINX_CONFIG"],
    "nginx_backup": os.environ["VGEN_STATE_NGINX_BACKUP"],
    "installed_at": datetime.now(timezone.utc).isoformat(),
}
destination = os.environ["VGEN_STATE_PATH"]
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, (json.dumps(payload, sort_keys=True) + "\n").encode())
finally:
    os.close(descriptor)
PY
}

atomic_replace_nginx_config() {
  local source_path="$1"
  local restore_candidate
  restore_candidate="$(mktemp "${NGINX_CONFIG_PATH}.restore.XXXXXX")" || return 1
  if ! cp --preserve=mode,ownership,timestamps -- "${source_path}" "${restore_candidate}"; then
    rm -f -- "${restore_candidate}"
    return 1
  fi
  if ! chown root:root "${restore_candidate}" || \
    ! chmod 0644 "${restore_candidate}" || \
    ! mv -f -- "${restore_candidate}" "${NGINX_CONFIG_PATH}"; then
    rm -f -- "${restore_candidate}"
    return 1
  fi
}

restore_nginx_config() {
  local backup_path="$1"
  log "restoring legacy Nginx route"
  verify_nginx_backup_path "${backup_path}" || return 1
  atomic_replace_nginx_config "${backup_path}" || return 1
  nginx -t || return 1
  systemctl reload nginx || return 1
}

clear_nginx_switch_traps() {
  trap - ERR INT TERM HUP
}

handle_nginx_switch_error() {
  local status="$1"
  clear_nginx_switch_traps
  if [[ "${NGINX_REPLACED}" -eq 1 && -n "${NGINX_ROLLBACK_BACKUP}" ]]; then
    warn "an unexpected error occurred while switching Nginx; restoring the legacy route"
    restore_nginx_config "${NGINX_ROLLBACK_BACKUP}" || \
      warn "automatic Nginx restoration failed; restore ${NGINX_ROLLBACK_BACKUP} manually"
  fi
  if [[ -n "${NGINX_GENERATED_PATH}" ]]; then
    rm -f -- "${NGINX_GENERATED_PATH}" || true
  fi
  exit "${status}"
}

switch_nginx() {
  local backup_path="${1:-}"
  local reuse_existing_state="${2:-0}"
  local stamp generated_path
  if [[ "${reuse_existing_state}" == "1" ]]; then
    [[ -n "${backup_path}" ]] || die "activate requires an existing Nginx backup"
  else
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_path="$(mktemp "${BACKUP_ROOT}/nginx-vgen-${stamp}.XXXXXX.conf")"
    if [[ -e "${NGINX_CONFIG_PATH}" ]]; then
      cp --preserve=mode,ownership,timestamps -- "${NGINX_CONFIG_PATH}" "${backup_path}"
    else
      render_uninitialized_nginx_config "${backup_path}"
      chown root:root "${backup_path}"
      chmod 0644 "${backup_path}"
    fi
    verify_nginx_backup_path "${backup_path}"
    verify_root_owned_not_writable "${backup_path}" "saved Nginx backup"
  fi
  generated_path="$(mktemp "${NGINX_CONFIG_PATH}.v1-candidate.XXXXXX")"
  NGINX_ROLLBACK_BACKUP="${backup_path}"
  NGINX_GENERATED_PATH="${generated_path}"
  NGINX_REPLACED=0

  render_nginx_config "${generated_path}"
  chown root:root "${generated_path}"
  chmod 0644 "${generated_path}"
  if [[ "${reuse_existing_state}" != "1" ]]; then
    write_install_state "${backup_path}"
  fi

  trap 'handle_nginx_switch_error $?' ERR
  trap 'handle_nginx_switch_error 130' INT
  trap 'handle_nginx_switch_error 143' TERM
  trap 'handle_nginx_switch_error 129' HUP
  NGINX_REPLACED=1
  mv -f -- "${generated_path}" "${NGINX_CONFIG_PATH}"
  NGINX_GENERATED_PATH=""

  if ! nginx -t; then
    clear_nginx_switch_traps
    restore_nginx_config "${backup_path}" || \
      die "generated config failed and automatic legacy restoration also failed; restore ${backup_path} manually"
    NGINX_REPLACED=0
    die "generated Nginx configuration failed validation; legacy route was restored"
  fi
  if ! systemctl reload nginx; then
    clear_nginx_switch_traps
    restore_nginx_config "${backup_path}" || \
      die "Nginx reload failed and automatic legacy restoration also failed; restore ${backup_path} manually"
    NGINX_REPLACED=0
    die "Nginx reload failed; legacy route was restored"
  fi
  if ! gateway_https_health_with_retry; then
    clear_nginx_switch_traps
    restore_nginx_config "${backup_path}" || \
      die "HTTPS health failed and automatic legacy restoration also failed; restore ${backup_path} manually"
    NGINX_REPLACED=0
    die "Gateway HTTPS health check failed; legacy route was restored"
  fi
  NGINX_REPLACED=0
  clear_nginx_switch_traps

  log "Nginx now routes https://${DOMAIN} to Gateway v1"
  log "legacy Nginx backup: ${backup_path}"
}

read_runtime_version() {
  local runtime_root="$1"
  VGEN_LEGACY_GATEWAY_BRIDGE_VERSION="${LEGACY_GATEWAY_BRIDGE_VERSION}" \
    "${runtime_root}/bin/python" -c '
import importlib.metadata
import os
import re

version = importlib.metadata.version("vgen")
legacy_bridge_version = os.environ["VGEN_LEGACY_GATEWAY_BRIDGE_VERSION"]
release = re.fullmatch(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
    version,
)
if release is None and version != legacy_bridge_version:
    raise SystemExit("installed VGen version is not a supported release version")
print(version)
'
}

compare_release_versions() {
  local installed="$1"
  local target="$2"
  VGEN_LEGACY_GATEWAY_BRIDGE_VERSION="${LEGACY_GATEWAY_BRIDGE_VERSION}" \
    python3.11 - "${installed}" "${target}" <<'PY'
import os
import sys

legacy_bridge_version = os.environ["VGEN_LEGACY_GATEWAY_BRIDGE_VERSION"]
if sys.argv[1] == legacy_bridge_version:
    # 2.0.0a1 was the internal identifier used before VGen adopted the
    # 0.MINOR.PATCH product line. It is an explicit predecessor, not a newer
    # 2.x release and not permission for generic pre-release downgrades.
    print(-1)
    raise SystemExit(0)
installed = tuple(int(part) for part in sys.argv[1].split("."))
target = tuple(int(part) for part in sys.argv[2].split("."))
print(-1 if installed < target else (1 if installed > target else 0))
PY
}

verify_upgrade_runtime_security() {
  local runtime_root="${1:-${INSTALL_ROOT}/venv}"
  VGEN_RUNTIME_ROOT="${runtime_root}" python3.11 <<'PY'
import os
import stat
from pathlib import Path

root = Path(os.environ["VGEN_RUNTIME_ROOT"])
if not root.is_dir() or root.is_symlink():
    raise SystemExit("upgrade refused: active runtime is missing or unsafe")
for path in (root, *root.rglob("*")):
    metadata = path.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"upgrade refused: runtime entry is not root-owned: {path}")
    if not stat.S_ISLNK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit(f"upgrade refused: runtime entry is group/other writable: {path}")
PY
  [[ -f "${runtime_root}/bin/vgen-gateway" && \
     ! -L "${runtime_root}/bin/vgen-gateway" ]] || \
    die "upgrade refused: active vgen-gateway executable is missing or unsafe"
  runuser -u vgen -- test -x "${runtime_root}/bin/python"
  runuser -u vgen -- "${runtime_root}/bin/vgen-gateway" --help >/dev/null
  INSTALLED_VGEN_VERSION="$(read_runtime_version "${runtime_root}")"
}

verify_upgrade_install_state() {
  VGEN_STATE_PATH="${INSTALL_STATE_PATH}" python3.11 <<'PY'
import json
import os

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"upgrade refused: duplicate install-state key: {key}")
        result[key] = value
    return result

with open(os.environ["VGEN_STATE_PATH"], encoding="utf-8") as handle:
    payload = json.load(handle, object_pairs_hook=unique_object)
expected = {"version", "domain", "nginx_config", "nginx_backup", "installed_at"}
if set(payload) != expected or payload.get("version") != 1:
    raise SystemExit("upgrade refused: install state does not match version 1")
if not isinstance(payload.get("installed_at"), str) or not payload["installed_at"]:
    raise SystemExit("upgrade refused: install timestamp is invalid")
PY

  local state_domain state_config backup_path
  state_domain="$(read_install_state_field domain)"
  state_config="$(read_install_state_field nginx_config)"
  backup_path="$(read_install_state_field nginx_backup)"
  [[ "${state_domain}" == "${DOMAIN}" ]] || \
    die "upgrade refused: install state belongs to ${state_domain}, not ${DOMAIN}"
  [[ "${state_config}" == "${NGINX_CONFIG_PATH}" ]] || \
    die "upgrade refused: install state names an unexpected Nginx config"
  verify_nginx_backup_path "${backup_path}"
  [[ -f "${backup_path}" && ! -L "${backup_path}" ]] || \
    die "upgrade refused: saved legacy Nginx backup is missing or unsafe"
  verify_root_owned_not_writable "${backup_path}" "saved Nginx backup"
}

rewrite_migrated_install_state() {
  local state_path="$1"
  VGEN_LAYOUT_STATE_PATH="${state_path}" \
  VGEN_LAYOUT_OLD_BACKUP_ROOT="${LEGACY_V1_BACKUP_ROOT}" \
  VGEN_LAYOUT_NEW_BACKUP_ROOT="${BACKUP_ROOT}" python3.11 <<'PY'
import json
import os
import stat
import tempfile
from pathlib import Path

path = Path(os.environ["VGEN_LAYOUT_STATE_PATH"])
old_root = Path(os.environ["VGEN_LAYOUT_OLD_BACKUP_ROOT"])
new_root = Path(os.environ["VGEN_LAYOUT_NEW_BACKUP_ROOT"])
payload = json.loads(path.read_text(encoding="utf-8"))
backup = Path(payload.get("nginx_backup", ""))
try:
    relative = backup.relative_to(old_root)
except ValueError as exc:
    raise SystemExit("layout migration refused: install state backup is outside the legacy root") from exc
destination = new_root / relative
if not destination.is_file() or destination.is_symlink():
    raise SystemExit("layout migration refused: migrated Nginx backup is missing or unsafe")
payload["nginx_backup"] = str(destination)
descriptor, temporary_name = tempfile.mkstemp(prefix=".install-state.layout-", dir=path.parent)
temporary = Path(temporary_name)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY
  chown root:root "${state_path}"
  chmod 0600 "${state_path}"
}

clear_layout_migration_traps() {
  trap - ERR INT TERM HUP
}

handle_layout_migration_error() {
  local status="$1"
  local rollback_ok=1
  clear_layout_migration_traps
  set +e
  ((status == 0)) && status=1
  warn "Gateway layout migration failed; restoring the /vgen-v1 directories"
  systemctl stop "${SERVICE_NAME}" || rollback_ok=0

  if [[ "${LAYOUT_UNIT_REPLACED}" -eq 1 ]]; then
    install -o root -g root -m 0644 \
      "${LAYOUT_MIGRATION_BACKUP_DIR}/vgen-gateway.service" "${UNIT_PATH}" || rollback_ok=0
  fi
  if [[ "${LAYOUT_CONFIG_MOVED}" -eq 1 && -d "${CONFIG_ROOT}" ]]; then
    mv -- "${CONFIG_ROOT}" "${LEGACY_V1_CONFIG_ROOT}" || rollback_ok=0
    if [[ -f "${LAYOUT_MIGRATION_BACKUP_DIR}/install-state.json" ]]; then
      install -o root -g root -m 0600 \
        "${LAYOUT_MIGRATION_BACKUP_DIR}/install-state.json" \
        "${LEGACY_V1_CONFIG_ROOT}/install-state.json" || rollback_ok=0
    fi
  fi
  if [[ "${LAYOUT_DATA_MOVED}" -eq 1 && -d "${DATA_ROOT}" ]]; then
    mv -- "${DATA_ROOT}" "${LEGACY_V1_DATA_ROOT}" || rollback_ok=0
  fi
  if [[ "${LAYOUT_INSTALL_MOVED}" -eq 1 && -d "${INSTALL_ROOT}" ]]; then
    mv -- "${INSTALL_ROOT}" "${LEGACY_V1_INSTALL_ROOT}" || rollback_ok=0
    relocate_python_runtime_scripts \
      "${INSTALL_ROOT}/venv" "${LEGACY_V1_INSTALL_ROOT}/venv" || rollback_ok=0
  fi
  if [[ "${LAYOUT_BACKUP_MOVED}" -eq 1 && -d "${BACKUP_ROOT}" ]]; then
    mv -- "${BACKUP_ROOT}" "${LEGACY_V1_BACKUP_ROOT}" || rollback_ok=0
  elif [[ -d "${BACKUP_ROOT}" ]]; then
    rmdir -- "${BACKUP_ROOT}" 2>/dev/null || true
  fi
  if [[ "${LAYOUT_USER_HOME_MOVED}" -eq 1 ]]; then
    usermod --home "${LEGACY_V1_DATA_ROOT}" vgen || rollback_ok=0
  fi
  systemctl daemon-reload || rollback_ok=0
  systemctl start "${SERVICE_NAME}" || rollback_ok=0
  gateway_local_health_with_retry || rollback_ok=0
  gateway_https_health_with_retry || rollback_ok=0
  if [[ "${rollback_ok}" -eq 1 ]]; then
    warn "legacy /vgen-v1 layout was restored and Gateway health passed"
  else
    warn "layout restoration needs manual inspection; backup: ${LAYOUT_MIGRATION_BACKUP_DIR}"
  fi
  exit "${status}"
}

verify_legacy_v1_layout_for_migration() {
  local new_path legacy_path legacy_home
  for new_path in "${INSTALL_ROOT}" "${DATA_ROOT}" "${CONFIG_ROOT}" "${BACKUP_ROOT}"; do
    [[ ! -e "${new_path}" && ! -L "${new_path}" ]] || \
      die "layout migration refused: new and /vgen-v1 paths are mixed: ${new_path}"
  done
  for legacy_path in \
    "${LEGACY_V1_INSTALL_ROOT}" "${LEGACY_V1_DATA_ROOT}" "${LEGACY_V1_CONFIG_ROOT}"; do
    [[ -d "${legacy_path}" && ! -L "${legacy_path}" ]] || \
      die "layout migration refused: legacy directory is missing or unsafe: ${legacy_path}"
  done
  [[ -d "${LEGACY_V1_INSTALL_ROOT}/venv" && \
     ! -L "${LEGACY_V1_INSTALL_ROOT}/venv" ]] || \
    die "layout migration refused: legacy runtime is missing or unsafe"
  [[ -f "${LEGACY_V1_DATA_ROOT}/vgen-gateway.db" && \
     ! -L "${LEGACY_V1_DATA_ROOT}/vgen-gateway.db" ]] || \
    die "layout migration refused: legacy database is missing or unsafe"
  [[ -f "${LEGACY_V1_CONFIG_ROOT}/gateway.env" && \
     ! -L "${LEGACY_V1_CONFIG_ROOT}/gateway.env" ]] || \
    die "layout migration refused: legacy Gateway environment is missing or unsafe"
  [[ -f "${LEGACY_V1_CONFIG_ROOT}/install-state.json" && \
     ! -L "${LEGACY_V1_CONFIG_ROOT}/install-state.json" ]] || \
    die "layout migration refused: legacy install state is missing or unsafe"
  [[ -f "${UNIT_PATH}" && ! -L "${UNIT_PATH}" ]] || \
    die "layout migration refused: systemd unit is missing or unsafe"
  [[ "$(stat -c '%a %U:%G' "${LEGACY_V1_DATA_ROOT}/vgen-gateway.db")" == \
     "600 vgen:vgen" ]] || die "layout migration refused: legacy database permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${LEGACY_V1_CONFIG_ROOT}/install-state.json")" == \
     "600 root:root" ]] || die "layout migration refused: legacy install state permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${UNIT_PATH}")" == "644 root:root" ]] || \
    die "layout migration refused: systemd unit permissions do not match"
  grep -Fq "ExecStart=${LEGACY_V1_INSTALL_ROOT}/venv/bin/vgen-gateway" "${UNIT_PATH}" || \
    die "layout migration refused: systemd unit does not use the legacy managed runtime"
  grep -Fq -- "--database ${LEGACY_V1_DATA_ROOT}/vgen-gateway.db" "${UNIT_PATH}" || \
    die "layout migration refused: systemd unit does not use the legacy managed database"
  verify_existing_gateway_environment "${LEGACY_V1_CONFIG_ROOT}/gateway.env"
  verify_upgrade_runtime_security "${LEGACY_V1_INSTALL_ROOT}/venv"
  legacy_home="$(getent passwd vgen | awk -F: '{print $6}')"
  [[ "${legacy_home}" == "${LEGACY_V1_DATA_ROOT}" || "${legacy_home}" == "${DATA_ROOT}" ]] || \
    die "layout migration refused: vgen user has an unexpected home directory"
  systemctl is-active --quiet "${SERVICE_NAME}" || \
    die "layout migration refused: Gateway service is not active"
  systemctl is-enabled --quiet "${SERVICE_NAME}" || \
    die "layout migration refused: Gateway service is not enabled"
  runuser -u vgen -- "${LEGACY_V1_INSTALL_ROOT}/venv/bin/vgen-gateway" \
    --database "${LEGACY_V1_DATA_ROOT}/vgen-gateway.db" doctor >/dev/null
  gateway_local_health_with_retry || die "layout migration refused: local Gateway health is not ready"
  gateway_https_health_with_retry || die "layout migration refused: public Gateway health is not ready"
}

migrate_legacy_v1_layout_if_needed() {
  local legacy_count=0 legacy_path stamp retained_backup legacy_home
  for legacy_path in \
    "${LEGACY_V1_INSTALL_ROOT}" "${LEGACY_V1_DATA_ROOT}" "${LEGACY_V1_CONFIG_ROOT}"; do
    [[ ! -e "${legacy_path}" && ! -L "${legacy_path}" ]] || legacy_count=$((legacy_count + 1))
  done
  if [[ "${legacy_count}" -eq 0 ]]; then
    return
  fi
  [[ "${legacy_count}" -eq 3 ]] || \
    die "layout migration refused: incomplete /vgen-v1 installation"
  log "migrating Gateway directories from /vgen-v1 to stable /vgen paths"
  verify_legacy_v1_layout_for_migration

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  LAYOUT_MIGRATION_BACKUP_DIR="$(mktemp -d "/var/backups/.vgen-layout-${stamp}.XXXXXX")"
  chmod 0700 "${LAYOUT_MIGRATION_BACKUP_DIR}"
  cp --preserve=mode,ownership,timestamps -- "${UNIT_PATH}" \
    "${LAYOUT_MIGRATION_BACKUP_DIR}/vgen-gateway.service"
  cp --preserve=mode,ownership,timestamps -- \
    "${LEGACY_V1_CONFIG_ROOT}/install-state.json" \
    "${LAYOUT_MIGRATION_BACKUP_DIR}/install-state.json"

  trap 'handle_layout_migration_error $?' ERR
  trap 'handle_layout_migration_error 130' INT
  trap 'handle_layout_migration_error 143' TERM
  trap 'handle_layout_migration_error 129' HUP
  systemctl stop "${SERVICE_NAME}"
  mv -- "${LEGACY_V1_INSTALL_ROOT}" "${INSTALL_ROOT}"
  LAYOUT_INSTALL_MOVED=1
  mv -- "${LEGACY_V1_DATA_ROOT}" "${DATA_ROOT}"
  LAYOUT_DATA_MOVED=1
  mv -- "${LEGACY_V1_CONFIG_ROOT}" "${CONFIG_ROOT}"
  LAYOUT_CONFIG_MOVED=1
  if [[ -d "${LEGACY_V1_BACKUP_ROOT}" && ! -L "${LEGACY_V1_BACKUP_ROOT}" ]]; then
    mv -- "${LEGACY_V1_BACKUP_ROOT}" "${BACKUP_ROOT}"
    LAYOUT_BACKUP_MOVED=1
  else
    [[ ! -e "${LEGACY_V1_BACKUP_ROOT}" && ! -L "${LEGACY_V1_BACKUP_ROOT}" ]] || false
    install -d -o root -g root -m 0700 "${BACKUP_ROOT}"
  fi
  relocate_python_runtime_scripts \
    "${LEGACY_V1_INSTALL_ROOT}/venv" "${INSTALL_ROOT}/venv"
  rewrite_migrated_install_state "${INSTALL_STATE_PATH}"
  legacy_home="$(getent passwd vgen | awk -F: '{print $6}')"
  if [[ "${legacy_home}" == "${LEGACY_V1_DATA_ROOT}" ]]; then
    usermod --home "${DATA_ROOT}" vgen
    LAYOUT_USER_HOME_MOVED=1
  fi
  install -o root -g root -m 0644 "${SERVICE_SOURCE_PATH}" "${UNIT_PATH}"
  LAYOUT_UNIT_REPLACED=1
  systemctl daemon-reload
  systemctl start "${SERVICE_NAME}"
  gateway_local_health_with_retry
  gateway_https_health_with_retry
  clear_layout_migration_traps

  retained_backup="${BACKUP_ROOT}/layout-migration-${stamp}"
  [[ ! -e "${retained_backup}" && ! -L "${retained_backup}" ]] || \
    die "layout migration backup destination already exists"
  mv -- "${LAYOUT_MIGRATION_BACKUP_DIR}" "${retained_backup}"
  LAYOUT_MIGRATION_BACKUP_DIR="${retained_backup}"
  log "Gateway directory layout migration completed"
  log "layout migration backup: ${LAYOUT_MIGRATION_BACKUP_DIR}"
}

verify_upgrade_preconditions() {
  [[ "${CONFIRM_UPGRADE}" -eq 1 ]] || die "upgrade requires --confirm-upgrade"
  verify_nginx_config_and_tls
  [[ -d "${INSTALL_ROOT}/venv" && ! -L "${INSTALL_ROOT}/venv" ]] || \
    die "upgrade refused: active Gateway runtime is missing or unsafe"
  [[ -f "${ENVIRONMENT_PATH}" && ! -L "${ENVIRONMENT_PATH}" ]] || \
    die "upgrade refused: Gateway environment is missing or unsafe"
  [[ -f "${DATABASE_PATH}" && ! -L "${DATABASE_PATH}" ]] || \
    die "upgrade refused: Gateway database is missing or unsafe"
  [[ -f "${UNIT_PATH}" && ! -L "${UNIT_PATH}" ]] || \
    die "upgrade refused: Gateway systemd unit is missing or unsafe"
  [[ -f "${INSTALL_STATE_PATH}" && ! -L "${INSTALL_STATE_PATH}" ]] || \
    die "upgrade refused: install state is missing or unsafe"
  [[ "$(stat -c '%a %U:%G' "${DATABASE_PATH}")" == "600 vgen:vgen" ]] || \
    die "upgrade refused: Gateway database permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${UNIT_PATH}")" == "644 root:root" ]] || \
    die "upgrade refused: Gateway systemd unit permissions do not match"
  [[ "$(stat -c '%a %U:%G' "${INSTALL_STATE_PATH}")" == "600 root:root" ]] || \
    die "upgrade refused: install state permissions do not match"
  if [[ -e "${BOOTSTRAP_PATH}" ]]; then
    [[ -f "${BOOTSTRAP_PATH}" && ! -L "${BOOTSTRAP_PATH}" ]] || \
      die "upgrade refused: Bootstrap code path is unsafe"
    [[ "$(stat -c '%a %U:%G' "${BOOTSTRAP_PATH}")" == "600 vgen:vgen" ]] || \
      die "upgrade refused: Bootstrap code permissions do not match"
  fi
  verify_root_owned_not_writable "${NGINX_CONFIG_PATH}" "current Nginx config"
  grep -Fq "ExecStart=${INSTALL_ROOT}/venv/bin/vgen-gateway" "${UNIT_PATH}" || \
    die "upgrade refused: current systemd unit does not use the managed runtime"
  grep -Fq -- "--database ${DATABASE_PATH}" "${UNIT_PATH}" || \
    die "upgrade refused: current systemd unit does not use the managed database"
  verify_existing_gateway_environment
  verify_upgrade_runtime_security
  verify_upgrade_install_state

  local expected_config previous_config version_order
  expected_config="$(mktemp "${NGINX_CONFIG_PATH}.upgrade-expected.XXXXXX")"
  previous_config="$(mktemp "${NGINX_CONFIG_PATH}.upgrade-previous.XXXXXX")"
  render_nginx_config "${expected_config}"
  render_previous_gateway_nginx_config "${previous_config}"
  if ! cmp --silent -- "${NGINX_CONFIG_PATH}" "${expected_config}" && \
     ! cmp --silent -- "${NGINX_CONFIG_PATH}" "${previous_config}"; then
    rm -f -- "${expected_config}" "${previous_config}"
    die "upgrade refused: public Nginx route is not the deterministic active Gateway route"
  fi
  rm -f -- "${expected_config}" "${previous_config}"
  nginx -t
  systemctl is-active --quiet "${SERVICE_NAME}" || \
    die "upgrade refused: Gateway service is not active"
  systemctl is-enabled --quiet "${SERVICE_NAME}" || \
    die "upgrade refused: Gateway service is not enabled"
  runuser -u vgen -- "${INSTALL_ROOT}/venv/bin/vgen-gateway" \
    --database "${DATABASE_PATH}" doctor >/dev/null
  gateway_local_health_with_retry || die "upgrade refused: local Gateway health is not ready"
  gateway_https_health_with_retry || die "upgrade refused: public Gateway health is not ready"

  version_order="$(compare_release_versions "${INSTALLED_VGEN_VERSION}" "${VGEN_VERSION}")"
  case "${version_order}" in
    -1)
      UPGRADE_ALREADY_TARGET=0
      ;;
    0)
      cmp --silent -- "${SERVICE_SOURCE_PATH}" "${UNIT_PATH}" || \
        die "upgrade refused: target runtime is installed but the reviewed systemd unit differs"
      UPGRADE_ALREADY_TARGET=1
      ;;
    1)
      die "upgrade refused: installed version ${INSTALLED_VGEN_VERSION} is newer than ${VGEN_VERSION}"
      ;;
    *)
      die "upgrade refused: version comparison failed"
      ;;
  esac
}

sqlite_online_backup() {
  local source_path="$1"
  local backup_path="$2"
  VGEN_SQLITE_SOURCE="${source_path}" VGEN_SQLITE_BACKUP="${backup_path}" python3.11 <<'PY'
import os
import sqlite3
from pathlib import Path

source_path = Path(os.environ["VGEN_SQLITE_SOURCE"])
backup_path = Path(os.environ["VGEN_SQLITE_BACKUP"])
descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.close(descriptor)
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
target = sqlite3.connect(backup_path)
try:
    source.backup(target)
    result = target.execute("PRAGMA quick_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"SQLite backup quick_check failed: {result}")
finally:
    target.close()
    source.close()
os.chmod(backup_path, 0o600)
PY
}

restore_sqlite_backup() {
  local backup_path="$1"
  local destination="$2"
  VGEN_SQLITE_BACKUP="${backup_path}" VGEN_SQLITE_DESTINATION="${destination}" python3.11 <<'PY'
import os
import sqlite3
from pathlib import Path

backup_path = Path(os.environ["VGEN_SQLITE_BACKUP"])
destination = Path(os.environ["VGEN_SQLITE_DESTINATION"])
source = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
target = sqlite3.connect(destination)
try:
    source.backup(target)
    result = target.execute("PRAGMA quick_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"restored SQLite quick_check failed: {result}")
    target.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
finally:
    target.close()
    source.close()
os.chmod(destination, 0o600)
PY
  chown vgen:vgen "${destination}"
}

stage_upgrade_runtime() {
  UPGRADE_CANDIDATE_RUNTIME="$(mktemp -d "${INSTALL_ROOT}/venv.candidate.${VGEN_VERSION}.XXXXXX")"
  log "staging Gateway ${VGEN_VERSION} in an isolated runtime"
  (
    umask 022
    python3.11 -m venv "${UPGRADE_CANDIDATE_RUNTIME}"
    "${UPGRADE_CANDIDATE_RUNTIME}/bin/python" -m pip install --disable-pip-version-check \
      "${WHEEL_PATH}[gateway,oss]"
  )
  normalize_and_verify_runtime_at "${UPGRADE_CANDIDATE_RUNTIME}" "${VGEN_VERSION}"
  verify_artifact_store_access_at "${UPGRADE_CANDIDATE_RUNTIME}"
}

backup_upgrade_config_and_preflight_database() {
  local stamp preflight_database
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  UPGRADE_BACKUP_DIR="$(mktemp -d "${BACKUP_ROOT}/gateway-upgrade-${stamp}.XXXXXX")"
  chmod 0700 "${UPGRADE_BACKUP_DIR}"
  cp --preserve=mode,ownership,timestamps -- "${UNIT_PATH}" \
    "${UPGRADE_BACKUP_DIR}/vgen-gateway.service"
  cp --preserve=mode,ownership,timestamps -- "${ENVIRONMENT_PATH}" \
    "${UPGRADE_BACKUP_DIR}/gateway.env"
  cp --preserve=mode,ownership,timestamps -- "${INSTALL_STATE_PATH}" \
    "${UPGRADE_BACKUP_DIR}/install-state.json"
  cp --preserve=mode,ownership,timestamps -- "${NGINX_CONFIG_PATH}" \
    "${UPGRADE_BACKUP_DIR}/nginx-vgen.conf"
  if [[ -f "${BOOTSTRAP_PATH}" && ! -L "${BOOTSTRAP_PATH}" ]]; then
    cp --preserve=mode,ownership,timestamps -- "${BOOTSTRAP_PATH}" \
      "${UPGRADE_BACKUP_DIR}/bootstrap-code"
  fi
  UPGRADE_CONFIG_BACKED_UP=1

  preflight_database="${UPGRADE_BACKUP_DIR}/preflight-vgen-gateway.db"
  sqlite_online_backup "${DATABASE_PATH}" "${preflight_database}"
  "${UPGRADE_CANDIDATE_RUNTIME}/bin/vgen-gateway" \
    --database "${preflight_database}" doctor >/dev/null
  log "reviewed runtime passed an isolated database migration preflight"
}

create_stopped_upgrade_database_backup() {
  local final_backup="${UPGRADE_BACKUP_DIR}/vgen-gateway.db"
  sqlite_online_backup "${DATABASE_PATH}" "${final_backup}"
  UPGRADE_DATABASE_BACKUP="${final_backup}"
  log "Gateway SQLite backup: ${UPGRADE_DATABASE_BACKUP}"
  log "Gateway SQLite backup SHA-256: $(sha256_of "${UPGRADE_DATABASE_BACKUP}")"
}

swap_upgrade_runtime() {
  local candidate_runtime="${UPGRADE_CANDIDATE_RUNTIME}"
  UPGRADE_PREVIOUS_RUNTIME="$(mktemp -d \
    "${INSTALL_ROOT}/venv.previous.${INSTALLED_VGEN_VERSION}.XXXXXX")"
  rmdir -- "${UPGRADE_PREVIOUS_RUNTIME}"
  mv -- "${INSTALL_ROOT}/venv" "${UPGRADE_PREVIOUS_RUNTIME}"
  UPGRADE_OLD_RUNTIME_MOVED=1
  mv -- "${candidate_runtime}" "${INSTALL_ROOT}/venv"
  UPGRADE_CANDIDATE_RUNTIME=""
  relocate_python_runtime_scripts "${candidate_runtime}" "${INSTALL_ROOT}/venv"
  normalize_and_verify_runtime_at "${INSTALL_ROOT}/venv" "${VGEN_VERSION}"
}

install_upgrade_nginx_config() {
  local generated_path
  generated_path="$(mktemp "${NGINX_CONFIG_PATH}.upgrade-candidate.XXXXXX")"
  render_nginx_config "${generated_path}"
  chown root:root "${generated_path}"
  chmod 0644 "${generated_path}"
  UPGRADE_NGINX_REPLACED=1
  mv -f -- "${generated_path}" "${NGINX_CONFIG_PATH}"
  nginx -t
  systemctl reload nginx
}

atomic_restore_upgrade_config() {
  local source_path="$1"
  local destination="$2"
  local mode="$3"
  local candidate
  candidate="$(mktemp "${destination}.upgrade-restore.XXXXXX")"
  install -o root -g root -m "${mode}" "${source_path}" "${candidate}"
  mv -f -- "${candidate}" "${destination}"
}

clear_upgrade_traps() {
  trap - ERR INT TERM HUP
}

handle_upgrade_error() {
  local status="$1"
  local rollback_ok=1
  local failed_runtime=""
  clear_upgrade_traps
  set +e
  ((status == 0)) && status=1
  warn "Gateway upgrade failed; restoring the previous runtime, database and service configuration"
  systemctl stop "${SERVICE_NAME}" || rollback_ok=0

  if [[ "${UPGRADE_OLD_RUNTIME_MOVED}" -eq 1 && -d "${UPGRADE_PREVIOUS_RUNTIME}" ]]; then
    if [[ -d "${INSTALL_ROOT}/venv" || -L "${INSTALL_ROOT}/venv" ]]; then
      failed_runtime="$(mktemp -d "${INSTALL_ROOT}/venv.failed.${VGEN_VERSION}.XXXXXX")"
      rmdir -- "${failed_runtime}" || rollback_ok=0
      mv -- "${INSTALL_ROOT}/venv" "${failed_runtime}" || rollback_ok=0
    fi
    if [[ ! -e "${INSTALL_ROOT}/venv" ]]; then
      mv -- "${UPGRADE_PREVIOUS_RUNTIME}" "${INSTALL_ROOT}/venv" || rollback_ok=0
    else
      rollback_ok=0
    fi
  fi

  if [[ -n "${UPGRADE_DATABASE_BACKUP}" && -f "${UPGRADE_DATABASE_BACKUP}" ]]; then
    if [[ -f "${DATABASE_PATH}" && ! -L "${DATABASE_PATH}" ]]; then
      sqlite_online_backup "${DATABASE_PATH}" \
        "${UPGRADE_BACKUP_DIR}/failed-vgen-gateway.db" || rollback_ok=0
    fi
    restore_sqlite_backup "${UPGRADE_DATABASE_BACKUP}" "${DATABASE_PATH}" || rollback_ok=0
  fi

  if [[ "${UPGRADE_CONFIG_BACKED_UP}" -eq 1 ]]; then
    atomic_restore_upgrade_config "${UPGRADE_BACKUP_DIR}/vgen-gateway.service" \
      "${UNIT_PATH}" 0644 || rollback_ok=0
    atomic_restore_upgrade_config "${UPGRADE_BACKUP_DIR}/gateway.env" \
      "${ENVIRONMENT_PATH}" 0600 || rollback_ok=0
    atomic_restore_upgrade_config "${UPGRADE_BACKUP_DIR}/install-state.json" \
      "${INSTALL_STATE_PATH}" 0600 || rollback_ok=0
    if [[ "${UPGRADE_NGINX_REPLACED}" -eq 1 ]]; then
      atomic_restore_upgrade_config "${UPGRADE_BACKUP_DIR}/nginx-vgen.conf" \
        "${NGINX_CONFIG_PATH}" 0644 || rollback_ok=0
      nginx -t || rollback_ok=0
      systemctl reload nginx || rollback_ok=0
    fi
  fi

  systemctl daemon-reload || rollback_ok=0
  systemctl start "${SERVICE_NAME}" || rollback_ok=0
  if ! gateway_local_health_with_retry; then
    rollback_ok=0
  fi
  if ! gateway_https_health_with_retry; then
    rollback_ok=0
  fi
  if [[ "${rollback_ok}" -eq 1 ]]; then
    warn "previous Gateway ${INSTALLED_VGEN_VERSION} was restored and passed local/public health checks"
  else
    warn "automatic restoration did not pass every check; inspect ${UPGRADE_BACKUP_DIR} and ${SERVICE_NAME}"
  fi
  exit "${status}"
}

upgrade_gateway() {
  require_root
  require_command awk
  require_command cmp
  require_command cp
  require_command curl
  require_command env
  require_command flock
  require_command getent
  require_command grep
  require_command install
  require_command mktemp
  require_command mv
  require_command nginx
  require_command python3.11
  require_command rmdir
  require_command runuser
  require_command sha256sum
  require_command stat
  require_command systemctl
  require_command usermod

  acquire_mutation_lock
  verify_release_bundle
  migrate_legacy_v1_layout_if_needed
  verify_upgrade_preconditions
  if [[ "${UPGRADE_ALREADY_TARGET}" -eq 1 ]]; then
    log "Gateway ${VGEN_VERSION} is already installed and healthy locally and publicly"
    log "no files, database rows or services were changed"
    return
  fi

  stage_upgrade_runtime
  backup_upgrade_config_and_preflight_database

  trap 'handle_upgrade_error $?' ERR
  trap 'handle_upgrade_error 130' INT
  trap 'handle_upgrade_error 143' TERM
  trap 'handle_upgrade_error 129' HUP
  install -d -o root -g root -m 0755 "${RELEASE_ROOT}"
  install_upgrade_nginx_config
  systemctl stop "${SERVICE_NAME}"
  create_stopped_upgrade_database_backup
  swap_upgrade_runtime
  install -o root -g root -m 0644 "${SERVICE_SOURCE_PATH}" "${UNIT_PATH}"
  runuser -u vgen -- "${INSTALL_ROOT}/venv/bin/vgen-gateway" \
    --database "${DATABASE_PATH}" doctor >/dev/null
  systemctl daemon-reload
  systemctl start "${SERVICE_NAME}"
  gateway_local_health_with_retry
  gateway_https_health_with_retry
  clear_upgrade_traps

  log "Gateway upgraded from ${INSTALLED_VGEN_VERSION} to ${VGEN_VERSION}"
  log "previous runtime retained at ${UPGRADE_PREVIOUS_RUNTIME}"
  log "database and service configuration backup retained at ${UPGRADE_BACKUP_DIR}"
  log "Bootstrap code, Gateway environment and install state were not replaced"
  log "Nginx Gateway virtual host is API-only; releases use the separate download host"
}

reset_test_gateway() {
  require_root
  require_command flock
  require_command install
  require_command mktemp
  require_command mv
  require_command systemctl
  [[ "${CONFIRM_RESET_TEST}" -eq 1 ]] || die "reset-test requires --confirm-reset-test"
  [[ "${CONFIRM_NO_ACTIVE_TASKS}" -eq 1 ]] || \
    die "reset-test requires --confirm-no-active-tasks"

  acquire_mutation_lock
  local source backup_dir found=0
  [[ ! -L "${BACKUP_ROOT}" ]] || die "reset-test refused: backup root is a symbolic link"
  for source in "${INSTALL_ROOT}" "${DATA_ROOT}" "${CONFIG_ROOT}" "${UNIT_PATH}"; do
    if [[ -L "${source}" ]]; then
      die "reset-test refused: managed path is a symbolic link: ${source}"
    fi
    [[ -e "${source}" ]] && found=1
  done
  [[ "${found}" -eq 1 ]] || die "reset-test refused: no managed Gateway installation exists"

  install -d -o root -g root -m 0700 "${BACKUP_ROOT}"
  backup_dir="$(mktemp -d "${BACKUP_ROOT}/gateway-test-reset-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
  chmod 0700 "${backup_dir}"
  systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true

  [[ ! -e "${INSTALL_ROOT}" ]] || mv -- "${INSTALL_ROOT}" "${backup_dir}/opt-vgen"
  [[ ! -e "${DATA_ROOT}" ]] || mv -- "${DATA_ROOT}" "${backup_dir}/var-lib-vgen"
  [[ ! -e "${CONFIG_ROOT}" ]] || mv -- "${CONFIG_ROOT}" "${backup_dir}/etc-vgen"
  [[ ! -e "${UNIT_PATH}" ]] || mv -- "${UNIT_PATH}" "${backup_dir}/vgen-gateway.service"
  systemctl daemon-reload
  systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true

  log "test Gateway runtime, data and service configuration were archived"
  log "test reset backup: ${backup_dir}"
  log "Nginx, TLS certificates, release downloads, RAM Role and OSS objects were not changed"
  log "run the install action next to initialize a new User/Workspace database"
}

print_mac_bootstrap_steps() {
  printf '\nNext steps:\n'
  printf '  1. Start the downloaded Mac installer.\n'
  printf '  2. When it asks for the one-time Bootstrap code, return to this SSH window and run:\n'
  printf '       sudo cat %s\n' "${BOOTSTRAP_PATH}"
  printf '  3. Paste it only into the hidden VGen prompt, never into a command, chat, or screenshot.\n'
  printf '  4. After Mac setup succeeds, remove the consumed local copy:\n'
  printf '       sudo rm -f %s\n' "${BOOTSTRAP_PATH}"
  printf '\nManual Mac command if needed:\n  vgen setup --gateway https://%s\n' "${DOMAIN}"
}

install_gateway() {
  require_root
  require_command awk
  require_command cmp
  require_command cp
  require_command curl
  require_command env
  require_command flock
  require_command getent
  require_command grep
  require_command groupadd
  require_command install
  require_command journalctl
  require_command mktemp
  require_command mv
  require_command nginx
  require_command python3.11
  require_command runuser
  require_command sha256sum
  require_command stat
  require_command systemctl
  require_command tr
  require_command useradd

  acquire_mutation_lock
  verify_release_bundle
  validate_artifact_store_options
  write_oss_setup_kit
  verify_install_preconditions
  check_legacy_task_status
  ensure_service_user_and_directories
  backup_legacy_database
  install_python_runtime
  write_gateway_environment
  verify_artifact_store_access_at "${INSTALL_ROOT}/venv"
  initialize_gateway
  install_and_start_service
  switch_nginx

  log "installation complete"
  log "bootstrap code remains protected at ${BOOTSTRAP_PATH} until the first Mac claims it"
  log "the legacy service was left untouched for rollback"
  log "task artifacts use private OSS through object-scoped STS credentials"
  log "RAM/IAM policy was not modified"
  print_mac_bootstrap_steps
}

resume_gateway() {
  require_root
  require_command awk
  require_command curl
  require_command env
  require_command flock
  require_command getent
  require_command grep
  require_command groupadd
  require_command install
  require_command journalctl
  require_command mktemp
  require_command mv
  require_command nginx
  require_command python3.11
  require_command runuser
  require_command sha256sum
  require_command stat
  require_command systemctl
  require_command tr
  require_command useradd

  acquire_mutation_lock
  verify_release_bundle
  verify_resume_preconditions
  check_legacy_task_status
  ensure_service_user_and_directories
  verify_existing_gateway_environment
  prepare_resume_runtime
  verify_artifact_store_access_at "${INSTALL_ROOT}/venv"
  initialize_gateway
  install_and_start_service
  switch_nginx

  log "partial installation resumed successfully"
  log "bootstrap code remains protected at ${BOOTSTRAP_PATH} until the first Mac claims it"
  log "the legacy service was left untouched for rollback"
  log "existing ArtifactStore configuration was preserved; RAM/IAM was not modified"
  print_mac_bootstrap_steps
}

activate_gateway() {
  require_root
  require_command awk
  require_command cmp
  require_command curl
  require_command flock
  require_command grep
  require_command mktemp
  require_command mv
  require_command nginx
  require_command python3.11
  require_command sha256sum
  require_command stat
  require_command systemctl

  acquire_mutation_lock
  verify_release_bundle
  verify_activation_preconditions
  verify_existing_gateway_environment
  verify_existing_python_runtime

  if [[ "${ACTIVATION_ALREADY_ACTIVE}" -eq 1 ]]; then
    log "Gateway v1 is already active with the deterministic Nginx config and strict health"
    log "no files or services were changed"
    print_mac_bootstrap_steps
    return
  fi

  switch_nginx "${ACTIVATION_BACKUP_PATH}" 1

  log "Gateway v1 public HTTPS activation completed"
  log "existing install state and legacy backup were reused without modification"
  print_mac_bootstrap_steps
}

read_install_state_field() {
  local field="$1"
  VGEN_STATE_PATH="${INSTALL_STATE_PATH}" VGEN_STATE_FIELD="${field}" python3.11 <<'PY'
import json
import os

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate install-state key: {key}")
        result[key] = value
    return result

with open(os.environ["VGEN_STATE_PATH"], encoding="utf-8") as handle:
    payload = json.load(handle, object_pairs_hook=unique_object)
value = payload.get(os.environ["VGEN_STATE_FIELD"])
if not isinstance(value, str) or not value:
    raise SystemExit(1)
print(value)
PY
}

rollback_gateway_route() {
  require_root
  require_command cmp
  require_command flock
  require_command mktemp
  require_command mv
  require_command nginx
  require_command python3.11
  require_command systemctl
  acquire_mutation_lock
  [[ "${CONFIRM_ROLLBACK}" -eq 1 ]] || die "rollback requires --confirm-rollback"
  [[ -f "${INSTALL_STATE_PATH}" && ! -L "${INSTALL_STATE_PATH}" ]] || \
    die "install state was not found at ${INSTALL_STATE_PATH}"

  verify_root_owned_not_writable "${NGINX_CONFIG_PATH}" "current Nginx config"
  verify_root_owned_not_writable "${INSTALL_STATE_PATH}" "install state"

  local state_domain state_config backup_path current_copy
  state_domain="$(read_install_state_field domain)"
  state_config="$(read_install_state_field nginx_config)"
  backup_path="$(read_install_state_field nginx_backup)"
  [[ "${state_domain}" == "${DOMAIN}" ]] || die "install state belongs to ${state_domain}, not ${DOMAIN}"
  [[ "${state_config}" == "${NGINX_CONFIG_PATH}" ]] || \
    die "install state names an unexpected Nginx config"
  verify_nginx_backup_path "${backup_path}"
  [[ -f "${backup_path}" && ! -L "${backup_path}" ]] || die "saved Nginx backup is missing"
  verify_root_owned_not_writable "${backup_path}" "saved Nginx backup"

  current_copy="$(mktemp "${NGINX_CONFIG_PATH}.rollback-current.XXXXXX")"
  cp --preserve=mode,ownership,timestamps -- "${NGINX_CONFIG_PATH}" "${current_copy}"
  if ! atomic_replace_nginx_config "${backup_path}" || ! nginx -t; then
    atomic_replace_nginx_config "${current_copy}" || true
    rm -f -- "${current_copy}"
    nginx -t || true
    die "saved legacy Nginx configuration is invalid; current v1 route was preserved"
  fi
  if ! systemctl reload nginx; then
    atomic_replace_nginx_config "${current_copy}" || true
    nginx -t && systemctl reload nginx || true
    rm -f -- "${current_copy}"
    die "legacy Nginx reload failed; current v1 route was restored"
  fi
  rm -f -- "${current_copy}"
  log "Nginx route was rolled back to the saved legacy configuration"
  log "Gateway v1 is still running locally on 127.0.0.1:${GATEWAY_PORT} for inspection"
}

show_status() {
  require_root
  require_command curl
  require_command systemctl
  printf 'domain=%s\n' "${DOMAIN}"
  printf 'installed_version='
  if [[ -x "${INSTALL_ROOT}/venv/bin/python" ]]; then
    read_runtime_version "${INSTALL_ROOT}/venv" 2>/dev/null || printf 'unknown\n'
  else
    printf 'missing\n'
  fi
  printf 'gateway_service='
  systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true
  printf 'legacy_service='
  systemctl is-active vgen-server.service 2>/dev/null || true
  printf 'local_v1_health='
  if curl --fail --silent --max-time 3 \
    "http://127.0.0.1:${GATEWAY_PORT}/api/v1/health" >/dev/null; then
    printf 'ok\n'
  else
    printf 'unavailable\n'
  fi
  printf 'public_v1_health='
  if curl --fail --silent --max-time 10 "https://${DOMAIN}/api/v1/health" >/dev/null; then
    printf 'ok\n'
  else
    printf 'unavailable\n'
  fi
  if [[ -f "${INSTALL_STATE_PATH}" ]]; then
    printf 'install_state=%s\n' "${INSTALL_STATE_PATH}"
  else
    printf 'install_state=missing\n'
  fi
}

main() {
  parse_arguments "$@"
  validate_domain
  case "${ACTION}" in
    install)
      collect_interactive_confirmations
      validate_confirmation
      collect_interactive_oss_options
      validate_artifact_store_options
      install_gateway
      ;;
    resume)
      collect_interactive_confirmations
      validate_confirmation
      resume_gateway
      ;;
    activate)
      collect_interactive_confirmations
      validate_confirmation
      activate_gateway
      ;;
    upgrade)
      collect_interactive_confirmations
      validate_confirmation
      upgrade_gateway
      ;;
    reset-test)
      collect_interactive_confirmations
      validate_confirmation
      reset_test_gateway
      ;;
    rollback)
      collect_interactive_confirmations
      validate_confirmation
      rollback_gateway_route
      ;;
    status)
      [[ -z "${CONFIRM_DOMAIN}" ]] || validate_confirmation
      show_status
      ;;
  esac
}

if [[ "${VGEN_SETUP_LIBRARY_ONLY:-0}" != "1" ]]; then
  main "$@"
fi
