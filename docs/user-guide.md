# VGen User Guide

English | [简体中文](zh-CN/user-guide.md)

This is the single operations handbook for VGen deployers and users. It covers
the ECS Gateway, Mac CLI/Home Broker, Windows GPU Worker, model downloads,
Worker updates, and real video jobs. Development, builds, and releases are
covered in the [Developer and Release Guide](developer-guide.md).

Placeholders used below:

- `<version>`: a release version such as `0.8.4`;
- `<gateway-domain>`: the API control-plane DNS name, such as
  `gateway.example.com`, without `https://`;
- `<release-domain>`: the CLI/Worker download site, such as
  `downloads.example.com`;
- `<job_id>`, `<worker_id>`, and `<enrollment_id>`: real IDs printed by the CLI.
  Do not type the angle brackets.

## 1. Architecture and installation order

```text
ECS Gateway (public HTTPS control plane and encrypted task state)
        ^
        +-- Administrator Mac CLI / Home Broker (manages Workspace and Workers)
        +-- Other Mac CLIs (join, submit jobs; no Broker required)
        +-- Windows Worker + ComfyUI (GPU inference, models, and outputs)
```

Install the components in this order:

1. Install or upgrade the Gateway on ECS and verify its public health endpoint.
2. Install the CLI/Home Broker on the administrator's Mac and initialize the
   first identity and Workspace.
3. Install the CLI on other Macs and join them to the Workspace.
4. Install ComfyUI Desktop or extract ComfyUI Portable on Windows.
5. Run the universal Worker installer and complete its one-time enrollment with
   the Mac.
6. If models are missing, start the model-install job from the Mac Home Broker.
7. Submit real zero-, one-, and two-image jobs for acceptance.

The Gateway runs under systemd. The installer configures the Mac Home Broker as
a per-user LaunchAgent. The Windows Worker currently requires its foreground
PowerShell window to remain open. The installer creates a stable `VGen Worker`
Desktop shortcut for starting it again after a reboot, but it is not installed
as a Windows Service and does not start automatically at boot.

> Installing a workflow does not download its model weights. Initialization
> installs the `vgen/minimax-h3-8step` manifest, parameter definitions, and
> ComfyUI graph on the Mac. Model weights live in the Windows model directory
> and must be installed as described in section 6.

## 2. Packages, prerequisites, and verification

| File | Purpose |
|---|---|
| `vgen-gateway-<version>.tar.gz` | Fresh Gateway install or in-place upgrade |
| `VGen-macOS-<version>.zip` | Mac CLI/Home Broker install or recovery |
| `vgen-windows-worker-installer-<version>.zip` | Public credential-free Windows installer |
| `vgen-<version>-py3-none-any.whl` | Reviewed remote VGen Worker update |

The Windows installer is universal. It contains no Worker ID, invite, session,
or private key. Each Windows machine creates its own keys during enrollment.

Before starting:

- download from a trusted Release page and compare the published package
  SHA-256;
- configure the ECS domains and valid HTTPS certificates, and install Python
  3.11+, Nginx, and systemd;
- install Python 3.11+ on the Mac and allow access to PyPI;
- install ComfyUI Desktop or prepare the official Portable build on Windows;
  MiniMax H3 requires ComfyUI 0.30.0 or later;
- never expose the Gateway's internal port `8010` or ComfyUI port `8188` to the
  public internet.

After extracting the Gateway package, verify its contents:

```bash
sha256sum -c SHA256SUMS
```

VGen uses separate HTTPS origins. `https://<gateway-domain>` serves `/api/v1`;
`https://<release-domain>` serves public installers. The stable manifest and
bootstrap scripts verify origin, size, and SHA-256 and reject cross-origin or
non-HTTPS downloads. These controls detect transfer or storage corruption, but
they are not publisher signatures. The current ZIPs are not yet Apple-notarized
or Authenticode-signed.

<!-- VGEN_GATEWAY_INSTALL_BEGIN -->

## 3. ECS Gateway

Every `setup-gateway.sh` action below includes `--domain <gateway-domain>`.
Omit `sudo` when already logged in as root.

Point both DNS names to the ECS host and prepare certificates. Configure the
read-only release route once after extracting the Gateway package:

```bash
sudo ./setup-release-site.sh install --domain <release-domain>
```

This route serves only `https://<release-domain>/releases/`. The Gateway
installer configures the API reverse proxy only for `<gateway-domain>`. Both
names may initially use one ECS host and the release origin may later move to
OSS/CDN independently.

### 3.1 Fresh install

Stop old Workers from claiming jobs, wait for active jobs, then unpack privately:

```bash
install -d -m 0700 /root/vgen-gateway-install
tar -xzf /root/vgen-gateway-<version>.tar.gz \
  -C /root/vgen-gateway-install --strip-components=1
cd /root/vgen-gateway-install
sha256sum -c SHA256SUMS
```

The Gateway must store task images and videos in a private OSS bucket, not on
the ECS system disk. Release packages may remain under
`/var/www/vgen-releases`; release storage and task artifact storage are
independent.

On its first run, the installer writes deployment-specific RAM policies and a
`README.txt` under `/var/tmp/vgen-oss-setup-<gateway-domain>/`. The generated
files contain no AccessKey. Apply them in the Alibaba Cloud console, then rerun:

```bash
sudo ./setup-gateway.sh install \
  --domain <gateway-domain> \
  --artifact-store oss \
  --oss-endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --oss-bucket <private-bucket> \
  --oss-prefix vgen/v1 \
  --oss-ecs-role <ecs-ram-role-name> \
  --aliyun-account-id <aliyun-account-id> \
  --oss-transfer-role VGenArtifactTransferRole \
  --confirm-oss-configured
```

The Gateway uses the ECS identity to call STS and narrows temporary credentials
to one object and one transfer direction. The CLI and Worker transfer encrypted
media directly to OSS. The Gateway only checks object metadata with `HEAD`.
Keep the bucket private and configure lifecycle rules for task retention and
abandoned multipart uploads.

The reference Nginx policy limits normal control requests to 16 MiB and public
bootstrap/login/recovery/invite requests to 64 KiB. Media must continue to use
direct OSS transfer; do not raise control-plane limits to accept media. The
reference deployment overwrites client-supplied `X-Forwarded-For` with the
connection source. Before adding a CDN or load balancer, configure only its
exact egress CIDRs as trusted proxies and retest rate limiting.

If installation stopped after creating the runtime and `gateway.env`, but
before database initialization, use the fixed release package to resume:

```bash
sudo ./setup-gateway.sh resume --domain <gateway-domain>
```

For a disposable development reset, archive the managed Gateway state with:

```bash
sudo ./setup-gateway.sh reset-test --domain <gateway-domain>
```

`reset-test` moves runtime, SQLite data, bootstrap material, and service config
to `/var/backups/vgen/gateway-test-reset-*`. It does not delete Nginx, TLS,
release files, RAM roles, or OSS objects. Never use it for a production system
that contains data.

### 3.2 In-place upgrade

Do not clear the database or bootstrap an existing Gateway again:

```bash
install -d -m 0700 /root/vgen-gateway-upgrade
tar -xzf /root/vgen-gateway-<version>.tar.gz \
  -C /root/vgen-gateway-upgrade --strip-components=1
cd /root/vgen-gateway-upgrade
sha256sum -c SHA256SUMS
sudo ./setup-gateway.sh upgrade --domain <gateway-domain>
```

The installer backs up the database, runtime, and configuration and
automatically restores the previous version if health checks fail. Repeating an
upgrade to the same healthy version is idempotent.

Owners of Workspaces created before signed Owner pins were introduced must
upgrade the CLI and run `vgen workspace owner-migrate`. Verify every identifier
shown by the command. Key grants and rotations fail closed until migration is
complete.

### 3.3 Status, activation, and route rollback

```bash
sudo ./setup-gateway.sh status --domain <gateway-domain>
curl --fail --silent https://<gateway-domain>/healthz
vgen gateway health
```

The public `/healthz` response contains only `"ok":true`. An authenticated
Gateway operator can run `vgen gateway health` to read `/api/v1/status`, where
Worker counts have distinct meanings:

- `workers_total`: all Worker records, including revoked records;
- `workers_active`: admitted Workers, whether online or not;
- `workers_online`: active Workers with a heartbeat in the last 120 seconds;
- `workers_revoked`: Workers that can no longer connect.

If the local Gateway is healthy but a transient 502 caused the Nginx switch to
roll back, activate it explicitly:

```bash
sudo ./setup-gateway.sh activate --domain <gateway-domain>
```

Restore only the previously saved Nginx route with:

```bash
sudo ./setup-gateway.sh rollback --domain <gateway-domain>
```

This does not delete deployment data and is not a general database downgrade.

### 3.4 First bootstrap code

Only the first Mac after a fresh installation needs the bootstrap code. Wait
until the Mac installer shows its hidden prompt, then display the code on ECS:

```bash
sudo cat /var/lib/vgen/bootstrap-code
```

Paste it only into the hidden prompt. Never put it in a command, chat, ticket,
screenshot, or shell history. After initialization, delete the expired copy:

```bash
sudo rm -f /var/lib/vgen/bootstrap-code
```

<!-- VGEN_GATEWAY_INSTALL_END -->

## 4. Mac CLI and Home Broker

### 4.1 First install

1. Verify the Release-page SHA-256 for `VGen-macOS-<version>.zip` and extract it.
2. Open `install.command`. If Gatekeeper blocks it, right-click and choose Open.
3. Enter a display name, record the 24 recovery words offline in order, and
   complete the confirmation.
4. Paste the bootstrap code into the hidden prompt when requested.
5. Wait for explicit confirmation that initialization completed and the Home
   Broker is online.

The installer creates the User, default Workspace, default GPU Pool, Logical
Home Broker, Broker Device, and official workflow manifest. Recovery words must
never be uploaded or shared. A bootstrap code cannot replace them.

### 4.2 Upgrade and recovery

After the first managed installation, upgrade in place:

```bash
vgen upgrade
vgen upgrade --check
```

The CLI verifies the pinned release origin, immutable manifest, package size,
SHA-256, ZIP paths, and internal `SHA256SUMS`. It switches the launcher only
after validating the new CLI and refreshes the Home Broker. A post-install
failure restores the old CLI and Broker. Identity and Workspace configuration
remain unchanged. Use `vgen upgrade --yes` only in approved automation.

To migrate a Gateway endpoint safely:

```bash
vgen profile endpoint-set https://<new-gateway-domain> --profile home
vgen broker service-refresh --profile home
```

The command health-checks and authenticates to the new endpoint as the same
principal before saving it. Gateway migration does not change the independently
pinned release origin. Verify the result:

```bash
vgen profile show
vgen gateway health
vgen broker status
vgen broker local-status
```

### 4.3 Join another Mac

For a person with no VGen User profile on that Mac, the Workspace Owner creates:

```bash
vgen workspace invite --kind user --method direct_invite \
  --relationship member --wait
```

For an existing User joining another Workspace, use:

```bash
vgen workspace invite --kind workspace_member --method direct_invite \
  --relationship member --wait
```

The invite types are not interchangeable. Send the full one-time URI only over
a trusted one-to-one channel, never in a group, ticket, screenshot, or command
argument. On the new Mac:

```bash
curl -fsSL https://downloads.example.com/releases/install-macos.sh | bash
vgen join --gateway https://gateway.example.com
```

Paste the invite into the hidden prompt and send the displayed five-part
verification code back over the trusted channel. The Owner compares it before
signing admission and granting the Workspace key. If the waiting Owner command
has exited:

```bash
vgen workspace key-grant-enrollment <enrollment_id> \
  --verification-code <five-part-verification-code>
```

For `invite_approval`, approval and key admission are combined:

```bash
vgen workspace decide <enrollment_id> --approve \
  --verification-code <five-part-verification-code>
```

If approval was pending, the joining Mac resumes without reusing the invite:

```bash
vgen join --resume
```

## 5. Windows Worker and ComfyUI

### 5.1 Install and enroll

Install ComfyUI Desktop or extract the official Portable package. Start a local
Standalone once when using Desktop's multi-instance manager. In a normal
PowerShell window run:

```powershell
irm https://<release-domain>/releases/install-windows-worker.ps1 | iex
```

At the same time, the Workspace Owner runs on the Mac:

```bash
vgen worker add --name "Windows GPU Worker" --pool "Default GPU Pool"
```

Omit `--pool` when there is only one Pool. Paste the one-time invite into the
hidden Windows prompt, then enter the Windows verification code into the
waiting Mac command. The Mac signs the Worker certificate and approves its Pool
and rate; Windows then detects ComfyUI and starts the Worker.

### 5.2 Runtime behavior and retry

The installer prepares an isolated VGen runtime and custom-node directories,
starts ComfyUI only on `127.0.0.1:8188` when needed, and runs the Worker in the
foreground. Missing models do not fail installation; the Worker comes online
in `maintenance-only` mode so the Broker can install them.

Keep `%LOCALAPPDATA%\VGen` when repairing or reenrolling. The installer safely
reuses reviewed, pinned custom-node repositories and preserves models. Keep one
PowerShell window open after polling starts. `Ctrl+C` stops the Worker and any
ComfyUI instance started by the supervisor. Logs are under
`%LOCALAPPDATA%\VGen\logs`.

The installer creates `%LOCALAPPDATA%\VGen\start-worker.cmd` and a `VGen Worker`
shortcut on the current user's Desktop. After Windows restarts, exit any ComfyUI
instance that was opened separately, double-click that same shortcut, and keep
the resulting PowerShell window open. The shortcut always targets the stable
launcher; a later reviewed installer updates the launcher's internal version
target without changing the shortcut. Rerunning the public `irm` command is not
required for an ordinary restart.

### 5.3 Desktop, Portable, and custom data roots

The installer checks standard Desktop and Portable locations and asks when
multiple installations are found, listing numbered choices in the current
window. If default locations do not resolve the installation, it asks for an
explicit root and never scans the entire disk. If needed, specify code and data
roots:

```powershell
.\setup-worker.ps1 `
  -ComfyUIRoot "D:\ComfyUI_windows_portable\ComfyUI" `
  -ComfyUIDataRoot "D:\ComfyUI-data"
```

Run a read-only prerequisite check with:

```powershell
.\setup-worker.ps1 -CheckOnly
```

VGen never writes into Program Files or overwrites the user's custom nodes.
The installer tightens the Windows ACL on local credentials automatically; the
user does not need to run `icacls` first.

### 5.4 Reinstall or reenroll

For a normal repair, stop the foreground Worker and rerun the public installer.
It authenticates with the existing local key and preserves the same Worker ID.
Do not delete credentials, ComfyUI, models, or `%LOCALAPPDATA%\VGen`.

Network failures, Gateway outages, and signature mismatches preserve the old
credential and stop safely. Use reenrollment only after confirming that the
credential belongs to the intended Gateway and that the old Worker identity is
invalid. Run the exact path printed by the installer:

```powershell
& "<full-path-from-error>\start-worker.cmd" -Reenroll
```

The old credential remains active until the new enrollment fully succeeds.

## 6. Model downloads and Worker updates

Run these commands on the Mac while the Windows Worker remains online. If the
Worker has no manager Broker, first run:

```bash
vgen worker manager-set "Windows GPU Worker"
```

Install pinned workflow models:

```bash
vgen broker model-install vgen/minimax-h3-8step \
  --worker "Windows GPU Worker" --wait
```

Review and accept the displayed licenses. Downloads resume safely and install
only after source revision, path, size, and SHA-256 all match. Inspect or cancel:

```bash
vgen broker maintenance-list --worker "Windows GPU Worker"
vgen broker maintenance-show <job_id>
vgen broker maintenance-cancel <job_id>
```

Upgrade a Worker from the pinned stable release without reinstalling Windows:

```bash
vgen worker upgrade --worker "Windows GPU Worker" --wait
```

For an explicitly reviewed local wheel:

```bash
vgen broker worker-update ~/Downloads/vgen-<version>-py3-none-any.whl \
  --worker "Windows GPU Worker" --wait
```

These commands update only the VGen Worker wheel, not the Gateway, Mac CLI,
ComfyUI, custom nodes, Python, CUDA, drivers, or model weights.

The long-running `vgen worker serve` process contains its own stable supervisor.
After the Broker-authorized wheel is verified and staged, that supervisor starts
the new isolated runtime, waits for its authenticated Gateway announce, and
returns to the previous runtime if activation fails. The Windows launcher keeps
the same compatibility behavior for Workers installed by an older package.
Do not run the Worker under an external loop that replaces its whole Python
environment; keep the original foreground command running and let VGen switch
the child runtime.

## 7. Real zero-, one-, and two-image tests

Check health and run a read-only scheduler preflight first:

```bash
vgen profile show
vgen gateway health
vgen broker status
vgen worker list
vgen broker maintenance-list --worker "Windows GPU Worker"
vgen task preflight
```

Preflight creates no Task or Attempt, reserves no Worker, uploads no media, and
incurs no usage. It distinguishes offline, busy, maintenance, allocation,
capability, model, memory, and rate problems.

Text-to-video:

```bash
vgen task submit "A cinematic sunrise above a calm sea" \
  --wait --output-dir ~/Downloads/VGen-output
```

First-frame image-to-video:

```bash
vgen task submit "The subject blinks and turns naturally" \
  --image ~/Downloads/first.png \
  --wait --output-dir ~/Downloads/VGen-output
```

First/last-frame generation:

```bash
vgen task submit "A smooth push-in with continuous motion" \
  --image ~/Downloads/first.png \
  --last-image ~/Downloads/last.png \
  --wait --output-dir ~/Downloads/VGen-output
```

`--last-image` requires `--image`. Acceptance requires more than `succeeded`:
open the absolute output path, play the file, and verify the requested 0/1/2
image semantics and visual quality. Existing different files are preserved with
safe suffixes unless `--overwrite` is explicitly supplied.

## 8. Removing Workers and devices

Gracefully drain or immediately stop a Worker:

```bash
vgen worker leave <worker_id>
vgen worker leave <worker_id> --force
vgen worker revoke <worker_id>
```

Revocation is permanent for that Worker ID. A lost or compromised Worker should
be revoked; normal repairs should use section 5.4 without revocation.

Before removing the current Mac, verify recovery material or another authorized
device, then run:

```bash
vgen identity show
vgen identity revoke --forget-local
```

From another authorized device, revoke a lost Mac and rotate Workspace keys:

```bash
vgen identity revoke <old_device_id>
vgen workspace key-rotate
```

Alpha recovery can restore an identity but does not yet rebuild every Broker,
Workspace, Pool, and local setting in one step. Keep the old device until the
new one has completed recovery, key sync, Broker binding, and a real task test.

## 9. Security boundaries

- Store recovery words offline. Never disclose private keys, invite secrets,
  bootstrap codes, sessions, Worker credentials, signed artifact URLs, or STS
  credentials.
- Send one-time invites and verification codes only through a trusted
  one-to-one channel.
- Keep the OSS bucket private and keep task media off the ECS system disk.
- Expose only HTTPS 80/443. Keep Gateway `8010` and ComfyUI `8188` private.
- Install only reviewed workflow packages, model licenses, Executors, and
  ComfyUI custom nodes.
- Remember that E2EE protects task payloads and media, not scheduling metadata.
  The selected Worker necessarily sees task plaintext while executing it.

## 10. Troubleshooting

- **Gateway returns 502 or is unhealthy:** run `setup-gateway.sh status`, check
  systemd logs and `127.0.0.1:8010`, then use `activate` only if the local
  Gateway is healthy. Use `rollback` to restore the saved Nginx route.
- **Worker is offline:** keep its PowerShell window open, check
  `%LOCALAPPDATA%\VGen\logs`, confirm Gateway reachability, and verify that
  ComfyUI listens only on loopback.
- **Worker is maintenance-only:** run the model-install command in section 6 and
  wait for every pinned dependency to verify.
- **Preflight reports no capacity:** check allocation, online heartbeat, active
  maintenance, Executor/model versions, GPU memory, and approved rate.
- **Join is pending:** the Owner must compare the joining device's verification
  code and complete key admission; then the new Mac runs `vgen join --resume`.
- **A task retries or progress restarts:** a disconnected Worker may produce a
  new fenced Attempt. Late results from the old Attempt cannot overwrite it.
- **The result already exists:** VGen preserves different files by choosing a
  suffixed name. Use `--overwrite` only when replacement is intentional.

When reporting a problem, include the VGen version, stable six-digit error code,
request/task/Worker ID, and sanitized logs. Never include secrets, prompts, user
media, signed URLs, authorization headers, or environment dumps.
