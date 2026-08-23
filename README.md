# VGen

English | [简体中文](README.zh-CN.md)

VGen is an open-source control plane for running GPU workflows across a public
Gateway, Mac CLI/Home Broker, and remote Workers. Task content and media are
end-to-end encrypted; the Gateway handles identity, admission, scheduling,
leases, auditing, and usage without storing business plaintext or decryption
keys.

## Features

- Share GPU Workers across Users, Workspaces, and Pools.
- Run Workers and Brokers on different machines and networks.
- Schedule by allocation, capacity, leases, and fencing.
- Submit text-to-video, first-frame image-to-video, and first/last-frame jobs
  through the built-in ComfyUI Executor.
- Transfer encrypted task media directly between clients, Workers, and private
  OSS using short-lived credentials.
- Install pinned workflow models and update Windows Workers from the Mac Broker.
- Upgrade the Mac CLI/Home Broker atomically with verification and rollback.
- Keep Gateway API traffic independent from public release downloads.
- Track Worker, GPU, network, and `billing_token` usage for every Attempt.

## Requirements

For a local Gateway preview:

- Git
- Docker with Docker Compose

For a complete GPU setup:

- an ECS host with Python 3.11+, Nginx, systemd, HTTPS, private OSS, and STS;
- a Mac with Python 3.11+ for the CLI/Home Broker;
- a Windows GPU machine with PowerShell 5.1+, ComfyUI 0.30.0+, and the required
  workflow models.

The Windows Worker currently runs in a foreground PowerShell window. Keep the
Gateway's internal port and ComfyUI private; expose only the Gateway HTTPS
endpoint.

## Quick start

Preview the Gateway locally without an ECS account or GPU:

```bash
git clone https://github.com/deofly/vgen.git
cd vgen
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example up --build -d
curl --fail http://127.0.0.1:8000/api/v1/health
```

The response should contain `"ok":true`. Stop the preview with:

```bash
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example down
```

This Compose setup is local-only and is not a production deployment template.

To generate a real video, first complete Gateway, Mac, Windows Worker, ComfyUI,
and model setup from the [User Guide](docs/user-guide.md). Then run:

```bash
vgen gateway health
vgen task preflight
vgen task submit "A cinematic sunrise above a calm sea" \
  --wait --output-dir ~/Downloads/VGen-output
```

Open the absolute output path printed by the CLI and verify playback and visual
quality.

## Local development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[gateway,broker,worker-comfyui,oss,dev]'
python -m ruff check .
python -m pytest
python tools/export_openapi_v1.py --check
python tools/check_public_repository.py
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Keep commits
focused, add tests for behavior changes, and never commit credentials, recovery
material, local databases, generated release artifacts, or machine-specific
configuration. Community expectations are in the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Protocol

The machine-readable API contract is
[`schemas/openapi-v1.json`](schemas/openapi-v1.json). Public endpoints use
`/api/v1`; legacy shared-token routes are unsupported. Published six-digit
business error codes are permanent compatibility identifiers.

## Documentation

- [User Guide](docs/user-guide.md): Gateway deployment, Mac onboarding,
  Windows Worker setup, model installation, upgrades, real jobs, and
  troubleshooting.
- [Developer and Release Guide](docs/developer-guide.md): architecture,
  security, protocol behavior, development, testing, builds, releases,
  migration, and extension rules.
- [Security Policy](SECURITY.md): supported releases and private vulnerability
  reporting.
- [Apache-2.0 License](LICENSE)

Never disclose recovery words, private keys, invite secrets, bootstrap codes,
Worker credentials, sessions, or signed artifact URLs.
