# VGen

English | [简体中文](README.zh-CN.md)

VGen is a platform for running GPU workflows through a Gateway, Brokers, and
remote Workers. It helps teams share GPU capacity, run video-generation tasks,
and keep task content and media encrypted end to end.

## Features

- Share GPU capacity across users, workspaces, and pools.
- Run workflows on remote GPU Workers while controlling them from a Broker.
- Generate text-to-video, first-frame, and first/last-frame videos with ComfyUI.
- Move task media securely between clients and Workers.
- Publish and activate reviewed workflow releases, reuse shared model content,
  and manage model/runtime installs remotely.
- Schedule work reliably with capacity-aware task execution.

## Requirements

For a local Gateway preview:

- Git
- Docker with Docker Compose

For a complete GPU setup, you need Python 3.11+, a supported GPU runtime such
as ComfyUI, and the models required by the workflow. See the [User Guide](docs/user-guide.md)
for deployment and Worker setup.

## Quick start

Preview the Gateway locally without an ECS account or GPU:

```bash
git clone https://github.com/deofly/vgen.git
cd vgen
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example up --build -d
curl --fail http://127.0.0.1:8000/healthz
```

The response should contain `"ok":true`. Stop the preview with:

```bash
docker compose -f examples/docker-compose.yml \
  --env-file examples/.env.example down
```

This Compose setup is local-only and is not a production deployment template.

To generate a real video, first complete Gateway, Broker, Worker, ComfyUI, and
model setup from the [User Guide](docs/user-guide.md). Then run:

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

## API

The machine-readable API contract is [`schemas/openapi-v1.json`](schemas/openapi-v1.json).
Public API endpoints use `/api/v1`.

Independent [Python and Java SDKs](sdks/README.md) provide API Service credentials,
request signing, and end-to-end encryption without importing CLI internals.

## Documentation

- [User Guide](docs/user-guide.md): Gateway deployment, Broker onboarding,
  Worker setup, model installation, upgrades, real jobs, and
  troubleshooting.
- [Developer and Release Guide](docs/developer-guide.md): architecture,
  security, protocol behavior, development, testing, builds, releases,
  migration, and extension rules.
- [SDK Compatibility Contract](docs/sdk-compatibility.md): credential, signature,
  encryption, and cross-language compatibility rules.
- [Security Policy](SECURITY.md): supported releases and private vulnerability
  reporting.
- [Apache-2.0 License](LICENSE)

Never disclose recovery words, private keys, invite secrets, bootstrap codes,
Worker credentials, sessions, or signed artifact URLs.
