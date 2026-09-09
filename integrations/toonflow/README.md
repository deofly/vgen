# Toonflow × VGen (direct CLI preview)

English | [简体中文](README.zh-CN.md)

Toonflow's backend calls the installed `vgen` executable directly using argument
arrays, without a shell. It reuses the CLI's current login, default Workspace and
Pool. No bridge server, address, token or additional Python service is required.

Implemented against Toonflow-app 1.1.8, commit
`e03cf590eb0cab63534a4040db9acb4ec95b42a6`. This is a source integration, not a
packaged desktop release. Text and image generation use separate Toonflow providers.

## Start

Make sure the existing CLI is installed and its account is ready:

```bash
vgen profile show
vgen task preflight --workflow=vgen/minimax-h3-8step@1.0.1
```

After recent Workspace approval, complete `vgen join --resume`. The workflow must
be installed and an allocated Worker must have its models and runtime ready.
The integration does not change GPU machines or install models automatically.

In the VGen source checkout:

```bash
python3 integrations/toonflow/install.py /path/to/Toonflow-app
```

Then, in Toonflow-app with its supported Node.js runtime and Yarn:

```bash
yarn install --frozen-lockfile
yarn dev
```

Open `http://127.0.0.1:10588`. Under **设置 → 模型服务 → VGen 本地生成**, enable
and test the video model. There are no connection fields. Select the same model
for project video generation.

The backend first finds `~/.local/bin/vgen`, then falls back to `vgen` on PATH.
Developers can set `VGEN_CLI` to an absolute executable path or `VGEN_PROFILE` to a
specific existing Profile before starting Toonflow. These are optional host
settings, not user-facing connection configuration. The CLI runs under the same
OS user as Toonflow. Desktop packaging must preserve this executable discovery.

## Behavior

- A separate SQLite queue lives under Toonflow's `data/vgen` directory. One task
  executes at a time; at most 100 unfinished requests are accepted.
- Each project video gets a stable request ID. Duplicate requests reuse it;
  different content with the same ID is rejected. A new video record is a new job.
- The backend calls `task preflight`, `task submit`, `task show --format=json`, and
  `task get`. Prompts remain positional argv values, even when they start with `-`.
- Task IDs and local output paths persist. Known tasks resume polling and download
  after a restart. Downloads retry without another submission.
- Every five seconds completed videos are restored to their original project and
  video record. Tests in the provider settings have no project record to restore.
- An interrupted submission with no known remote ID becomes `needs_attention`.
  It is never blindly replayed. Reconcile using `vgen task list` / `task show`.
- Closing a dialog does not cancel remote work. To cancel an already submitted
  job, use `vgen task cancel <task_id>`; a frontend cancel control is not included.
- The queue permits one Toonflow process per data directory. Local prompts,
  reference images and decrypted videos are retained; automatic cleanup is not
  implemented. They are private local files, not encrypted application storage.

The installer updates provider metadata, the trusted `AiVideo` dispatch, and the
restart recovery hook. It clears obsolete VGen address/key fields from the prior
HTTP preview, preserving other providers. The old bridge's data directory is not
removed or imported. The bridge itself is no longer part of this integration.

## Preview preset

| Setting | Values |
| --- | --- |
| Workflow | `vgen/minimax-h3-8step@1.0.1` |
| Input | Text; first frame; ordered first and last frame |
| Output | One MP4 with native audio |
| Duration | 39 frames / 24 fps = 1.625 seconds |
| Landscape / portrait | 1344×768 / 768×1344 (UI label: `768p`) |
| Images | PNG, JPEG or WebP; at most 10 MiB each |

The existing preset is not exactly 16:9. Longer durations, arbitrary workflows,
reference video and audio-off require separately validated presets.

## Verify

```bash
python3 -m pytest -q tests/integrations
TOONFLOW_CHECKOUT=/path/to/Toonflow-app node --test integrations/toonflow/test-provider.cjs
# In Toonflow-app:
yarn lint
```

Node tests run the direct executor against real local SQLite, a simulated CLI,
and Toonflow's Sucrase/VM2 environment. They cover queue persistence, retries,
parameter validation, private files, subprocess arguments and project recovery.
GPU acceptance still requires actual clips, playback, project return and export.

## Workflow maintenance

Toonflow does not carry a second workflow registry. At startup it reads versioned
workflows installed for the local VGen CLI and displays their model entries. Each
video stores the selected `id@version` and digest; a digest mismatch blocks submission.

Maintain a new release on the VGen/Worker side, then refresh Toonflow:

```bash
vgen workflow verify ./workflow-package
vgen workflow install ./workflow-package
vgen workflow list --format=json
vgen broker workflow-install vgen/example@1.0.0 --worker <worker>
vgen broker model-install vgen/example@1.0.0 --worker <worker> --wait
vgen task preflight "test prompt" --workflow=vgen/example@1.0.0
```

A package must contain a versioned manifest, parameter Schema, graph, mapping,
model digests and dependency declarations. Publish a new SemVer instead of replacing
an existing release. Wait for the Worker to report its models, nodes, executor and
resource requirements ready before refreshing Toonflow. Use
`vgen broker workflow-deactivate` or `workflow-uninstall` for lifecycle changes;
other versions remain separate.

The workbench now exposes `cancelVideoGenerate` and `retryVideoGenerate`: cancel
resolves the remote task correlated to one video record, while retry only accepts a
failed/cancelled job and creates a new idempotency key. `checkVideoStateList` also
returns in-progress videos and their latest task progress.
