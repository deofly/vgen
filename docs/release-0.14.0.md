# VGen 0.14.0

This release adds workflow discovery and usage help, and the runtime support
needed by the MiniMax H3 face-reference video preview.

- Workflow listings show descriptions and stable catalog codes. Use `h3`,
  `h3-face`, or `ltx25-q4`; append `@version` to pin a release. Full IDs remain
  supported, ambiguous codes are rejected, and installed workflows can resolve
  cached codes offline.
- `vgen workflow help <code>` displays parameter defaults, ranges, combinations,
  reference prompts, and copyable commands. `task submit --help` includes quick
  examples. `workflow show` and `workflow search` now default to readable text;
  scripts should explicitly request `--format json`. `verify` keeps JSON as its
  default.
- `task submit --video` encrypts reference-video uploads. ComfyUI Executor 1.3.0
  supports `v2v`, binds uploads to the exact native `LoadVideo.file` input, and
  rejects unbound local video reads. The Gateway accepts the matching capability
  metadata and the exact native `Video Slice` node name.
- For the reviewed `h3-face@1.0.0` package, `--video-fps-mode auto` probes source
  frame timestamps and resamples the selected segment to 24 fps before upload.
  `strict` rejects incompatible inputs instead. Video and audio use the same
  starting point; source files are unchanged and temporary plaintext is cleaned
  after encrypted upload or failure.

## Upgrade and prerequisites

Upgrade the Gateway and Worker together with the CLI. `vgen upgrade` also
refreshes the local Home Broker. Existing model files and workflow identities
are retained; installing a workflow/model is a separate operation.

Automatic video adaptation requires local FFmpeg (`ffmpeg` and `ffprobe` on
PATH); it is not bundled. The face-reference preview requires ComfyUI >=0.33.0,
Executor >=1.3.0, and the Ref2VA model. Its output remains 124 frames at 24 fps,
about 5.17 seconds. Only use your own or authorized likenesses and video.

## Validation boundary

Package checks, encrypted input bindings, CLI examples, and real FFmpeg tests
cover fractional/variable frame rates, clip timing, audio selection, and cleanup.
The face-reference workflow remains a preview: GPU output quality has not been
validated. It regenerates a reference shot and is not exact frame-by-frame face
replacement. Runtime publication does not certify identity, motion, or lip-sync
fidelity.

See the [user guide](user-guide.md) or [Chinese user guide](zh-CN/user-guide.md)
for installation, preflight, and submission commands.
