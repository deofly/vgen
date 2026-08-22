# MiniMax H3 8-step

This package exposes one ComfyUI API graph through three operations:

- no image: `t2v`;
- `image`: `i2v`, with the image as the first frame;
- `image` and `last_image`: `flf`, with first and last frame constraints.

The builder removes both `LoadImage` nodes when no image is supplied, so an
export-time default image can never silently affect text-to-video generation.

## Runtime dependencies

The manifest pins the five referenced model files to immutable upstream
revisions, byte sizes and SHA-256 digests. Four base components use the
MiniMax H3 Community License; the 8-step LoRA is Apache-2.0. Review those terms
before downloading. VGen records these dependencies for verification and
scheduling, but never downloads them automatically.

The T8 audio nodes and Video Helper Suite are executable GPL-licensed custom
nodes pinned to exact Git commits. A Worker machine administrator must review
and install them locally. The workflow package does not install or execute
plugin setup code.

Executor or custom-node code is never installed by `vgen workflow install`.
