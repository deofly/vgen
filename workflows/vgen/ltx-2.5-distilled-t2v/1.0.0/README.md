# LTX-2.5 distilled text-to-video

This package exposes the native ComfyUI LTX-2.5 two-stage distilled
text-to-video graph. It generates synchronized video and audio and supports
the `t2v` operation only.

## Provenance and conversion

The source is Comfy-Org's MIT-licensed
`video_ltx2_5_t2v.json` template at commit
`2ded761bde3af3b4c8e905e162f45551cbec12ea`. The source UI workflow has
SHA-256
`0040f7d44a57bbaaddff78a2fbe6a9bc9631897f034f8c0fa179f94a4c8e6b84`.

The template was loaded into ComfyUI `v0.33.4` at commit
`7a131a3afadc8200120f67f9236311a2c48b7445`, using frontend `1.49.6` and
workflow templates `0.11.46`, then exported through **Export (API)**. The
template's stale `extra.prompt` graph was not used. The full frontend export
had 44 nodes and SHA-256
`5606abd1276e3aee56759eeee077abf847c43fd5042d62f26fb38676a1fb2964`.

VGen applies these reviewed derivations to the frontend export:

- remove optional prompt-enhancer nodes `405:393`, `405:380`, `405:381`,
  `405:382`, and `405:383`, then connect `405:376` directly to `405:364`;
- remove `ResolutionSelector` node `409`, make width and height direct integer
  inputs, and use the selector's official 0.9-megapixel result of `1280x736`
  as defaults;
- remove localized `_meta` titles and serialize the graph as canonical,
  sorted, compact JSON.

The prompt-enhancer branch is deliberately absent. In the unmodified API
export, its `PreviewAny` output keeps the enhancer model validation-reachable
even when the switch is false, so treating that model as optional would make
remote execution fail before queuing.

All 23 node classes in the resulting 38-node graph are native ComfyUI core
classes. This package has no third-party custom-node dependency. LTX-2.5
support first shipped in ComfyUI `v0.32.0`. VGen verified all 23 classes
against a fresh `v0.32.0` `/object_info` response and submitted the graph to
that version's `/prompt` validator; the only validation failures were the five
intentionally absent pinned model files. The same check passed on `v0.33.4`.

## Parameters

`duration` is measured in whole seconds. The graph calculates the frame count
as `duration * fps + 1`. The package requires `fps` to be a multiple of 8 so
the LTX frame-count constraint is preserved, and width and height must be
multiples of 32. A negative seed asks VGen to choose a seed before submission.

## Models, gate, and license

The five required model files total 39,709,872,236 bytes. They are pinned to
the immutable Hugging Face revision
`6c7e5e573ac1667efc83407806fe9b0b93730e60`, including exact byte sizes and
SHA-256 digests in `manifest.yaml`. The package does not contain or mirror the
weights.

All five files are gated under the LTX-2.x Community License Agreement. The
operator must review and accept the current terms on the LTX-2.5 Hugging Face
page before installation. Gated downloads use only the Worker's local
`HF_TOKEN` or `HF_TOKEN_PATH`; the credential is not sent to the Mac broker or
Gateway. The license dated August 11, 2026 requires a paid license for covered
commercial use by entities with at least USD 10 million in annual revenue and
also imposes distribution and use restrictions. Review the binding upstream
license rather than relying on this summary.

Lightricks documents a minimum NVIDIA GPU with 32 GB or more VRAM, 32 GB
system RAM, 100 GB free storage, CUDA 12.7 or newer, and Python 3.12 or newer.
The manifest advertises the memory floors; the operator must also preserve the
documented free-storage headroom for models, caches, and generated media.
