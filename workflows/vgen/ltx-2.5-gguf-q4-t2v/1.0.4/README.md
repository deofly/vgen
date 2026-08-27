# LTX-2.5 distilled GGUF Q4 text-to-video 1.0.4

This revision uses a public Hugging Face mirror for Worker downloads while
retaining the original immutable revisions, byte sizes, and SHA-256 pins.

Release 1.0.4 preserves the reviewed graph and model pins while replacing the
manual host dependency with a remotely managed Node Pack.

This is an experimental RTX 3090-oriented release of the native ComfyUI
LTX-2.5 two-stage text-to-video graph. It replaces only the distilled
transformer with the community Q4_K_M GGUF conversion; the text encoder, VAEs,
and spatial upscaler remain digest-pinned LTX-2.5 components.

The conservative default is 512 x 288, 24 fps, and one second. Increase size
or duration only after a successful short generation because peak memory and
generation time rise quickly.

The model sources used by this release are public HTTPS mirrors pinned by
repository revision, byte count, and SHA-256. A Hugging Face token is not
required for these exact URLs. VGen can later point the same digest pins at an
OSS mirror without changing the workflow graph.

`ComfyUI-GGUF` is executable third-party code. VGen installs the reviewed
`vgen/comfyui-gguf@1.0.1` Node Pack automatically through signed Worker
maintenance. Its source, pure-Python GGUF dependency wheel, artifact digest,
Git revision, and approved UNet loader classes are immutable. The Worker pauses
only ComfyUI, validates `/object_info`, and restores the previous node directory
if activation fails.
