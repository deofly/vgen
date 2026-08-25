# LTX-2.5 distilled GGUF Q4 text-to-video

Release 1.0.1 preserves the reviewed graph and model pins while assigning a
new immutable release reference after an earlier Worker-side version conflict.

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

`ComfyUI-GGUF` is executable third-party code. The Windows Worker bootstrap
installs only the reviewed Git commit and exact Python dependency versions;
the workflow package itself remains inert data and merely authorizes the
`UnetLoaderGGUF` node class for this exact release.
