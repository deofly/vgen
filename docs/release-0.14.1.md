# VGen 0.14.1

This patch release restores one-click installation of the MiniMax H3
face-reference preview for Workers that cannot reach Hugging Face's redirected
AWS/Xet download endpoint.

- `h3-face@1.0.1` downloads the Ref2VA model from a commit-pinned ModelScope
  mirror. The expected size and SHA-256 remain identical to the reviewed
  Comfy-Org artifact.
- Automatic and strict input-frame-rate handling accepts the exact reviewed
  digests of both `h3-face@1.0.0` and `h3-face@1.0.1`; unrelated or modified
  packages remain fail closed.
- Help and user-guide examples now select `h3-face@1.0.1`.

The workflow remains a preview. Installing the model and passing preflight do
not certify output quality, identity consistency, motion, or lip-sync fidelity.
