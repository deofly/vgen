# VGen 0.14.7

This patch release lets one reviewed Node Pack carry exact wheels for multiple
ComfyUI Python ABIs.

- The Worker now resolves each pinned distribution name and version from the
  offline wheel directory, allowing the target ComfyUI Python to select its
  single compatible wheel tag.
- It still uses `--no-index`, `--no-deps`, binary-only installation, a bounded
  target directory and the existing content-addressed Node Pack verification.
- `h3-face@2.0.1` pins Node Pack 1.0.1 with Windows CPython 3.10, 3.11 and 3.12
  MediaPipe 0.10.21 dependencies. The face-swap graph and model are unchanged.

## Validation

Tests verify that three MediaPipe ABI wheels become one exact pip requirement
and that raw wheel paths are not forced into the target interpreter. Workflow
2.0.1 was packaged and verified with content digest
`9a9ccdd71c9588744721d68baff9de9cd0d5bb06421864beed2905f513f08b6f`.
