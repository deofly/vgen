# VGen 0.14.6

This patch release lets Workers enrolled before managed Node Packs safely
install reviewed binary dependencies without revisiting the machine.

- A legacy Worker with no recorded ComfyUI Python argument now checks only the
  known portable, Desktop and virtual-environment layouts adjacent to its
  configured ComfyUI directories.
- Binary Node Packs are enabled only when that search resolves to exactly one
  regular, non-link Python executable. Missing or ambiguous layouts retain the
  existing pure-Python-only restriction.

## Validation

Tests cover unique portable discovery, ambiguous interpreter rejection and the
existing safe fallback to the managed Worker interpreter. The change is needed
for the pre-Node-Pack `HONEYLONG GPU Worker`, which correctly rejected the
MediaPipe wheel before this compatibility migration.
