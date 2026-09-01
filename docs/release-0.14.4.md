# VGen 0.14.4

This release replaces the `h3-face` generative preview with a deterministic,
frame-preserving single-face swap workflow.

- `h3-face@2.0.0` keeps the original video frames, movement, background and
  audio, and modifies only the detected face oval.
- The reviewed Node Pack pins MediaPipe 0.10.21, OpenCV 4.11.0.86 and their
  Windows CPython 3.11 offline dependencies. It does not use InsightFace's
  non-commercial swap models or a third-party face-swap API.
- MediaPipe `.task` assets are now recognized as pinned model files, and the
  Windows Worker exposes a controlled `face_landmarkers` model category.
- The 1.x workflow releases remain immutable and installable. The existing
  `seed` parameter is accepted by 2.0.0 for command compatibility but no longer
  affects the deterministic result.

## Validation

The package, mapping and capability policy tests cover the new graph and exact
dependency pins. A local run using the reported portrait and source video found
one face in all 124 frames, processed the clip in about 5.5 seconds, retained
the original audio, and produced a 24 fps 720x1280 MP4. Real Windows Worker
installation and task output are release gates, not inferred from the local
prototype.

Only use face materials belonging to the user or covered by explicit consent.
The workflow intentionally supports one visible person; side profiles,
occlusions and low-resolution faces still require review.
