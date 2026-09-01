# VGen 0.14.3

This patch release makes long-running Worker output publication recoverable and
improves the safe diagnosis of MiniMax H3 sampler failures.

- Output-ticket expiry is retryable for uploads. The Worker keeps the encrypted
  output spool, renews the object-scoped ticket, and resumes publication without
  running the GPU workflow again. Expired input/download tickets remain fail
  closed.
- ComfyUI diagnostics now distinguish missing H3 helpers, tensor-alignment
  failures, CUDA device failures, and host-buffer failures in safe Worker error
  details.
- A regression test proves that an expired output ticket is renewed and uploaded
  with exactly one executor invocation.

## Validation

The full test suite and release gates cover the retry path. A real
`h3-face@1.0.1` task ran for about 26 minutes, outlived its original upload
ticket, reported `resuming_output_upload`, and completed with one attempt. The
result contained 124 frames at 24 fps with its audio stream attached.

The H3 face-reference workflow remains a preview. One successful authorized
sample does not guarantee identity, motion, occlusion, or lip-sync quality for
other inputs; review every generated video before use.
