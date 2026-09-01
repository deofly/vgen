# VGen 0.14.5

This patch release makes large reviewed Node Packs reliable on slow or
intermittent public connections.

- Node Pack downloads now stream directly to a bounded temporary file instead
  of holding the entire artifact in memory.
- Interrupted HTTPS transfers resume from the verified byte offset when the
  immutable marketplace server supports byte ranges.
- Every completed download remains subject to the existing public-address,
  redirect, maximum-size and exact SHA-256 checks before atomic installation.

## Validation

The retry test interrupts an initial transfer and verifies that the next
request resumes at the exact byte offset. The production `h3-face@2.0.0` Node
Pack (108,303,940 bytes) was then downloaded through the public marketplace in
257.55 seconds and matched SHA-256
`457fd895f3d68041d9f03be75cb1d9e5b510062c58d58148988177ba9f0e287f`.
