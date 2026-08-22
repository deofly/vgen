# Contributing

1. Create a focused branch and keep secrets and machine-specific paths out of commits.
2. Add tests for protocol, authorization and task-state changes.
3. Follow the quality gate in the
   [developer and release handbook](docs/developer-guide.md).
   A public release must also follow its source, tag, artifact provenance and
   real-environment acceptance steps; files already present in `dist/` are not
   release evidence.
4. Do not reuse or renumber a published six-digit error code.
5. New executors must pass the executor conformance suite and must not add
   engine-specific fields to the Gateway task protocol.
6. Follow [the versioning policy](docs/developer-guide.md#8-版本与候选发行). Change the product
   version only in `pyproject.toml`; do not hand-copy it into runtime code,
   installer sources or tests. Release-specific user documentation may show the
   matching artifact filename, but must not drive a build.

Contributions are accepted under Apache-2.0 and certify the contributor has the
right to submit the work under that license.
