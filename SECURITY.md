# Security policy

## Reporting

Please report vulnerabilities privately to the project maintainer before opening
a public issue. Do not include recovery words, private keys, invite secrets,
session tokens, signed artifact URLs, prompts or user media in a report.

## Supported versions

Only the latest published `0.x` release is supported while VGen remains in its
pre-1.0 development phase. The protocol version is independent of the product
release number. The legacy shared-token API is unsupported and must not be
exposed to untrusted networks.

## Trust boundary

Gateway metadata is not end-to-end private. Task payloads and artifacts are.
The Worker selected to execute a task necessarily observes its plaintext. Never
install workflow executors or ComfyUI custom nodes from an untrusted publisher.
The complete identity, encryption, maintenance and deployment boundary is in the
[developer and release handbook](docs/developer-guide.md#2-身份准入与端到端加密).
