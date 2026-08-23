# Security policy

## Reporting

Please use the repository host's **Security** tab and private vulnerability
reporting form when it is available. If private reporting has not yet been
enabled, contact the repository owner through the owner profile and request a
private channel before sending technical details. Do not open a public issue
containing an unpatched vulnerability.

Do not include live recovery words, private keys, invite secrets, session
tokens, signed artifact URLs, prompts or user media in a report. Reproduce with
synthetic data and include the affected version, impact, prerequisites and the
smallest safe proof of concept. The maintainer will acknowledge receipt,
coordinate a fix and publish remediation information after affected users have
a reasonable upgrade path.

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
[developer and release handbook](docs/developer-guide.md#2-identity-admission-and-end-to-end-encryption).
