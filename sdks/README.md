# VGen SDKs

[简体中文](README.zh-CN.md)

VGen SDKs provide portable API Service credentials, signing, and end-to-end encryption primitives without importing CLI internals.

- [Python SDK](python/README.md)
- [Java SDK](java/README.md)
- [Byte-level compatibility contract](../docs/sdk-compatibility.md)
- [Shared compatibility vectors](../tests/sdk_compat/vectors.json)

The SDKs are additive clients. They do not replace or modify the production CLI, Gateway, Broker, or Worker paths. Both language implementations must pass the same fixed vectors before a release, and changes must remain wire-compatible with credentials and tasks already issued by VGen.

All private keys in the compatibility vectors are public test fixtures. Never use them as real credentials.

## One-time credential provisioning with the existing CLI

Provisioning remains an administrator operation. It creates a dedicated API Service identity without reusing the administrator's User Device identity.

First, an administrator creates a scoped, one-time Service invite. Deliver the complete invite URI through a secure channel and treat it as a bearer secret:

```bash
vgen workspace invite \
  --kind service \
  --method direct_invite \
  --scope task:submit \
  --scope task:read \
  --scope task:cancel \
  --workspace <workspace_id> \
  --profile <admin_profile>
```

On the provisioning host, pass that complete URI through standard input and write a private credential file. Deliberately omit `--use`:

```bash
read -r -s VGEN_SERVICE_INVITE
printf '\n'
printf '%s\n' "$VGEN_SERVICE_INVITE" | \
  vgen service enroll \
    --invite-stdin \
    --name 'render-service' \
    --credentials-file /secure/path/vgen-service.json \
    --profile <gateway_profile>
unset VGEN_SERVICE_INVITE
```

After enrollment, the application loads `vgen-service.json` directly. The CLI Profile in the command above is used only once to select the Gateway and validate the invite authority; omitting `--use` leaves that Profile unbound to the Service. Subsequent SDK use has no dependency on a CLI Profile, User Device identity, User recovery key, or administrator session.

This first SDK delivery is deliberately low-level. It supports credentials, Service Challenge/Session request construction, signatures, AAD, HPKE, and XChaCha primitives; it is not a complete task HTTP client. The current Gateway does not admit a Service as a new Workspace Data Key recipient. API Services instead preserve their own task read access with a direct HPKE reader envelope, as shown in the language guides. Service Workspace-key admission, workflow construction, media transfer, and HTTP orchestration remain outside this SDK-only change.
