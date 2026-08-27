"""Small, release-pinned compatibility bridge for the one-click H3 policy.

New Marketplace workflows are authorized by signed maintenance receipts and do
not belong here.  H3 is exceptional because released Windows installers
provisioned it as machine-admin state before that protocol existed.  Keeping
the bridge declarative, digest-pinned, and tested against the bundled package
avoids trusting a Worker's heartbeat while the legacy installer is retired.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BootstrapWorkflowAuthorization:
    workflow_ref: str
    workflow_digest: str
    model_digests: tuple[str, ...]
    node_classes: tuple[str, ...]


COMFYUI_BOOTSTRAP_WORKFLOWS = (
    BootstrapWorkflowAuthorization(
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest="sha256:bd15cace959f6330626b47c07195b6f8a016e334683969c0d5b044b24debcb93",
        model_digests=(
            "sha256:2339acdf19bfe123f46b971ea35d367a84adb85de43627e1eceafa5a5b2b111e",
            "sha256:35a88d51044231fe332301d7a62aa81e3f2cba62febeb446e2c1e3e0ef76f2c6",
            "sha256:7c1f131492e7eddacaac9069a61b81bdd39de5cc96561e677c5eab1cdce5e522",
            "sha256:8e505d95dd1561d47abd43d4238fd40d9bb1ae9e147ed0a4cba778d76ae4db48",
            "sha256:e889202c41dafb67b10d67b97f0d8541508036a6090af23425a5c2615d03c47a",
        ),
        node_classes=(
            "BasicGuider",
            "CLIPLoader",
            "LoadImage",
            "LoraLoaderBypassModelOnly",
            "MiniMaxH3AVDecodeT8",
            "MiniMaxH3AudioConditioningT8",
            "MiniMaxH3DualClockSamplerT8",
            "RandomNoise",
            "SamplerCustomAdvanced",
            "UNETLoader",
            "VAELoader",
            "VHS_VideoCombine",
        ),
    ),
)
