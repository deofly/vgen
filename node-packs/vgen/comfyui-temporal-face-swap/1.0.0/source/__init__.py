"""VGen's reviewed temporal face-swap ComfyUI node."""

from .face_swap import VGenTemporalFaceSwap

NODE_CLASS_MAPPINGS = {"VGenTemporalFaceSwap": VGenTemporalFaceSwap}
NODE_DISPLAY_NAME_MAPPINGS = {
    "VGenTemporalFaceSwap": "VGen Temporal Face Swap",
}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
