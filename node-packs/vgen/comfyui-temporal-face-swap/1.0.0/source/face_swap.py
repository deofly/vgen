"""Deterministic single-face texture transfer for an existing video.

The node deliberately does not regenerate frames. It detects one face mesh in
the source portrait and each target frame, piecewise-warps the portrait's face
texture, colour-matches it to the target, and feathers only inside the target
face oval. Frames without a confident target face pass through unchanged.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

import cv2
import mediapipe as mp
import numpy as np
from mediapipe.tasks.python import BaseOptions
from mediapipe.tasks.python.vision import (
    FaceLandmarker,
    FaceLandmarkerOptions,
    FaceLandmarksConnections,
    RunningMode,
)

if TYPE_CHECKING:
    import torch


_FACE_OVAL = np.asarray(
    [
        10,
        338,
        297,
        332,
        284,
        251,
        389,
        356,
        454,
        323,
        361,
        288,
        397,
        365,
        379,
        378,
        400,
        377,
        152,
        148,
        176,
        149,
        150,
        136,
        172,
        58,
        132,
        93,
        234,
        127,
        162,
        21,
        54,
        103,
        67,
        109,
    ],
    dtype=np.int32,
)
_ALIGNMENT_POINTS = np.asarray([33, 263, 1, 61, 291, 152], dtype=np.int32)
_LEFT_EYE = np.asarray(
    [33, 246, 161, 160, 159, 158, 157, 173, 133, 155, 154, 153, 145, 144, 163, 7],
    dtype=np.int32,
)
_RIGHT_EYE = np.asarray(
    [263, 466, 388, 387, 386, 385, 384, 398, 362, 382, 381, 380, 374, 373, 390, 249],
    dtype=np.int32,
)
_INNER_MOUTH = np.asarray(
    [13, 312, 311, 310, 415, 308, 324, 318, 402, 317, 14, 87, 178, 88, 95, 78, 191, 80, 81, 82],
    dtype=np.int32,
)


@lru_cache(maxsize=1)
def _mesh_triangles() -> tuple[tuple[int, int, int], ...]:
    connections = FaceLandmarksConnections.FACE_LANDMARKS_TESSELATION
    triangles: set[tuple[int, int, int]] = set()
    for offset in range(0, len(connections) - 2, 3):
        edges = connections[offset : offset + 3]
        vertices = {edge.start for edge in edges} | {edge.end for edge in edges}
        if len(vertices) == 3:
            triangles.add(tuple(sorted(vertices)))
    if len(triangles) < 800:
        raise RuntimeError("MediaPipe face mesh topology is unavailable")
    return tuple(sorted(triangles))


def _rgb8(image: torch.Tensor) -> np.ndarray:
    value = image.detach().float().cpu().numpy()
    return np.ascontiguousarray(np.clip(value * 255.0 + 0.5, 0, 255).astype(np.uint8))


def _landmark_points(result: object, width: int, height: int) -> np.ndarray | None:
    faces = getattr(result, "face_landmarks", None)
    if not faces:
        return None
    return np.asarray(
        [(point.x * width, point.y * height) for point in faces[0]],
        dtype=np.float32,
    )


def _detect(
    landmarker: FaceLandmarker, image: np.ndarray, timestamp_ms: int | None
) -> np.ndarray | None:
    media = mp.Image(image_format=mp.ImageFormat.SRGB, data=np.ascontiguousarray(image))
    if timestamp_ms is None:
        result = landmarker.detect(media)
    else:
        result = landmarker.detect_for_video(media, timestamp_ms)
    return _landmark_points(result, image.shape[1], image.shape[0])


def _rect(points: np.ndarray, width: int, height: int) -> tuple[int, int, int, int] | None:
    x, y, w, h = cv2.boundingRect(points.astype(np.float32))
    x0 = max(0, x)
    y0 = max(0, y)
    x1 = min(width, x + w)
    y1 = min(height, y + h)
    if x1 - x0 < 2 or y1 - y0 < 2:
        return None
    return x0, y0, x1 - x0, y1 - y0


def _warp_triangle(
    source: np.ndarray,
    destination: np.ndarray,
    source_triangle: np.ndarray,
    destination_triangle: np.ndarray,
) -> None:
    source_rect = _rect(source_triangle, source.shape[1], source.shape[0])
    destination_rect = _rect(destination_triangle, destination.shape[1], destination.shape[0])
    if source_rect is None or destination_rect is None:
        return
    sx, sy, sw, sh = source_rect
    dx, dy, dw, dh = destination_rect
    source_local = source_triangle - np.asarray([sx, sy], dtype=np.float32)
    destination_local = destination_triangle - np.asarray([dx, dy], dtype=np.float32)
    transform = cv2.getAffineTransform(source_local, destination_local)
    patch = cv2.warpAffine(
        source[sy : sy + sh, sx : sx + sw],
        transform,
        (dw, dh),
        flags=cv2.INTER_LINEAR,
        borderMode=cv2.BORDER_REFLECT_101,
    )
    mask = np.zeros((dh, dw), dtype=np.float32)
    cv2.fillConvexPoly(mask, np.round(destination_local).astype(np.int32), 1.0)
    region = destination[dy : dy + dh, dx : dx + dw]
    region[:] = (
        region.astype(np.float32) * (1.0 - mask[..., None])
        + patch.astype(np.float32) * mask[..., None]
    ).astype(np.uint8)


def _identity_geometry(
    source_points: np.ndarray,
    target_points: np.ndarray,
    amount: float,
) -> np.ndarray:
    if amount <= 0:
        return target_points
    transform, _ = cv2.estimateAffinePartial2D(
        source_points[_ALIGNMENT_POINTS],
        target_points[_ALIGNMENT_POINTS],
        method=cv2.LMEDS,
    )
    if transform is None:
        return target_points
    aligned = cv2.transform(source_points[None, :, :], transform)[0]
    result = target_points + (aligned - target_points) * amount
    # Preserve the target mouth opening and eyelid motion more strongly while
    # retaining source proportions around the jaw, cheeks, nose and brows.
    expression_points = np.asarray(
        [
            0,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            33,
            133,
            159,
            145,
            160,
            144,
            263,
            362,
            386,
            374,
            385,
            380,
            61,
            291,
            78,
            308,
            80,
            310,
            81,
            311,
            82,
            312,
            87,
            317,
            88,
            318,
            95,
            324,
        ],
        dtype=np.int32,
    )
    result[expression_points] = (
        target_points[expression_points]
        + (aligned[expression_points] - target_points[expression_points]) * amount * 0.35
    )
    return result.astype(np.float32)


def _colour_match(warped: np.ndarray, target: np.ndarray, mask: np.ndarray) -> np.ndarray:
    selected = mask > 0.55
    if np.count_nonzero(selected) < 64:
        return warped
    warped_lab = cv2.cvtColor(warped, cv2.COLOR_RGB2LAB).astype(np.float32)
    target_lab = cv2.cvtColor(target, cv2.COLOR_RGB2LAB).astype(np.float32)
    source_values = warped_lab[selected]
    target_values = target_lab[selected]
    source_mean = source_values.mean(axis=0)
    target_mean = target_values.mean(axis=0)
    # A bounded mean shift adapts skin tone and illumination without amplifying
    # dark eyelashes or lips into black artifacts.
    shift = np.clip(target_mean - source_mean, [-28.0, -18.0, -18.0], [28.0, 18.0, 18.0])
    matched = warped_lab + shift
    return cv2.cvtColor(np.clip(matched, 0, 255).astype(np.uint8), cv2.COLOR_LAB2RGB)


def _face_alpha(points: np.ndarray, shape: tuple[int, int], feather: float) -> np.ndarray:
    height, width = shape
    outer = np.round(points[_FACE_OVAL]).astype(np.int32)
    centre = outer.astype(np.float32).mean(axis=0)
    inner = np.round(centre + (outer - centre) * 0.91).astype(np.int32)
    outer_mask = np.zeros((height, width), dtype=np.float32)
    inner_mask = np.zeros((height, width), dtype=np.float32)
    cv2.fillPoly(outer_mask, [outer], 1.0)
    cv2.fillPoly(inner_mask, [inner], 1.0)
    face_width = max(8.0, float(np.ptp(outer[:, 0])))
    sigma = max(1.0, face_width * feather)
    blurred = cv2.GaussianBlur(inner_mask, (0, 0), sigmaX=sigma, sigmaY=sigma)
    maximum = float(blurred.max())
    if maximum > 0:
        blurred /= maximum
    alpha = np.clip(blurred * outer_mask, 0.0, 1.0)
    # Preserve the target eye opening and inner mouth (teeth/tongue) so the
    # original blink and speech timing stay readable. Surrounding lids, brows,
    # lips, cheeks, nose and face texture still come from the source portrait.
    expression_mask = np.zeros((height, width), dtype=np.float32)
    cv2.fillPoly(expression_mask, [np.round(points[_LEFT_EYE]).astype(np.int32)], 0.55)
    cv2.fillPoly(expression_mask, [np.round(points[_RIGHT_EYE]).astype(np.int32)], 0.55)
    cv2.fillPoly(expression_mask, [np.round(points[_INNER_MOUTH]).astype(np.int32)], 0.82)
    expression_mask = cv2.GaussianBlur(expression_mask, (0, 0), sigmaX=2.0, sigmaY=2.0)
    return np.clip(alpha * (1.0 - expression_mask), 0.0, 1.0)


def swap_frame(
    source: np.ndarray,
    target: np.ndarray,
    source_points: np.ndarray,
    target_points: np.ndarray,
    *,
    strength: float,
    identity_shape: float,
    feather: float,
) -> np.ndarray:
    destination_points = _identity_geometry(source_points, target_points, identity_shape)
    warped = target.copy()
    for triangle in _mesh_triangles():
        indices = np.asarray(triangle, dtype=np.int32)
        _warp_triangle(source, warped, source_points[indices], destination_points[indices])
    alpha = _face_alpha(destination_points, target.shape[:2], feather)
    matched = _colour_match(warped, target, alpha)
    blend = np.clip(alpha * strength, 0.0, 1.0)[..., None]
    return np.clip(
        target.astype(np.float32) * (1.0 - blend) + matched.astype(np.float32) * blend,
        0,
        255,
    ).astype(np.uint8)


class VGenTemporalFaceSwap:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "source_image": ("IMAGE",),
                "target_images": ("IMAGE",),
                "model_name": ("STRING", {"default": "face_landmarker.task"}),
                "prompt": ("STRING", {"default": "Authorized single-face replacement"}),
                "seed": ("INT", {"default": -1, "min": -1, "max": 0xFFFFFFFFFFFFFFFF}),
                "strength": (
                    "FLOAT",
                    {"default": 1.0, "min": 0.0, "max": 1.0, "step": 0.05},
                ),
                "identity_shape": (
                    "FLOAT",
                    {"default": 0.3, "min": 0.0, "max": 0.6, "step": 0.05},
                ),
                "feather": (
                    "FLOAT",
                    {"default": 0.045, "min": 0.01, "max": 0.12, "step": 0.005},
                ),
            }
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("images",)
    FUNCTION = "swap"
    CATEGORY = "VGen/Face"

    def swap(
        self,
        source_image: torch.Tensor,
        target_images: torch.Tensor,
        model_name: str,
        prompt: str,
        seed: int,
        strength: float,
        identity_shape: float,
        feather: float,
    ) -> tuple[torch.Tensor]:
        import torch

        del prompt, seed
        model_value = Path(model_name)
        if model_value.name != model_name and not model_value.is_absolute():
            raise ValueError("Face landmarker model name must be one filename")
        if model_value.is_absolute():
            resolved_model = model_value.expanduser().resolve(strict=True)
        else:
            import folder_paths

            resolved_model = (
                Path(folder_paths.models_dir) / "face_landmarkers" / model_name
            ).resolve(strict=True)
        source = _rgb8(source_image[0])
        source_options = FaceLandmarkerOptions(
            base_options=BaseOptions(
                model_asset_path=str(resolved_model),
                delegate=BaseOptions.Delegate.CPU,
            ),
            running_mode=RunningMode.IMAGE,
            num_faces=1,
            min_face_detection_confidence=0.55,
            min_face_presence_confidence=0.55,
        )
        target_options = FaceLandmarkerOptions(
            base_options=BaseOptions(
                model_asset_path=str(resolved_model),
                delegate=BaseOptions.Delegate.CPU,
            ),
            running_mode=RunningMode.VIDEO,
            num_faces=1,
            min_face_detection_confidence=0.45,
            min_face_presence_confidence=0.45,
            min_tracking_confidence=0.45,
        )
        output: list[torch.Tensor] = []
        with FaceLandmarker.create_from_options(source_options) as source_landmarker:
            source_points = _detect(source_landmarker, source, None)
        if source_points is None:
            raise ValueError("No single clear face was found in the source portrait")
        previous: np.ndarray | None = None
        with FaceLandmarker.create_from_options(target_options) as target_landmarker:
            for index, tensor in enumerate(target_images):
                target = _rgb8(tensor)
                points = _detect(target_landmarker, target, round(index * 1000 / 24))
                if points is None:
                    result = target
                    previous = None
                else:
                    if previous is not None:
                        points = previous * 0.32 + points * 0.68
                    previous = points
                    result = swap_frame(
                        source,
                        target,
                        source_points,
                        points,
                        strength=float(strength),
                        identity_shape=float(identity_shape),
                        feather=float(feather),
                    )
                output.append(torch.from_numpy(result.copy()).to(dtype=torch.float32) / 255.0)
        return (torch.stack(output, dim=0),)
