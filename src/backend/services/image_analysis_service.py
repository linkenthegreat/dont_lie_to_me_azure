"""Image authenticity analysis service.

Combines GPT-4o vision analysis (primary) with Pillow metadata analysis
(supplementary) to detect manipulated, AI-generated, and deepfake images.
"""

import base64
import io
import json
import logging

from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

_FALLBACK_SYSTEM_PROMPT = (
    "You are a digital forensics expert. Analyze this image for signs of manipulation, "
    "AI generation, or deepfake. Return a JSON object with keys: authenticity_score (0-1), "
    "verdict (AUTHENTIC/LIKELY_MANIPULATED/MANIPULATED/AI_GENERATED/DEEPFAKE/INCONCLUSIVE), "
    "manipulation_indicators (list), visual_analysis (object), ai_generation_analysis (object), "
    "context_analysis (object), summary (string). Do not include markdown fences."
)

_MAX_DIMENSION = 2048


def analyze_image(image_base64: str, image_media_type: str = "image/png") -> dict:
    """Orchestrate image authenticity analysis.

    Combines AI vision analysis with optional metadata extraction.

    Parameters
    ----------
    image_base64:
        Raw base64-encoded image data (no data URI prefix).
    image_media_type:
        MIME type of the image, e.g. "image/png", "image/jpeg".

    Returns
    -------
    dict
        Unified analysis result with vision + metadata findings.
    """
    # Resize if needed to reduce token consumption
    resized_base64, resized_media_type = _resize_for_vision(image_base64, image_media_type)

    # Primary: GPT-4o vision analysis
    vision_result = _analyze_with_vision(resized_base64, resized_media_type)

    # Supplementary: Pillow metadata analysis (best-effort)
    metadata_result = _analyze_metadata(image_base64)

    # Merge metadata into vision result
    vision_result["metadata_analysis"] = metadata_result

    return vision_result


def _analyze_with_vision(image_base64: str, image_media_type: str) -> dict:
    """Analyze image using GPT-4o multimodal vision."""
    config = get_prompt_config("image_authenticity_analyzer")
    system_prompt = config.get("system_prompt", _FALLBACK_SYSTEM_PROMPT)
    max_tokens = config.get("max_tokens", 2048)
    temperature = config.get("temperature", 0.2)

    client = AzureAIClient()
    raw = client.chat_with_image(
        system_prompt=system_prompt,
        user_message="Analyze this image for authenticity. Detect any signs of manipulation, editing, AI generation, or deepfake.",
        image_base64=image_base64,
        image_media_type=image_media_type,
        max_tokens=max_tokens,
        temperature=temperature,
    )

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Vision model returned non-JSON: %s", raw[:300])
        return {
            "authenticity_score": 0.5,
            "verdict": "INCONCLUSIVE",
            "manipulation_indicators": [],
            "visual_analysis": {
                "text_consistency": "Unable to parse",
                "font_analysis": "Unable to parse",
                "layout_anomalies": "Unable to parse",
                "pixel_artifacts": "Unable to parse",
                "lighting_consistency": "Unable to parse",
            },
            "ai_generation_analysis": {
                "is_ai_generated": False,
                "confidence": 0.0,
                "generator_hints": "UNKNOWN",
                "artifacts_found": [],
                "deepfake_indicators": [],
            },
            "context_analysis": {
                "platform_identified": "UNKNOWN",
                "expected_vs_actual": "Unable to parse",
                "suspicious_patterns": [],
            },
            "summary": raw,
        }


def _analyze_metadata(image_base64: str) -> dict:
    """Extract and analyze image metadata using Pillow (best-effort).

    Most screenshots and messaging app images lack EXIF data.
    This is supplementary to the vision analysis.
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        image_bytes = base64.b64decode(image_base64)
        img = Image.open(io.BytesIO(image_bytes))

        result = {
            "exif_present": False,
            "editing_software_detected": None,
            "metadata_anomalies": [],
            "image_format": img.format,
            "image_size": {"width": img.width, "height": img.height},
        }

        # Extract EXIF if available
        exif_data = img.getexif()
        if exif_data:
            result["exif_present"] = True
            decoded_exif = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                try:
                    decoded_exif[tag_name] = str(value)
                except Exception:
                    pass

            # Check for editing software
            software = decoded_exif.get("Software", "")
            if software:
                editing_tools = ["photoshop", "gimp", "paint", "canva", "pixlr", "snapseed", "lightroom"]
                for tool in editing_tools:
                    if tool in software.lower():
                        result["editing_software_detected"] = software
                        result["metadata_anomalies"].append(
                            f"Editing software detected: {software}"
                        )
                        break

            # Check for modification date vs creation date anomalies
            date_original = decoded_exif.get("DateTimeOriginal", "")
            date_modified = decoded_exif.get("DateTime", "")
            if date_original and date_modified and date_original != date_modified:
                result["metadata_anomalies"].append(
                    f"Date mismatch: original={date_original}, modified={date_modified}"
                )
        else:
            result["metadata_anomalies"].append(
                "No EXIF metadata (common for screenshots and messaging apps)"
            )

        return result

    except Exception as exc:
        logger.warning("Metadata analysis failed: %s", exc)
        return {
            "exif_present": False,
            "editing_software_detected": None,
            "metadata_anomalies": ["Metadata extraction failed"],
            "note": "Could not extract metadata from this image",
        }


def _resize_for_vision(
    image_base64: str, image_media_type: str
) -> tuple[str, str]:
    """Resize image to max dimension if larger than _MAX_DIMENSION.

    Reduces token consumption when sending to GPT-4o vision.
    Returns the (possibly resized) base64 and media type.
    """
    try:
        from PIL import Image

        image_bytes = base64.b64decode(image_base64)
        img = Image.open(io.BytesIO(image_bytes))

        if max(img.width, img.height) <= _MAX_DIMENSION:
            return image_base64, image_media_type

        # Resize preserving aspect ratio
        img.thumbnail((_MAX_DIMENSION, _MAX_DIMENSION), Image.LANCZOS)

        # Save as JPEG for efficiency (unless PNG with transparency)
        buf = io.BytesIO()
        if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
            img.save(buf, format="PNG", optimize=True)
            out_media_type = "image/png"
        else:
            img = img.convert("RGB")
            img.save(buf, format="JPEG", quality=85)
            out_media_type = "image/jpeg"

        resized_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        logger.info(
            "Image resized from %dx%d to %dx%d for vision API",
            Image.open(io.BytesIO(image_bytes)).width,
            Image.open(io.BytesIO(image_bytes)).height,
            img.width,
            img.height,
        )
        return resized_b64, out_media_type

    except Exception as exc:
        logger.warning("Image resize failed, using original: %s", exc)
        return image_base64, image_media_type
