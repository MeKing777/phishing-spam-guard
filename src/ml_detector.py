"""Optional adapter for the phishing-detection-py pretrained classifiers."""

from __future__ import annotations

import math
import os
from functools import lru_cache
from importlib.util import find_spec

_TORCH_THREADS_CONFIGURED = False


def phishing_package_installed() -> bool:
    """Check for the optional package without importing its ML dependencies."""
    try:
        return find_spec("phishing_detection_py") is not None
    except (ImportError, ValueError):
        return False


@lru_cache(maxsize=2)
def _load_detector(model_type: str):
    global _TORCH_THREADS_CONFIGURED
    import torch

    # Large default thread pools can make small CPU inference slower and less
    # responsive on consumer machines. Keep local predictions bounded.
    if not _TORCH_THREADS_CONFIGURED:
        torch.set_num_threads(min(2, max(1, os.cpu_count() or 1)))
        try:
            torch.set_num_interop_threads(1)
        except RuntimeError:
            pass
        _TORCH_THREADS_CONFIGURED = True

    from phishing_detection_py import PhishingDetector

    return PhishingDetector(model_type=model_type)


def _result_row(output):
    if isinstance(output, list):
        return output[0] if output and isinstance(output[0], dict) else None
    if isinstance(output, dict):
        predictions = output.get("prediction")
        if isinstance(predictions, list):
            return predictions[0] if predictions and isinstance(predictions[0], dict) else None
        return output
    return None


def _verdict(label) -> str:
    normalized = str(label or "").strip().lower().replace("_", " ")
    if any(term in normalized for term in ("not phishing", "non phishing", "not malicious")):
        return "Likely legitimate"
    if "phish" in normalized or "malicious" in normalized:
        return "Likely phishing"
    if any(term in normalized for term in ("legitimate", "benign", "safe", "ham")):
        return "Likely legitimate"
    return "Unclear model label"


def assess_phishing(text: str, model_type: str = "email") -> dict:
    """Get a normalized model opinion without changing the local risk score."""
    if model_type not in {"email", "url"}:
        return {"status": "unavailable", "message": "Unsupported model type."}
    if not (text or "").strip():
        return {"status": "unavailable", "message": "There is no text to classify."}
    if not phishing_package_installed():
        return {
            "status": "unavailable",
            "message": "The optional phishing model is not installed. See the setup steps in Settings.",
        }

    try:
        detector = _load_detector(model_type)
        # Keep submitted text bounded; transformer models also truncate by tokens.
        output = detector.predict(text[:12000])
    except Exception as exc:
        detail = " ".join(str(exc).split())[:260]
        return {
            "status": "unavailable",
            "message": f"The optional model could not run. Check the ML setup and first-use model download. {detail}".strip(),
        }

    row = _result_row(output)
    if row is None:
        return {
            "status": "unavailable",
            "message": "The optional model returned an unexpected result format.",
        }

    label = row.get("label", row.get("prediction", row.get("class", "")))
    confidence = row.get("confidence", row.get("score"))
    try:
        confidence = float(confidence)
        if confidence > 1 and confidence <= 100:
            confidence /= 100
        if not math.isfinite(confidence) or confidence < 0 or confidence > 1:
            confidence = None
    except (TypeError, ValueError):
        confidence = None

    return {
        "status": "ready",
        "verdict": _verdict(label),
        "confidence": confidence,
        "model_type": model_type,
    }
