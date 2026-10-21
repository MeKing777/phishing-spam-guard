"""Local inference for the repository's separately trained text classifiers."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


MODEL_DIR = Path(
    os.environ.get("ALERTER_MODEL_DIR", Path(__file__).resolve().parents[1] / "models")
)
MODEL_FILES = {
    "email": "alerter_email_v1.joblib",
    "url": "alerter_url_v1.joblib",
}


def models_available() -> dict[str, bool]:
    return {
        kind: (MODEL_DIR / filename).is_file()
        for kind, filename in MODEL_FILES.items()
    }


@lru_cache(maxsize=2)
def _load_model(kind: str):
    path = MODEL_DIR / MODEL_FILES[kind]
    if not path.is_file():
        return None
    import joblib

    bundle = joblib.load(path)
    if (
        not isinstance(bundle, dict)
        or bundle.get("schema_version") != 1
        or not hasattr(bundle.get("pipeline"), "predict_proba")
    ):
        raise RuntimeError(f"Unsupported local model artifact: {path}")
    return bundle


def assess(text: str, kind: str) -> dict | None:
    """Return a local model opinion; None means no model artifact is installed."""
    if kind not in MODEL_FILES:
        raise ValueError(f"Unsupported trained model type: {kind}")
    value = (text or "").strip()
    if not value:
        return None
    bundle = _load_model(kind)
    if bundle is None:
        return None
    probabilities = bundle["pipeline"].predict_proba([value[:20000]])[0]
    classes = list(bundle["pipeline"].classes_)
    if len(classes) != len(probabilities):
        raise RuntimeError(f"Invalid local model output for {kind}.")
    thresholds = bundle.get("thresholds", {})
    risky_classes = {"phishing", "spam"} if kind == "email" else {"phishing"}
    flagged_candidates = [
        (str(label), float(probabilities[index]), float(thresholds[label]))
        for index, label in enumerate(classes)
        if str(label) in risky_classes
        and label in thresholds
        and float(thresholds[label]) <= 1
        and float(probabilities[index]) >= float(thresholds[label])
    ]
    if flagged_candidates:
        label, confidence, threshold = max(
            flagged_candidates,
            key=lambda candidate: candidate[1] / candidate[2],
        )
        flagged = True
    else:
        index = max(range(len(probabilities)), key=lambda item: float(probabilities[item]))
        label = str(classes[index])
        confidence = float(probabilities[index])
        threshold = thresholds.get(label)
        flagged = False
    return {
        "kind": kind,
        "label": label,
        "confidence": confidence,
        "threshold": float(threshold) if threshold is not None else None,
        "flagged": flagged,
    }
