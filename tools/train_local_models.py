"""Train local email and URL classifiers from pinned, licensed public datasets."""
from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "training_sources"
MODEL_DIR = ROOT / "models"
REPORT_PATH = ROOT / "data" / "threat_intelligence" / "training_report.json"
SEED = 47
MIN_WARNING_PRECISION = 0.98

SOURCES = {
    "email_spam_ham": {
        "url": (
            "https://huggingface.co/datasets/haoxianc/"
            "haldonmez_spam-or-ham-a-dataset-for-email-classification/resolve/"
            "ff760d3eb375d52912ff7639521177f780922598/dataset/combined_enron.csv"
        ),
        "license": "CC0-1.0",
        "citation": (
            "Halil Donmez, Spam Email Classification Dataset; mirror and source "
            "details: https://huggingface.co/datasets/haoxianc/"
            "haldonmez_spam-or-ham-a-dataset-for-email-classification"
        ),
    },
    "email_phishing": {
        "url": (
            "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/"
            "resolve/34085a032c123ca237f314a01a67909cdea35e34/Phishing_Email.csv"
        ),
        "license": "LGPL-3.0",
        "citation": (
            "Cyber Cop, Phishing Email Detection; source and license details: "
            "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset"
        ),
    },
    "url_train": {
        "url": (
            "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/"
            "1375d450d4540205ac11781b807249c9509739cd/data/train.parquet"
        ),
        "license": "CC-BY-4.0",
        "citation": (
            "Hannousse & Yahiouche (2021), Towards benchmark datasets for "
            "machine learning based website phishing detection: an experimental "
            "study, https://doi.org/10.1016/j.engappai.2021.104347"
        ),
    },
    "url_test": {
        "url": (
            "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/"
            "1375d450d4540205ac11781b807249c9509739cd/data/test.parquet"
        ),
        "license": "CC-BY-4.0",
        "citation": (
            "Hannousse & Yahiouche (2021), Towards benchmark datasets for "
            "machine learning based website phishing detection: an experimental "
            "study, https://doi.org/10.1016/j.engappai.2021.104347"
        ),
    },
}


def _download(name: str) -> Path:
    path = DATA_DIR / name
    if path.is_file() and path.stat().st_size:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".part")
    source_name = name[:-8] if name.endswith(".parquet") else name
    request = urllib.request.Request(
        SOURCES[source_name]["url"],
        headers={"User-Agent": "Alerter-Local-Training/1.0"},
    )
    with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    temporary.replace(path)
    return path


def _canonical_email(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(str(text or ""))).strip().casefold()


def _email_rows() -> tuple[list[str], list[str], list[str], dict]:
    records: list[tuple[str, str, str]] = []
    raw_counts: dict[str, dict[str, int]] = {}
    files = {
        "email_spam_ham": ("email_spam_ham.csv", "text", "label"),
        "email_phishing": ("email_phishing.csv", "Email Text", "Email Type"),
    }
    label_map = {
        "ham": "benign",
        "safe email": "benign",
        "legitimate": "benign",
        "benign": "benign",
        "spam": "spam",
        "phishing": "phishing",
        "phishing email": "phishing",
    }
    for source, (filename, text_column, label_column) in files.items():
        frame = pd.read_csv(_download(source), dtype=str, keep_default_na=False)
        if text_column not in frame or label_column not in frame:
            raise ValueError(f"Unexpected columns in the {source} corpus.")
        counts: dict[str, int] = {}
        for raw_text, raw_label in zip(
            frame[text_column], frame[label_column], strict=True
        ):
            label = label_map.get(str(raw_label).strip().casefold())
            text = str(raw_text).strip()[:20000]
            if not label or len(text) < 20:
                continue
            counts[label] = counts.get(label, 0) + 1
            records.append((text, label, source))
        raw_counts[source] = counts

    by_digest: dict[str, tuple[str, str, set[str]]] = {}
    conflicts: set[str] = set()
    for text, label, source in records:
        canonical = _canonical_email(text)
        if len(canonical) < 20:
            continue
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        existing = by_digest.get(digest)
        if existing is None:
            by_digest[digest] = (text, label, {source})
        elif existing[1] != label:
            conflicts.add(digest)
        else:
            existing[2].add(source)

    samples, labels, groups = [], [], []
    for digest, (text, label, _) in by_digest.items():
        if digest in conflicts:
            continue
        samples.append(text)
        labels.append(label)
        groups.append(digest)

    counts = {
        "raw_rows": len(records),
        "unique_after_exact_deduplication": len(samples),
        "conflicting_duplicate_groups_removed": len(conflicts),
        "source_label_counts_before_deduplication": raw_counts,
        "unique_label_counts": {
            label: labels.count(label) for label in sorted(set(labels))
        },
    }
    return samples, labels, groups, counts


def _host_group(url: str) -> str:
    candidate = str(url).strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
        candidate = "https://" + candidate
    host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or "invalid:" + hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def _url_rows() -> tuple[list[str], list[str], list[str], dict]:
    rows = []
    source_counts: dict[str, dict[str, int]] = {}
    for source in ("url_train", "url_test"):
        frame = pd.read_parquet(_download(f"{source}.parquet"))
        if not {"url", "status"}.issubset(frame.columns):
            raise ValueError(f"Unexpected columns in the {source} corpus.")
        counts: dict[str, int] = {}
        for url, status in zip(frame["url"], frame["status"], strict=True):
            label = str(status).strip().casefold()
            if label not in {"phishing", "legitimate"}:
                continue
            value = str(url).strip()
            if not value or len(value) > 4096:
                continue
            counts[label] = counts.get(label, 0) + 1
            rows.append((value, label, _host_group(value)))
        source_counts[source] = counts

    unique: dict[str, tuple[str, str, str]] = {}
    conflicts: set[str] = set()
    for url, label, group in rows:
        digest = hashlib.sha256(url.casefold().encode("utf-8")).hexdigest()
        current = unique.get(digest)
        if current is None:
            unique[digest] = (url, label, group)
        elif current[1] != label:
            conflicts.add(digest)

    samples, labels, groups = [], [], []
    for digest, (url, label, group) in unique.items():
        if digest in conflicts:
            continue
        samples.append(url)
        labels.append(label)
        groups.append(group)

    counts = {
        "raw_rows": len(rows),
        "unique_after_exact_deduplication": len(samples),
        "conflicting_duplicate_groups_removed": len(conflicts),
        "source_label_counts_before_deduplication": source_counts,
        "unique_label_counts": {
            label: labels.count(label) for label in sorted(set(labels))
        },
        "distinct_host_groups": len(set(groups)),
    }
    return samples, labels, groups, counts


def grouped_train_validation_test(
    labels: list[str], groups: list[str], seed: int = SEED
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Create deterministic 64/16/20 splits without sharing groups."""
    labels_array = np.asarray(labels)
    groups_array = np.asarray(groups)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    candidates = list(
        splitter.split(np.zeros(len(labels_array)), labels_array, groups_array)
    )
    overall = {
        label: float(np.mean(labels_array == label))
        for label in sorted(set(labels))
    }

    def split_cost(indices: np.ndarray, target_size: float) -> float:
        ratios = [
            abs(float(np.mean(labels_array[indices] == label)) - overall[label])
            for label in overall
        ]
        return abs(len(indices) / len(labels_array) - target_size) + sum(ratios)

    train_val, test = min(
        ((train, test) for train, test in candidates),
        key=lambda pair: split_cost(pair[1], 0.20),
    )
    val_splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed + 1)
    val_candidates = list(
        val_splitter.split(
            np.zeros(len(train_val)),
            labels_array[train_val],
            groups_array[train_val],
        )
    )
    train_local, val_local = min(
        val_candidates,
        key=lambda pair: split_cost(train_val[pair[1]], 0.20),
    )
    train = train_val[train_local]
    validation = train_val[val_local]
    if (
        set(groups_array[train]) & set(groups_array[validation])
        or set(groups_array[train]) & set(groups_array[test])
        or set(groups_array[validation]) & set(groups_array[test])
    ):
        raise RuntimeError("Grouped data split leaked samples across partitions.")
    return train, validation, test


def _pipeline(kind: str) -> Pipeline:
    if kind == "email":
        features = FeatureUnion([
            ("word", HashingVectorizer(
                n_features=2**18,
                alternate_sign=False,
                ngram_range=(1, 2),
                stop_words="english",
                strip_accents="unicode",
                token_pattern=r"(?u)\b\w\w+\b",
            )),
            ("char", HashingVectorizer(
                analyzer="char",
                n_features=2**19,
                alternate_sign=False,
                ngram_range=(3, 5),
            )),
        ])
    elif kind == "url":
        features = HashingVectorizer(
            analyzer="char",
            n_features=2**18,
            alternate_sign=False,
            ngram_range=(2, 5),
        )
    else:
        raise ValueError(f"Unsupported model kind: {kind}")
    return Pipeline([
        ("features", features),
        ("classifier", SGDClassifier(
            loss="log_loss",
            alpha=1e-5,
            class_weight="balanced",
            max_iter=50,
            tol=1e-3,
            random_state=SEED,
            average=True,
        )),
    ])


def _thresholds(model: Pipeline, texts: list[str], labels: list[str]) -> dict[str, float]:
    probabilities = model.predict_proba(texts)
    classes = list(model.classes_)
    thresholds = {}
    for class_index, label in enumerate(classes):
        actual = np.asarray(labels) == label
        best: tuple[float, float] | None = None
        for threshold in np.linspace(0.50, 0.99, 50):
            predicted = probabilities[:, class_index] >= threshold
            positive_count = int(predicted.sum())
            if positive_count < 10:
                continue
            precision = float(precision_recall_fscore_support(
                actual, predicted, average="binary", zero_division=0
            )[0])
            recall = float(precision_recall_fscore_support(
                actual, predicted, average="binary", zero_division=0
            )[1])
            if precision >= MIN_WARNING_PRECISION and (best is None or recall > best[0]):
                best = (recall, float(threshold))
        thresholds[label] = best[1] if best else 1.01
    return thresholds


def _evaluation(
    model: Pipeline,
    texts: list[str],
    labels: list[str],
    thresholds: dict[str, float],
) -> dict:
    predictions = model.predict(texts)
    probabilities = model.predict_proba(texts)
    classes = list(model.classes_)
    threshold_results = {}
    for index, label in enumerate(classes):
        threshold = thresholds[label]
        flagged = probabilities[:, index] >= threshold
        actual = np.asarray(labels) == label
        precision, recall, f1, _ = precision_recall_fscore_support(
            actual, flagged, average="binary", zero_division=0
        )
        threshold_results[label] = {
            "threshold": threshold,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "actual_positive": int(actual.sum()),
            "flagged_count": int(flagged.sum()),
        }
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "macro_f1": float(precision_recall_fscore_support(
            labels, predictions, average="macro", zero_division=0
        )[2]),
        "classification_report": classification_report(
            labels, predictions, labels=classes, output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=classes).tolist(),
        "classes": classes,
        "threshold_metrics_on_test": threshold_results,
    }


def _train_one(
    name: str,
    kind: str,
    texts: list[str],
    labels: list[str],
    groups: list[str],
    data_summary: dict,
) -> dict:
    train_idx, validation_idx, test_idx = grouped_train_validation_test(labels, groups)
    model = _pipeline(kind)
    model.fit([texts[i] for i in train_idx], [labels[i] for i in train_idx])
    thresholds = _thresholds(
        model,
        [texts[i] for i in validation_idx],
        [labels[i] for i in validation_idx],
    )
    metrics = _evaluation(
        model,
        [texts[i] for i in test_idx],
        [labels[i] for i in test_idx],
        thresholds,
    )
    bundle = {
        "schema_version": 1,
        "name": name,
        "pipeline": model,
        "thresholds": thresholds,
        "classes": list(model.classes_),
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_DIR / f"{name}.joblib", compress=3)
    data_summary["split_rows"] = {
        "train": int(len(train_idx)),
        "validation": int(len(validation_idx)),
        "test": int(len(test_idx)),
    }
    data_summary["split_group_counts"] = {
        "train": len(set(groups[i] for i in train_idx)),
        "validation": len(set(groups[i] for i in validation_idx)),
        "test": len(set(groups[i] for i in test_idx)),
    }
    return {
        "data": data_summary,
        "metrics": metrics,
        "model_file": f"models/{name}.joblib",
    }


def train() -> dict:
    email_texts, email_labels, email_groups, email_summary = _email_rows()
    url_texts, url_labels, url_groups, url_summary = _url_rows()
    if set(email_labels) != {"benign", "phishing", "spam"}:
        raise ValueError("Email corpora did not provide all expected classes.")
    if set(url_labels) != {"legitimate", "phishing"}:
        raise ValueError("URL corpus did not provide both expected classes.")

    report = {
        "seed": SEED,
        "method": (
            "HashingVectorizer + SGD logistic-loss classifier; exact duplicate "
            "email groups and normalized URL host groups are held wholly within "
            "one train/validation/test partition. Risk-class warning thresholds "
            f"are selected on validation for at least {MIN_WARNING_PRECISION:.0%} "
            "precision, when feasible."
        ),
        "sources": {
            name: {
                "url": info["url"],
                "license": info["license"],
                "citation": info["citation"],
            }
            for name, info in SOURCES.items()
        },
        "models": {},
    }
    report["models"]["email"] = _train_one(
        "alerter_email_v1",
        "email",
        email_texts,
        email_labels,
        email_groups,
        email_summary,
    )
    report["models"]["url"] = _train_one(
        "alerter_url_v1",
        "url",
        url_texts,
        url_labels,
        url_groups,
        url_summary,
    )
    report["limitations"] = [
        "These public corpora are historical and source-biased; performance is not a guarantee on current threats.",
        "Email duplicate control is exact after whitespace and case normalization, not semantic near-duplicate detection.",
        "Email test data is a grouped holdout from the same source corpora, not a source-held-out evaluation; source-specific patterns can inflate results.",
        "URL grouping is by hostname, not a full public-suffix registrable-domain calculation.",
        "The phishing email corpus is LGPL-3.0 and its labels/provenance inherit the source dataset's limitations.",
        "Model scores are not probabilities calibrated for real-world prevalence; low risk is not proof of safety.",
    ]
    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


if __name__ == "__main__":
    result = train()
    for kind, details in result["models"].items():
        metrics = details["metrics"]
        print(
            f"{kind}: rows={details['data']['unique_after_exact_deduplication']} "
            f"test={details['data']['split_rows']['test']} "
            f"accuracy={metrics['accuracy']:.3f} macro_f1={metrics['macro_f1']:.3f}"
        )
    print(f"Training report: {REPORT_PATH}")
