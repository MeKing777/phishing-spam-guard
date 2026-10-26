"""Load the pinned, labeled public email and URL corpora into MongoDB Atlas."""
from __future__ import annotations

import hashlib
import os
import sys
from collections import defaultdict


DATASET_VERSION = "public-corpora-v2"
PREVIOUS_DATASET_VERSIONS = ("public-corpora-v1", DATASET_VERSION)
DATABASE_NAME = "alerter_training"
SPLITS = ("train", "validation", "test")
BATCH_SIZE = 1000


def _records_for_kind(kind: str, texts: list[str], labels: list[str], groups: list[str], splits: dict[str, set[int]]):
    source_pool = {
        "email": "email_public_corpora",
        "url": "hannousse_yahiouche_url_benchmark",
    }[kind]
    licenses = {
        "email": ["CC0-1.0", "LGPL-3.0"],
        "url": ["CC-BY-4.0"],
    }[kind]
    for index, (text, label, group) in enumerate(zip(texts, labels, groups, strict=True)):
        split = next(name for name in SPLITS if index in splits[name])
        # Keep examples from one URL host in the same split, but store each
        # distinct sample as its own document.
        digest = hashlib.sha256(
            f"{kind}\0{group}\0{text}".encode("utf-8")
        ).hexdigest()
        record = {
            "_id": f"{DATASET_VERSION}:{kind}:{split}:{digest}",
            "dataset_version": DATASET_VERSION,
            "kind": kind,
            "label": label,
            "source_corpus_group": source_pool,
            "source_licenses": licenses,
            "source": "pinned_public_corpora",
            "is_synthetic": False,
            "split": split,
        }
        if kind == "email":
            record["text"] = text
        else:
            record["url"] = text
        yield split, record


def load_dataset() -> tuple[int, int]:
    """Upsert labeled public records; return (email_count, url_count)."""
    uri = os.environ.get("MONGODB_URI", "").strip()
    if not uri:
        raise RuntimeError(
            "Set MONGODB_URI in your local environment to an Atlas connection string. "
            "Do not paste database credentials into chat or commit them."
        )

    try:
        from pymongo import MongoClient, ReplaceOne
        from tools.train_local_models import (
            SOURCES,
            _email_rows,
            _url_rows,
            grouped_train_validation_test,
        )
    except ImportError as error:
        raise RuntimeError(
            "Atlas and training dependencies are missing. Install them with "
            "`python -m pip install -r requirements-training.txt -r requirements-atlas.txt`."
        ) from error

    email_texts, email_labels, email_groups, email_summary = _email_rows()
    url_texts, url_labels, url_groups, url_summary = _url_rows()
    email_splits = grouped_train_validation_test(email_labels, email_groups)
    url_splits = grouped_train_validation_test(url_labels, url_groups)
    split_indices = {
        kind: {
            name: set(int(index) for index in indices)
            for name, indices in zip(SPLITS, split_arrays, strict=True)
        }
        for kind, split_arrays in (("email", email_splits), ("url", url_splits))
    }
    split_counts = {
        kind: {name: len(indices) for name, indices in partitions.items()}
        for kind, partitions in split_indices.items()
    }

    database_name = os.environ.get("ALERTER_MONGODB_DATABASE", DATABASE_NAME)
    client = MongoClient(uri, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000)
    try:
        client.admin.command("ping")
        database = client[database_name]
        # Remove only records written by this loader's earlier dataset
        # versions, including any partial run, before creating the corrected
        # version. These collections also hold any unrelated records.
        owned_collections = [
            f"{kind}_{split}_samples"
            for kind in ("email", "url")
            for split in SPLITS
        ]
        for collection_name in owned_collections:
            database[collection_name].delete_many(
                {"dataset_version": {"$in": PREVIOUS_DATASET_VERSIONS}}
            )
        database["dataset_catalog"].delete_many(
            {"_id": {"$in": PREVIOUS_DATASET_VERSIONS}}
        )
        counts = defaultdict(int)
        pending: dict[str, list] = defaultdict(list)
        indexed: set[str] = set()

        def flush(collection_name: str) -> None:
            operations = pending[collection_name]
            if operations:
                database[collection_name].bulk_write(operations, ordered=False)
                operations.clear()

        for kind, texts, labels, groups in (
            ("email", email_texts, email_labels, email_groups),
            ("url", url_texts, url_labels, url_groups),
        ):
            for split, record in _records_for_kind(
                kind, texts, labels, groups, split_indices[kind]
            ):
                collection_name = f"{kind}_{split}_samples"
                collection = database[collection_name]
                if collection_name not in indexed:
                    collection.create_index([("label", 1), ("kind", 1)])
                    collection.create_index("dataset_version")
                    indexed.add(collection_name)
                pending[collection_name].append(
                    ReplaceOne({"_id": record["_id"]}, record, upsert=True)
                )
                counts[kind] += 1
                if len(pending[collection_name]) >= BATCH_SIZE:
                    flush(collection_name)

        for collection_name in pending:
            flush(collection_name)

        database["dataset_catalog"].replace_one(
            {"_id": DATASET_VERSION},
            {
                "_id": DATASET_VERSION,
                "dataset_version": DATASET_VERSION,
                "email_counts": email_summary["unique_label_counts"],
                "url_counts": url_summary["unique_label_counts"],
                "email_splits": split_counts["email"],
                "url_splits": split_counts["url"],
                "sources": SOURCES,
                "split_method": "Deterministic 64/16/20 stratified grouped split; exact email groups and URL host groups stay within one split.",
                "limitations": [
                    "Public corpora are historical and source-biased.",
                    "Email labels inherit source dataset limitations and are not independently verified.",
                    "No inbox contents or browsing history are included.",
                ],
            },
            upsert=True,
        )
        return counts["email"], counts["url"]
    finally:
        client.close()


if __name__ == "__main__":
    try:
        email_count, url_count = load_dataset()
    except RuntimeError as error:
        print(f"Atlas dataset load failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except Exception as error:
        print(
            f"Atlas dataset load failed ({type(error).__name__}). Check the URI, "
            "Atlas IP access list, and database user's write permissions. "
            "Connection details are omitted.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    print(f"Loaded public labeled records into Atlas: emails={email_count}, URLs={url_count}")
    print("Collections: email_train_samples, email_validation_samples, email_test_samples,")
    print("            url_train_samples, url_validation_samples, url_test_samples, dataset_catalog")
