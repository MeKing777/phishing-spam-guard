"""Idempotently load the synthetic train/test corpus into MongoDB Atlas."""
from __future__ import annotations

import json
import os
import sys

from tools.build_threat_dataset import DEFAULT_OUTPUT, write_dataset


def load_dataset() -> tuple[int, int]:
    uri = os.environ.get("MONGODB_URI", "").strip()
    if not uri:
        raise RuntimeError(
            "Set MONGODB_URI in your local environment to an Atlas connection string. "
            "Do not paste database credentials into chat or commit them."
        )

    try:
        from pymongo import MongoClient, ReplaceOne
    except ImportError as error:
        raise RuntimeError(
            "MongoDB driver is missing. Install it with "
            "`python -m pip install -r requirements-atlas.txt`."
        ) from error

    train_path, test_path = write_dataset(DEFAULT_OUTPUT)
    database_name = os.environ.get("ALERTER_MONGODB_DATABASE", "alerter_training")
    client = MongoClient(uri, serverSelectionTimeoutMS=10000, connectTimeoutMS=10000)
    try:
        client.admin.command("ping")
        database = client[database_name]
        totals: list[int] = []
        for split, path in (("train", train_path), ("test", test_path)):
            collection = database[f"{split}_samples"]
            collection.create_index([("label", 1), ("kind", 1)])
            collection.create_index("dataset_version")
            operations = []
            for line in path.read_text(encoding="utf-8").splitlines():
                sample = json.loads(line)
                operations.append(ReplaceOne({"_id": sample["_id"]}, sample, upsert=True))
            if operations:
                collection.bulk_write(operations, ordered=False)
                totals.append(len(operations))
            else:
                totals.append(0)
        return totals[0], totals[1]
    finally:
        client.close()


if __name__ == "__main__":
    try:
        train_count, test_count = load_dataset()
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
    print(f"Loaded synthetic records into Atlas: train={train_count}, test={test_count}")
    print("Collections: train_samples, test_samples")
