import unittest
from unittest.mock import patch

from tools.build_threat_dataset import DATASET_VERSION, build_dataset
from tools.load_atlas_dataset import load_dataset


class SyntheticThreatDatasetTests(unittest.TestCase):
    def test_train_and_test_are_stratified_and_disjoint(self):
        train, test = build_dataset()

        self.assertEqual(len(train), 100)
        self.assertEqual(len(test), 25)
        self.assertEqual(
            {label: sum(row["label"] == label for row in train) for label in {
                "benign", "spam", "phishing", "harmful_url"
            }},
            {"benign": 40, "spam": 20, "phishing": 20, "harmful_url": 20},
        )
        self.assertEqual(
            {label: sum(row["label"] == label for row in test) for label in {
                "benign", "spam", "phishing", "harmful_url"
            }},
            {"benign": 10, "spam": 5, "phishing": 5, "harmful_url": 5},
        )
        self.assertFalse({row["_id"] for row in train} & {row["_id"] for row in test})
        self.assertTrue(all(row["dataset_version"] == DATASET_VERSION for row in train + test))
        self.assertTrue(all(row["is_synthetic"] and row["source"] == "synthetic" for row in train + test))
        self.assertTrue(all(row["kind"] in {"email", "url"} for row in train + test))
        self.assertFalse(
            {row["url"].split("/")[2] for row in train if row["kind"] == "url"}
            & {row["url"].split("/")[2] for row in test if row["kind"] == "url"}
        )
        train_emails = {
            (row["subject"], row["body"]) for row in train if row["kind"] == "email"
        }
        test_emails = {
            (row["subject"], row["body"]) for row in test if row["kind"] == "email"
        }
        self.assertFalse(train_emails & test_emails)

    def test_dataset_is_reproducible(self):
        self.assertEqual(build_dataset(), build_dataset())

    def test_atlas_loader_requires_local_uri_without_exposing_credentials(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Set MONGODB_URI"):
                load_dataset()


if __name__ == "__main__":
    unittest.main()
