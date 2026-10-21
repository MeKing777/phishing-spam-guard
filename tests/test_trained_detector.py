import unittest
from unittest.mock import patch

from src.analyzer import analyze_email, analyze_url
from tools.train_local_models import grouped_train_validation_test


class TrainedDetectorIntegrationTests(unittest.TestCase):
    @patch(
        "src.analyzer.assess_trained_model",
        return_value={
            "kind": "email",
            "label": "phishing",
            "confidence": 0.97,
            "threshold": 0.95,
            "flagged": True,
        },
    )
    def test_high_precision_email_model_flag_sets_review_without_forcing_high(self, _):
        result = analyze_email(subject="Team update", body="The meeting is next week.")

        self.assertEqual(result["risk_level"], "Review")
        self.assertIn("Phishing", result["category"])
        self.assertTrue(any("locally trained email model" in item for item in result["signals"]))

    @patch(
        "src.analyzer.assess_trained_model",
        return_value={
            "kind": "url",
            "label": "phishing",
            "confidence": 0.98,
            "threshold": 0.95,
            "flagged": True,
        },
    )
    def test_url_model_flag_sets_review_without_forcing_high(self, _):
        result = analyze_url("https://ordinary.example/article")

        self.assertEqual(result["risk_level"], "Review")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertTrue(any("locally trained URL model" in item for item in result["signals"]))

    def test_model_benign_opinion_does_not_lower_heuristic_risk(self):
        message = {
            "subject": "Verify your account immediately",
            "body": "Click the link and submit your password to restore access.",
            "sender": "security@service.example",
            "reply_to": "attacker@outside.example",
        }
        with patch("src.analyzer.assess_trained_model", return_value=None):
            baseline = analyze_email(**message)
        with patch(
            "src.analyzer.assess_trained_model",
            return_value={
                "kind": "email",
                "label": "benign",
                "confidence": 0.99,
                "threshold": None,
                "flagged": False,
            },
        ):
            result = analyze_email(**message)

        self.assertEqual(result["risk_score"], baseline["risk_score"])
        self.assertEqual(result["risk_level"], baseline["risk_level"])


class GroupedSplitTests(unittest.TestCase):
    def test_samples_from_a_group_never_cross_partitions(self):
        labels, groups = [], []
        for label in ("benign", "phishing"):
            for group_index in range(30):
                for _ in range(2):
                    labels.append(label)
                    groups.append(f"{label}-{group_index}")

        train, validation, test = grouped_train_validation_test(labels, groups)
        group_splits = [
            {groups[index] for index in indices}
            for indices in (train, validation, test)
        ]
        self.assertFalse(group_splits[0] & group_splits[1])
        self.assertFalse(group_splits[0] & group_splits[2])
        self.assertFalse(group_splits[1] & group_splits[2])


if __name__ == "__main__":
    unittest.main()
