import unittest

from src.analyzer import analyze_url


class AnalyzeRedirectUrlTests(unittest.TestCase):
    def test_flags_risky_destination_in_redirect_parameter(self):
        result = analyze_url(
            "https://safe.example/redirect?url="
            "https%3A%2F%2Fpaypal-login.example%2Fverify"
        )

        self.assertIn(result["risk_level"], {"Review", "High"})
        self.assertTrue(
            any("Redirect parameter points to" in signal for signal in result["signals"])
        )

    def test_treats_shortened_links_as_needing_review(self):
        result = analyze_url("https://bit.ly/example")

        self.assertEqual(result["risk_level"], "Review")

    def test_does_not_raise_risk_for_unflagged_redirect_destination(self):
        result = analyze_url(
            "https://safe.example/redirect?next="
            "https%3A%2F%2Fexample.org%2Farticle"
        )

        self.assertEqual(result["risk_level"], "Low")


if __name__ == "__main__":
    unittest.main()
