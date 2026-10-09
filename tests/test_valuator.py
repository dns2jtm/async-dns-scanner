"""Unit tests for domain valuation, pronounceability, and linguistic algorithms."""

import unittest
from dns_scanner.valuator import DomainValuator


class TestDomainValuator(unittest.TestCase):

    def setUp(self):
        self.dictionary = {"apple", "cloud", "apex", "flow", "nexus"}
        self.frequencies = {"apple": 5000000, "cloud": 8000000, "apex": 200000}
        self.valuator = DomainValuator(self.dictionary, self.frequencies)

    def test_score_pronounceability_natural_vs_cluster(self):
        score_cvcv = self.valuator.score_pronounceability("luna")
        score_unnatural = self.valuator.score_pronounceability("zqwt")

        self.assertGreater(score_cvcv, 0.7)
        self.assertLess(score_unnatural, 0.2)

    def test_score_pronounceability_empty(self):
        self.assertEqual(self.valuator.score_pronounceability(""), 0.0)

    def test_evaluate_dictionary_word(self):
        result = self.valuator.evaluate("cloud")
        self.assertTrue(result["is_dictionary_word"])
        self.assertEqual(result["frequency"], 8000000)
        self.assertGreater(result["composite_score"], 50.0)

    def test_evaluate_synthetic_pronounceable(self):
        result = self.valuator.evaluate("miko")
        self.assertFalse(result["is_dictionary_word"])
        self.assertGreater(result["pronounceability"], 0.7)
        self.assertGreater(result["composite_score"], 35.0)

    def test_length_multiplier_penalty(self):
        short_res = self.valuator.evaluate("nova")
        long_res = self.valuator.evaluate("novaxzprlky")
        self.assertGreater(short_res["composite_score"], long_res["composite_score"])


if __name__ == "__main__":
    unittest.main()
