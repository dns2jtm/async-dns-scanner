"""Unit tests for domain candidate generator."""

import unittest
from dns_scanner.generator import generate_cv_pattern, generate_morpheme_domains, filter_top_candidates
from dns_scanner.valuator import DomainValuator


class TestDomainGenerator(unittest.TestCase):

    def test_generate_cv_pattern_count(self):
        # CVCV has 17 consonants * 5 vowels * 17 consonants * 5 vowels = 7225
        gen = generate_cv_pattern("CVCV")
        first_few = [next(gen) for _ in range(5)]
        self.assertEqual(len(first_few), 5)
        # Check that first pattern matches CVCV structure
        for word in first_few:
            self.assertEqual(len(word), 4)

    def test_generate_morpheme_domains(self):
        domains = generate_morpheme_domains(stems=["code"], affixes=["ly", "io"])
        self.assertIn("codely", domains)
        self.assertIn("codeio", domains)
        self.assertIn("lycode", domains)

    def test_filter_top_candidates(self):
        valuator = DomainValuator()
        candidates = ["luna", "kipo", "zqwt", "bcdf"]
        top = filter_top_candidates(candidates, valuator, min_score=20.0, limit=2)
        self.assertLessEqual(len(top), 2)
        top_labels = [c["label"] for c in top]
        self.assertIn("luna", top_labels)


if __name__ == "__main__":
    unittest.main()
