"""Unit tests for retry backoff and lexicon loading."""

import os
import tempfile
import unittest

from dns_scanner.resolver import backoff_delay
from dns_scanner.valuator import load_lexicon, DomainValuator


class TestBackoff(unittest.TestCase):

    def test_backoff_bounded_and_growing_cap(self):
        for attempt in range(6):
            cap = min(2.0, 0.1 * (2 ** attempt))
            for _ in range(200):
                d = backoff_delay(attempt)
                self.assertGreaterEqual(d, 0.0)
                self.assertLessEqual(d, cap)

    def test_backoff_respects_cap(self):
        for _ in range(200):
            self.assertLessEqual(backoff_delay(20), 2.0)


class TestLexicon(unittest.TestCase):

    def test_load_lexicon_words_and_frequencies(self):
        content = "# comment\nAPPLE 5000000\nzebra\nbad-word\ncloud,8000000\n\n"
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            words, freqs = load_lexicon(path)
        finally:
            os.unlink(path)
        self.assertEqual(words, {"apple", "zebra", "cloud"})
        self.assertEqual(freqs, {"apple": 5000000, "cloud": 8000000})

        valuator = DomainValuator(words, freqs)
        self.assertTrue(valuator.evaluate("zebra")["is_dictionary_word"])
        self.assertFalse(valuator.evaluate("luna")["is_dictionary_word"])


if __name__ == "__main__":
    unittest.main()
