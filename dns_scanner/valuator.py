"""Domain valuation, linguistic scoring, and lexicon analysis."""

import re
import math
from typing import Set, Dict, Optional, Tuple, Any

VOWELS = set("aeiouy")
CONSONANTS = set("bcdfghjklmnpqrstvwxz")

COMMON_PREFIXES = {"re", "de", "un", "in", "pro", "pre", "co", "meta", "syn", "auto", "hyper", "omni"}
COMMON_SUFFIXES = {"ly", "fy", "ic", "al", "io", "ia", "ex", "ix", "on", "ar", "is", "us", "er", "or"}

DEFAULT_LEXICON = {
    "code", "data", "cloud", "core", "mesh", "pulse", "node", "byte", "bit", "sync",
    "flux", "base", "mind", "peak", "prime", "wave", "stack", "link", "flow", "apex",
    "nova", "luna", "star", "solar", "meta", "cyber", "quantum", "vector", "matrix",
    "logic", "spark", "forge", "craft", "vault", "haven", "swift", "hyper", "omni",
    "alpha", "beta", "gamma", "delta", "nexus", "axon", "scale", "pilot", "orbit",
    "apple", "gold", "silver", "blue", "green", "red", "fast", "smart", "open", "free"
}


def load_lexicon(path: str) -> Tuple[Set[str], Dict[str, int]]:
    """
    Loads a word list such as SOWPODS / Collins Scrabble Words.

    Accepts one word per line, optionally followed by a whitespace- or
    comma-separated integer frequency (e.g. "apple 5000000"). Returns
    (words, frequencies). Lines starting with '#' are ignored.
    """
    words: Set[str] = set()
    freqs: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[\s,]+", line)
            word = parts[0].lower()
            if not word.isalpha():
                continue
            words.add(word)
            if len(parts) > 1 and parts[1].isdigit():
                freqs[word] = int(parts[1])
    return words, freqs


class DomainValuator:
    """
    Evaluates semantic value, brandability, and pronounceability of domain strings.
    Scoring range: 0.0 to 100.0.
    """

    def __init__(self, dictionary_words: Optional[Set[str]] = None, word_frequencies: Optional[Dict[str, int]] = None):
        self.dictionary = dictionary_words if dictionary_words is not None else DEFAULT_LEXICON
        self.frequencies = word_frequencies or {}

    def score_pronounceability(self, s: str) -> float:
        """
        Calculates phonetic score based on vowel-consonant alternation,
        length penalty, and avoidance of awkward consonant clusters.
        """
        s = s.lower().strip()
        n = len(s)
        if n == 0:
            return 0.0

        vowels_count = sum(1 for c in s if c in VOWELS)
        ratio = vowels_count / n

        # Optimal vowel ratio in natural language is roughly 35% - 50%
        ratio_score = 1.0 - abs(ratio - 0.42) * 2.0
        ratio_score = max(0.0, ratio_score)

        # Alternation check: reward C-V-C-V patterns
        alternations = 0
        consecutive_consonants = 0
        max_consec_consonants = 0

        for i in range(n - 1):
            c1_vowel = s[i] in VOWELS
            c2_vowel = s[i+1] in VOWELS
            if c1_vowel != c2_vowel:
                alternations += 1

            if not c1_vowel:
                consecutive_consonants += 1
                max_consec_consonants = max(max_consec_consonants, consecutive_consonants)
            else:
                consecutive_consonants = 0

        alt_score = alternations / max(1, n - 1)

        # Heavy penalty for 3+ consecutive consonants
        penalty = 0.0
        if max_consec_consonants >= 3:
            penalty = 0.3 * (max_consec_consonants - 2)

        base_score = (0.5 * ratio_score + 0.5 * alt_score) - penalty
        return max(0.0, min(1.0, base_score))

    def evaluate(self, label: str) -> Dict[str, Any]:
        """Returns comprehensive linguistic breakdown and composite valuation score."""
        label = label.lower().strip()
        n = len(label)

        is_dict_word = label in self.dictionary
        raw_freq = self.frequencies.get(label, 0)
        pronounce_score = self.score_pronounceability(label)

        # Length multiplier (shorter domains are exponentially rarer and more valuable)
        # 3L = 1.0, 4L = 0.85, 5L = 0.70, 6L = 0.55, 7L+ = decaying
        if n <= 3:
            length_mult = 1.0
        elif n == 4:
            length_mult = 0.85
        elif n == 5:
            length_mult = 0.70
        elif n == 6:
            length_mult = 0.55
        else:
            length_mult = max(0.2, 0.55 - (n - 6) * 0.08)

        # Dictionary frequency component (log scaled)
        if raw_freq > 0:
            freq_score = min(1.0, math.log10(raw_freq) / 9.0)
        elif is_dict_word:
            freq_score = 0.5
        else:
            freq_score = 0.0

        # Composite score calculation (0 - 100)
        if is_dict_word:
            composite = (50.0 + (freq_score * 30.0) + (pronounce_score * 20.0)) * length_mult
        else:
            composite = (pronounce_score * 70.0) * length_mult

        composite = round(max(0.0, min(100.0, composite)), 2)

        return {
            "label": label,
            "length": n,
            "is_dictionary_word": is_dict_word,
            "frequency": raw_freq,
            "pronounceability": round(pronounce_score, 3),
            "composite_score": composite
        }
