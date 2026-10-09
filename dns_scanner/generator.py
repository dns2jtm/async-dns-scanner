"""Candidate domain generator based on phonetic templates and morpheme combining."""

import itertools
from typing import List, Generator
from .valuator import DomainValuator

VOWELS = ["a", "e", "i", "o", "u"]
CONSONANTS = ["b", "c", "d", "f", "g", "h", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z"]

TECH_STEMS = [
    "byte", "bit", "data", "flow", "cloud", "core", "mesh", "pulse",
    "hyper", "omni", "poly", "node", "nexus", "volt", "stack", "sync",
    "flux", "base", "mind", "peak", "prime", "wave", "code", "dev"
]

AFFIXES = ["ly", "fy", "ic", "al", "io", "ia", "ex", "ix", "on", "ar", "is", "us", "er", "or", "lab", "hub"]


def generate_cv_pattern(pattern: str = "CVCV") -> Generator[str, None, None]:
    """Generates all combinations matching a pattern of 'C' (consonants) and 'V' (vowels)."""
    options = []
    for char in pattern.upper():
        if char == "C":
            options.append(CONSONANTS)
        elif char == "V":
            options.append(VOWELS)
        else:
            options.append([char.lower()])

    for combo in itertools.product(*options):
        yield "".join(combo)


def generate_morpheme_domains(stems: List[str] = TECH_STEMS, affixes: List[str] = AFFIXES) -> List[str]:
    """Generates domains by combining semantic stems and affixes."""
    candidates = set()
    for stem in stems:
        for affix in affixes:
            candidates.add(f"{stem}{affix}")
            candidates.add(f"{affix}{stem}")
    return sorted(list(candidates))


def filter_top_candidates(
    candidates: List[str],
    valuator: DomainValuator,
    min_score: float = 60.0,
    limit: int = 100
) -> List[dict]:
    """Evaluates and sorts candidate domains by pronounceability and composite score."""
    scored = []
    for cand in candidates:
        evaluation = valuator.evaluate(cand)
        if evaluation["composite_score"] >= min_score:
            scored.append(evaluation)

    scored.sort(key=lambda x: x["composite_score"], reverse=True)
    return scored[:limit]
