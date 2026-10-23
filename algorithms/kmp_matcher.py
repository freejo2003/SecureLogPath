"""Single-pattern Knuth-Morris-Pratt substring matching."""

from __future__ import annotations


def build_lps(pattern: str) -> list[int]:
    """Build the longest-prefix-suffix table for ``pattern`` in O(M) time."""
    lps = [0] * len(pattern)
    prefix_length = 0
    index = 1
    while index < len(pattern):
        if pattern[index] == pattern[prefix_length]:
            prefix_length += 1
            lps[index] = prefix_length
            index += 1
        elif prefix_length:
            prefix_length = lps[prefix_length - 1]
        else:
            index += 1
    return lps


def find_all(pattern: str, text: str) -> list[int]:
    """Return all match start offsets in ``text`` in O(N + M) time.

    Empty patterns are rejected so a configured signature cannot match every
    position accidentally. Offsets count Python Unicode code points.
    """
    if not pattern:
        raise ValueError("pattern must not be empty")
    matches: list[int] = []
    lps = build_lps(pattern)
    text_index = pattern_index = 0
    while text_index < len(text):
        if text[text_index] == pattern[pattern_index]:
            text_index += 1
            pattern_index += 1
            if pattern_index == len(pattern):
                matches.append(text_index - pattern_index)
                pattern_index = lps[pattern_index - 1]
        elif pattern_index:
            pattern_index = lps[pattern_index - 1]
        else:
            text_index += 1
    return matches
