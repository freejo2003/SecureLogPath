import unittest

from algorithms.kmp_matcher import build_lps, find_all


class KMPMatcherTests(unittest.TestCase):
    def test_lps_prefix_fallbacks(self):
        self.assertEqual(build_lps("ABABCABAB"), [0, 0, 1, 2, 0, 1, 2, 3, 4])

    def test_all_overlapping_matches(self):
        self.assertEqual(find_all("ABA", "ABABABA"), [0, 2, 4])

    def test_repeated_prefix_pattern(self):
        self.assertEqual(find_all("AAAA", "AAAAAAAAA"), [0, 1, 2, 3, 4, 5])

    def test_no_match_empty_text_and_unicode(self):
        self.assertEqual(find_all("needle", "haystack"), [])
        self.assertEqual(find_all("needle", ""), [])
        self.assertEqual(find_all("猫", "犬猫猫"), [1, 2])

    def test_empty_pattern_is_rejected(self):
        with self.assertRaises(ValueError):
            find_all("", "text")


if __name__ == "__main__":
    unittest.main()
