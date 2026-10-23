import unittest

from algorithms.monte_carlo import estimate_proportion


class MonteCarloTests(unittest.TestCase):
    def test_reproducible_sample_and_metadata(self):
        population = list(range(100))
        first = estimate_proportion(population, lambda value: value < 20, 0.30, seed=17)
        second = estimate_proportion(population, lambda value: value < 20, 0.30, seed=17)
        self.assertEqual(first.sampled_successes, second.sampled_successes)
        self.assertEqual(first.sample_count, 30)
        self.assertEqual(first.actual_sample_fraction, 0.30)
        self.assertEqual(first.seed, 17)
        self.assertEqual(first.exact_baseline, 0.20)
        self.assertEqual(first.baseline_status, "exact_full_scan")
        self.assertLessEqual(first.confidence_interval[0], first.confidence_interval[1])

    def test_one_percent_boundary_and_without_replacement(self):
        population = list(range(100))
        result = estimate_proportion(population, lambda value: value == 0, 0.01, seed=4)
        self.assertEqual(result.sample_count, 1)
        self.assertEqual(result.requested_sample_fraction, 0.01)

    def test_single_record_sample_has_zero_width_interval(self):
        result = estimate_proportion([True], bool, 0.30, seed=1)
        self.assertEqual(result.sample_count, 1)
        self.assertEqual(result.confidence_interval, (1.0, 1.0))
        self.assertGreaterEqual(result.confidence_interval[0], 0.0)
        self.assertLessEqual(result.confidence_interval[1], 1.0)
        estimate = estimate_proportion(
            list(range(100)), bool, 0.30, seed=1, exact_baseline_limit=0
        )
        self.assertIsNone(estimate.exact_baseline)
        self.assertEqual(estimate.baseline_status, "omitted_scope_too_large")

    def test_invalid_fraction_confidence_and_empty_population(self):
        for fraction in (0.009, 0.301):
            with self.subTest(fraction=fraction), self.assertRaises(ValueError):
                estimate_proportion([1, 2], bool, fraction)
        with self.assertRaises(ValueError):
            estimate_proportion([1], bool, 0.1, confidence_level=1)
        with self.assertRaises(ValueError):
            estimate_proportion([], bool, 0.1)


if __name__ == "__main__":
    unittest.main()
