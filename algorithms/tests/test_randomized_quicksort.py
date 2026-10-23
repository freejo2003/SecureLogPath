import random
import unittest

from algorithms.randomized_quicksort import randomized_quicksort


class RandomizedQuickSortTests(unittest.TestCase):
    def test_empty_singleton_and_duplicates(self):
        self.assertEqual(randomized_quicksort([]), [])
        self.assertEqual(randomized_quicksort([4]), [4])
        self.assertEqual(randomized_quicksort([3, 1, 3, 2, 1]), [1, 1, 2, 3, 3])

    def test_reverse_and_adversarial_order_with_seed(self):
        values = list(range(1500, -1, -1))
        self.assertEqual(
            randomized_quicksort(values, rng=random.Random(7)), sorted(values)
        )

    def test_seed_repeats_result_and_does_not_mutate_input(self):
        values = [8, 2, 7, 2, 9, 1]
        original = values.copy()
        first = randomized_quicksort(values, rng=random.Random(42))
        second = randomized_quicksort(values, rng=random.Random(42))
        self.assertEqual(first, second)
        self.assertEqual(values, original)

    def test_key_function(self):
        records = [{"time": 3}, {"time": 1}, {"time": 2}]
        self.assertEqual(
            randomized_quicksort(records, key=lambda record: record["time"]),
            [{"time": 1}, {"time": 2}, {"time": 3}],
        )


if __name__ == "__main__":
    unittest.main()
