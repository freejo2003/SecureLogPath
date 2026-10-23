import unittest

from algorithms.binary_search import equal_range, lower_bound, time_window_indices, upper_bound


class BinarySearchTests(unittest.TestCase):
    def test_bounds_on_duplicates(self):
        values = [1, 2, 2, 2, 5]
        self.assertEqual(lower_bound(values, 2), 1)
        self.assertEqual(upper_bound(values, 2), 4)
        self.assertEqual(equal_range(values, 2), (1, 4))

    def test_empty_and_outside_ranges(self):
        self.assertEqual(equal_range([], 3), (0, 0))
        self.assertEqual(lower_bound([2, 4], 1), 0)
        self.assertEqual(upper_bound([2, 4], 5), 2)

    def test_half_open_timestamp_window(self):
        rows = [(10, "a"), (10, "b"), (12, "c"), (15, "d")]
        start, end = time_window_indices(
            rows, 10, 15, timestamp_key=lambda row: row[0]
        )
        self.assertEqual((start, end), (0, 3))
        self.assertEqual(rows[start:end], rows[:3])

    def test_reversed_window_rejected(self):
        with self.assertRaises(ValueError):
            time_window_indices([], 4, 3, timestamp_key=lambda row: row)


if __name__ == "__main__":
    unittest.main()
