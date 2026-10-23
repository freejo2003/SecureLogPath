import unittest

from algorithms.dijkstra_path import PathResult, risk_to_cost, shortest_path


class DijkstraPathTests(unittest.TestCase):
    def test_lowest_cost_route_and_explanation(self):
        graph = {
            "entry": [("a", 4), ("b", 1)],
            "b": [("a", 2), ("target", 7)],
            "a": [("target", 2)],
            "target": [],
        }
        self.assertEqual(shortest_path(graph, "entry", "target"), PathResult(("entry", "b", "a", "target"), 5.0))

    def test_unreachable_start_equals_target_and_blocked_edge(self):
        graph = {"a": [], "b": []}
        self.assertIsNone(shortest_path(graph, "a", "b"))
        self.assertEqual(shortest_path(graph, "a", "a"), PathResult(("a",), 0.0))
        self.assertIsNone(shortest_path({"a": []}, "a", "blocked"))

    def test_negative_nonfinite_and_boolean_costs_rejected(self):
        for weight in (-1, float("inf"), float("nan"), True):
            with self.subTest(weight=weight), self.assertRaises(ValueError):
                shortest_path({"a": [("b", weight)]}, "a", "b")

    def test_risk_mapping_bounds(self):
        self.assertEqual(risk_to_cost(9), 1.0)
        self.assertEqual(risk_to_cost(1), 9.0)
        for risk in (0, 10, float("nan")):
            with self.subTest(risk=risk), self.assertRaises(ValueError):
                risk_to_cost(risk)


if __name__ == "__main__":
    unittest.main()
