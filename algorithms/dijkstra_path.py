"""Heap-based shortest paths for the simulated topology graph."""

from __future__ import annotations

import heapq
import itertools
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from numbers import Real
from typing import Hashable, TypeVar

Node = TypeVar("Node", bound=Hashable)


@dataclass(frozen=True)
class PathResult:
    """Lowest-cost path and its total modeled cost."""

    nodes: tuple[Hashable, ...]
    total_cost: float


def risk_to_cost(risk: int | float) -> float:
    """Map bounded risk R in [1, 9] to non-negative path cost W = 10 - R."""
    if isinstance(risk, bool) or not isinstance(risk, Real) or not math.isfinite(risk):
        raise ValueError("risk must be a finite number in [1, 9]")
    if not 1 <= risk <= 9:
        raise ValueError("risk must be in [1, 9]")
    return float(10 - risk)


def shortest_path(
    graph: Mapping[Node, Sequence[tuple[Node, int | float]]], start: Node, target: Node
) -> PathResult | None:
    """Return a minimum-cost path, or ``None`` when target is unreachable.

    The graph is directed and represented as ``node -> (neighbor, cost)``
    edges. Blocked edges must be omitted by the caller. All supplied costs are
    validated as finite and non-negative. Complexity is O((V + E) log V).
    """
    for edges in graph.values():
        for edge in edges:
            if len(edge) != 2:
                raise ValueError("each edge must contain a neighbor and a cost")
            weight = edge[1]
            if (
                isinstance(weight, bool)
                or not isinstance(weight, Real)
                or not math.isfinite(weight)
                or weight < 0
            ):
                raise ValueError("edge costs must be finite and non-negative")

    if start == target:
        return PathResult((start,), 0.0)

    distances: dict[Node, float] = {start: 0.0}
    previous: dict[Node, Node] = {}
    sequence = itertools.count()
    queue: list[tuple[float, int, Node]] = [(0.0, next(sequence), start)]

    while queue:
        distance, _, node = heapq.heappop(queue)
        if distance != distances.get(node):
            continue
        if node == target:
            break
        for neighbor, weight in graph.get(node, ()):
            candidate = distance + float(weight)
            if candidate < distances.get(neighbor, math.inf):
                distances[neighbor] = candidate
                previous[neighbor] = node
                heapq.heappush(queue, (candidate, next(sequence), neighbor))

    if target not in distances:
        return None

    reversed_path = [target]
    while reversed_path[-1] != start:
        reversed_path.append(previous[reversed_path[-1]])
    reversed_path.reverse()
    return PathResult(tuple(reversed_path), distances[target])
