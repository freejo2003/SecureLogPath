"""Randomized three-way QuickSort for controlled in-memory datasets."""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")
K = TypeVar("K")


def randomized_quicksort(
    values: Sequence[T],
    *,
    key: Callable[[T], K] | None = None,
    rng: random.Random | None = None,
) -> list[T]:
    """Return a sorted copy using randomized pivots and three-way partitioning.

    Expected time is O(N log N); the theoretical worst case remains O(N²).
    Equal keys are grouped in one partition, which handles duplicate-heavy
    inputs efficiently. A seeded ``random.Random`` can make demonstrations
    reproducible. This function does not mutate ``values``.
    """
    result = list(values)
    if len(result) < 2:
        return result
    key_fn: Callable[[T], object] = key if key is not None else lambda value: value
    generator = rng if rng is not None else random.Random()
    pending = [(0, len(result))]

    while pending:
        low, high = pending.pop()
        while high - low > 1:
            pivot = key_fn(result[generator.randrange(low, high)])
            less, scan, greater = low, low, high
            while scan < greater:
                current = key_fn(result[scan])
                if current < pivot:
                    result[less], result[scan] = result[scan], result[less]
                    less += 1
                    scan += 1
                elif current > pivot:
                    greater -= 1
                    result[scan], result[greater] = result[greater], result[scan]
                else:
                    scan += 1

            left = (low, less)
            right = (greater, high)
            left_size = left[1] - left[0]
            right_size = right[1] - right[0]
            if left_size < right_size:
                if right_size > 1:
                    pending.append(right)
                low, high = left
            else:
                if left_size > 1:
                    pending.append(left)
                low, high = right
    return result
