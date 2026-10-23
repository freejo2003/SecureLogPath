"""Binary-search bounds and half-open time-window lookup helpers."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")
K = TypeVar("K")


def lower_bound(
    values: Sequence[T], target: K, *, key: Callable[[T], K] | None = None
) -> int:
    """Return the first index whose value/key is greater than or equal to target."""
    key_fn: Callable[[T], K] = key if key is not None else lambda value: value  # type: ignore[assignment]
    low, high = 0, len(values)
    while low < high:
        middle = (low + high) // 2
        if key_fn(values[middle]) < target:
            low = middle + 1
        else:
            high = middle
    return low


def upper_bound(
    values: Sequence[T], target: K, *, key: Callable[[T], K] | None = None
) -> int:
    """Return the first index whose value/key is strictly greater than target."""
    key_fn: Callable[[T], K] = key if key is not None else lambda value: value  # type: ignore[assignment]
    low, high = 0, len(values)
    while low < high:
        middle = (low + high) // 2
        if target < key_fn(values[middle]):
            high = middle
        else:
            low = middle + 1
    return low


def equal_range(
    values: Sequence[T], target: K, *, key: Callable[[T], K] | None = None
) -> tuple[int, int]:
    """Return the half-open index range containing values equal to target."""
    return (
        lower_bound(values, target, key=key),
        upper_bound(values, target, key=key),
    )


def time_window_indices(
    sorted_records: Sequence[T],
    start_inclusive: K,
    end_exclusive: K,
    *,
    timestamp_key: Callable[[T], K],
) -> tuple[int, int]:
    """Find ``[start, end)`` bounds in records sorted by timestamp.

    This helper is for in-memory demonstrations and benchmark fixtures. Real
    log retrieval must use indexed database time predicates.
    """
    if end_exclusive < start_inclusive:
        raise ValueError("end_exclusive must not precede start_inclusive")
    return (
        lower_bound(sorted_records, start_inclusive, key=timestamp_key),
        lower_bound(sorted_records, end_exclusive, key=timestamp_key),
    )
