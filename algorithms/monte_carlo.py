"""Reproducible finite-population Monte Carlo proportion estimation."""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from statistics import NormalDist
from time import perf_counter
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ProportionEstimate:
    """Estimate metadata suitable for an academic demonstration response."""

    estimate: float
    confidence_interval: tuple[float, float]
    confidence_level: float
    interval_method: str
    sample_count: int
    population_size: int
    requested_sample_fraction: float
    actual_sample_fraction: float
    sampled_successes: int
    seed: int | None
    exact_baseline: float | None
    baseline_status: str
    elapsed_ms: float


def _wilson_interval(
    successes: int, sample_count: int, population_size: int, confidence_level: float
) -> tuple[float, float]:
    estimate = successes / sample_count
    if sample_count == population_size:
        return estimate, estimate

    z = NormalDist().inv_cdf(0.5 + confidence_level / 2)
    z_squared = z * z
    denominator = 1 + z_squared / sample_count
    center = (estimate + z_squared / (2 * sample_count)) / denominator
    half_width = (
        z
        * math.sqrt(
            estimate * (1 - estimate) / sample_count
            + z_squared / (4 * sample_count * sample_count)
        )
        / denominator
    )
    correction = math.sqrt((population_size - sample_count) / (population_size - 1))
    return max(0.0, center - half_width * correction), min(
        1.0, center + half_width * correction
    )


def estimate_proportion(
    population: Sequence[T],
    predicate: Callable[[T], bool],
    sample_fraction: float,
    *,
    confidence_level: float = 0.95,
    seed: int | None = None,
    exact_baseline_limit: int = 10_000,
) -> ProportionEstimate:
    """Estimate the fraction of population records satisfying ``predicate``.

    Records are sampled without replacement. The requested fraction must be
    between 1% and 30%. Sample count is rounded up, with one record minimum.
    Confidence bounds use a Wilson score interval with the finite-population
    correction; this is an approximation for sampling without replacement.
    An exact full-scan baseline is computed only when population size is at or
    below ``exact_baseline_limit``. The predicate should be deterministic and
    side-effect-free because baseline calculation evaluates the full scope.
    """
    if not 0.01 <= sample_fraction <= 0.30:
        raise ValueError("sample_fraction must be between 0.01 and 0.30")
    if not 0 < confidence_level < 1:
        raise ValueError("confidence_level must be between 0 and 1")
    if exact_baseline_limit < 0:
        raise ValueError("exact_baseline_limit must be non-negative")
    population_size = len(population)
    if population_size == 0:
        raise ValueError("population must not be empty")

    start_time = perf_counter()
    sample_count = min(population_size, max(1, math.ceil(population_size * sample_fraction)))
    generator = random.Random(seed)
    sample_indices = generator.sample(range(population_size), sample_count)
    successes = sum(bool(predicate(population[index])) for index in sample_indices)
    estimate = successes / sample_count
    interval = _wilson_interval(successes, sample_count, population_size, confidence_level)

    exact_baseline: float | None = None
    if population_size <= exact_baseline_limit:
        exact_baseline = sum(bool(predicate(record)) for record in population) / population_size
    elapsed_ms = (perf_counter() - start_time) * 1000

    return ProportionEstimate(
        estimate=estimate,
        confidence_interval=interval,
        confidence_level=confidence_level,
        interval_method="wilson_score_with_finite_population_correction_approximation",
        sample_count=sample_count,
        population_size=population_size,
        requested_sample_fraction=sample_fraction,
        actual_sample_fraction=sample_count / population_size,
        sampled_successes=successes,
        seed=seed,
        exact_baseline=exact_baseline,
        baseline_status="exact_full_scan" if exact_baseline is not None else "omitted_scope_too_large",
        elapsed_ms=elapsed_ms,
    )
