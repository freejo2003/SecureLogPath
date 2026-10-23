# SecureLogPath algorithms

This root-level Python package is the **only source of algorithm
implementations** in the project. It is standard-library-only and must not
import FastAPI, database/ORM code, or browser code.

Python application layers call these modules directly, for example:

```python
from algorithms.kmp_matcher import find_all
from algorithms.dijkstra_path import shortest_path
```

Do not copy or reimplement these algorithms inside `backend/`, scripts, or
other project directories. Backend services should adapt request/data shapes,
then delegate computation to this package. The frontend must call backend API
operations; it must not maintain a second algorithm implementation in
JavaScript. Tests live inside this directory under `tests/` and import the same
public functions used by application code.

## Modules

| Module | Public operations | Complexity and boundary |
| --- | --- | --- |
| `rsa_math.py` | `gcd`, `extended_gcd`, `mod_inverse`, `modular_power`, `crt_combine`, `rsa_private_operation_crt` | Euclid is O(log min(a,b)); square-and-multiply is O(log exponent) modular multiplications. Educational only; never protects real data. |
| `kmp_matcher.py` | `build_lps`, `find_all` | O(N + M) time and O(M) auxiliary space for one pattern/text pair. Multi-signature scans sum the per-pattern costs. |
| `randomized_quicksort.py` | `randomized_quicksort` | Expected O(N log N), theoretical O(N²). Returns a new list; seed an injected `random.Random` for repeatability. |
| `binary_search.py` | `lower_bound`, `upper_bound`, `equal_range`, `time_window_indices` | O(log N) comparisons on already-sorted in-memory values. Operational log searches must use indexed database predicates. |
| `dijkstra_path.py` | `risk_to_cost`, `shortest_path`, `PathResult` | Heap-based O((V + E) log V); requires finite non-negative costs. Blocked edges are omitted. No reachable route returns `None`. |
| `monte_carlo.py` | `estimate_proportion`, `ProportionEstimate` | O(k) to sample and inspect k records, plus O(N) only when an exact baseline is enabled within its configured limit. Samples without replacement. |

## Reproducibility and interpretation

- The sorting function accepts an injected seeded `random.Random` instance.
- The Monte Carlo function accepts a seed, reports requested and realized
  sample fractions, sample count, confidence level, interval method, run time,
  and exact-baseline status.
- The Monte Carlo interval uses a Wilson score interval with an approximate
  finite-population correction. It is an educational estimate, not a guarantee
  of calibrated threat probability.
- The graph maps bounded risk R in [1, 9] to cost W = 10 - R. Path output is a
  lowest-cost route under that heuristic, not a probability of compromise.
- RSA helpers omit production safeguards such as constant-time operations,
  standardized padding, secure key generation, and side-channel protection.

## Run the unit tests

From the repository root, with Python 3.12 or newer:

```sh
python -m unittest discover -s algorithms/tests -v
```
