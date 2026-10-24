"""Safe database queries and canonical algorithms for investigation routes."""

import base64
from datetime import datetime, timezone
import random
import time
from typing import Any, Callable
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from algorithms.dijkstra_path import risk_to_cost, shortest_path
from algorithms.monte_carlo import estimate_proportion
from algorithms.randomized_quicksort import randomized_quicksort
from app.repositories import record_audit_event


class CursorError(ValueError):
    pass


def encode_cursor(timestamp: datetime, record_id: UUID) -> str:
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("cursor timestamp must be timezone-aware")
    value = f"{timestamp.astimezone(timezone.utc).isoformat()}|{record_id}"
    return base64.urlsafe_b64encode(value.encode("ascii")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    if not cursor or len(cursor) > 256:
        raise CursorError("invalid_cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True).decode("ascii")
        timestamp_text, record_id_text = decoded.rsplit("|", 1)
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError
        return timestamp.astimezone(timezone.utc), UUID(record_id_text)
    except (ValueError, UnicodeDecodeError):
        raise CursorError("invalid_cursor") from None


def search_logs(
    connection: Connection,
    *,
    start: datetime | None,
    end: datetime | None,
    asset_id: str | None,
    event_type: str | None,
    query: str | None,
    severity: str | None,
    cursor: tuple[datetime, UUID] | None,
    limit: int,
) -> list[dict[str, Any]]:
    filters = ["TRUE"]
    params: list[Any] = []
    if start is not None:
        filters.append("l.occurred_at >= %s")
        params.append(start)
    if end is not None:
        filters.append("l.occurred_at < %s")
        params.append(end)
    if asset_id is not None:
        filters.append("(l.source_asset_id = %s OR l.destination_asset_id = %s)")
        params.extend((asset_id, asset_id))
    if event_type is not None:
        filters.append("l.event_type = %s")
        params.append(event_type)
    if query is not None:
        filters.append(
            "(l.log_id::text = %s OR l.event_type ILIKE %s OR l.source_asset_id = %s OR l.destination_asset_id = %s)"
        )
        params.extend((query, f"%{query}%", query, query))
    if severity is not None:
        filters.append(
            "EXISTS (SELECT 1 FROM alerts af WHERE af.occurred_at = l.occurred_at AND af.log_id = l.log_id AND af.severity = %s)"
        )
        params.append(severity)
    if cursor is not None:
        filters.append("(l.occurred_at, l.log_id) < (%s, %s)")
        params.extend(cursor)
    params.append(limit + 1)
    statement = f"""
        SELECT l.occurred_at, l.log_id, l.source_asset_id, l.destination_asset_id,
               l.event_type, l.ingestion_job_id,
               COALESCE(array_agg(DISTINCT a.severity) FILTER (WHERE a.id IS NOT NULL), ARRAY[]::text[]) AS severities,
               COALESCE(array_agg(DISTINCT a.category) FILTER (WHERE a.id IS NOT NULL), ARRAY[]::text[]) AS categories
        FROM security_logs l
        LEFT JOIN alerts a ON a.occurred_at = l.occurred_at AND a.log_id = l.log_id
        WHERE {' AND '.join(filters)}
        GROUP BY l.occurred_at, l.log_id, l.source_asset_id, l.destination_asset_id,
                 l.event_type, l.ingestion_job_id
        ORDER BY l.occurred_at DESC, l.log_id DESC
        LIMIT %s
    """
    with connection.cursor(row_factory=dict_row) as db_cursor:
        return db_cursor.execute(statement, params).fetchall()


def search_alerts(
    connection: Connection,
    *,
    start: datetime | None,
    end: datetime | None,
    severity: str | None,
    category: str | None,
    asset_id: str | None,
    cursor: tuple[datetime, UUID] | None,
    limit: int,
) -> list[dict[str, Any]]:
    filters = ["TRUE"]
    params: list[Any] = []
    if start is not None:
        filters.append("a.detected_at >= %s")
        params.append(start)
    if end is not None:
        filters.append("a.detected_at < %s")
        params.append(end)
    if severity is not None:
        filters.append("a.severity = %s")
        params.append(severity)
    if category is not None:
        filters.append("a.category = %s")
        params.append(category)
    if asset_id is not None:
        filters.append("(a.source_asset_id = %s OR a.destination_asset_id = %s)")
        params.extend((asset_id, asset_id))
    if cursor is not None:
        filters.append("(a.detected_at, a.id) < (%s, %s)")
        params.extend(cursor)
    params.append(limit + 1)
    statement = f"""
        SELECT a.id, a.occurred_at, a.detected_at, a.log_id, a.signature_id,
               a.category, a.severity, a.explanation, a.source_asset_id,
               a.destination_asset_id, a.safe_metadata
        FROM alerts a
        WHERE {' AND '.join(filters)}
        ORDER BY a.detected_at DESC, a.id DESC
        LIMIT %s
    """
    with connection.cursor(row_factory=dict_row) as db_cursor:
        return db_cursor.execute(statement, params).fetchall()


def get_topology(connection: Connection) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with connection.cursor(row_factory=dict_row) as cursor:
        nodes = cursor.execute(
            """
            SELECT id, label, asset_type, tier, is_high_value, safe_metadata
            FROM topology_nodes ORDER BY id
            """
        ).fetchall()
        edges = cursor.execute(
            """
            SELECT source_id, destination_id, risk_score, is_blocked, is_discovered, updated_at
            FROM topology_edges ORDER BY source_id, destination_id
            """
        ).fetchall()
    return nodes, edges


def analyze_path(
    connection: Connection, source_id: str, destination_id: str
) -> dict[str, Any] | None:
    with connection.cursor() as cursor:
        node_ids = {
            row[0]
            for row in cursor.execute("SELECT id FROM topology_nodes").fetchall()
        }
        if source_id not in node_ids or destination_id not in node_ids:
            return None
        edge_rows = cursor.execute(
            """
            SELECT source_id, destination_id, risk_score
            FROM topology_edges WHERE is_blocked = FALSE
            """
        ).fetchall()
    graph: dict[str, list[tuple[str, float]]] = {node_id: [] for node_id in node_ids}
    for source, destination, risk_score in edge_rows:
        # DB risk is 0..10; normalize linearly to the algorithm's documented 1..9 scale.
        normalized_risk = 1 + (8 * risk_score / 10)
        graph[source].append((destination, risk_to_cost(normalized_risk)))
    result = shortest_path(graph, source_id, destination_id)
    return {
        "source_id": source_id,
        "destination_id": destination_id,
        "reachable": result is not None,
        "nodes": list(result.nodes) if result else [],
        "edge_count": len(result.nodes) - 1 if result else 0,
        "total_modeled_cost": round(result.total_cost, 4) if result else None,
        "cost_interpretation": "Modeled path cost under the risk-to-cost heuristic; it is not a probability of compromise.",
    }


def set_edge_containment(
    connection: Connection,
    *,
    source_id: str,
    destination_id: str,
    blocked: bool,
    actor_id: UUID,
) -> dict[str, Any] | None:
    with connection.transaction():
        with connection.cursor(row_factory=dict_row) as cursor:
            edge = cursor.execute(
                """
                SELECT source_id, destination_id, is_blocked, updated_at
                FROM topology_edges WHERE source_id = %s AND destination_id = %s
                FOR UPDATE
                """,
                (source_id, destination_id),
            ).fetchone()
            if edge is None:
                return None
            updated = cursor.execute(
                """
                UPDATE topology_edges SET is_blocked = %s, updated_at = now()
                WHERE source_id = %s AND destination_id = %s
                RETURNING source_id, destination_id, is_blocked, updated_at
                """,
                (blocked, source_id, destination_id),
            ).fetchone()
        record_audit_event(
            connection,
            actor_id=actor_id,
            action="topology.containment_simulated",
            outcome="success",
            target_type="topology_edge",
            target_id=f"{source_id}->{destination_id}",
            safe_metadata={"blocked": blocked, "changed": edge["is_blocked"] != blocked},
        )
    return updated


def run_benchmark(
    connection: Connection,
    *,
    actor_id: UUID,
    dataset_size: int,
    seed: int,
    sample_fraction: float,
) -> dict[str, Any]:
    generator = random.Random(seed)
    values = [generator.randrange(1_000_000) for _ in range(dataset_size)]

    started = time.perf_counter()
    quick_sorted = randomized_quicksort(values, rng=random.Random(seed))
    quicksort_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    reference_sorted = sorted(values)
    builtin_sort_ms = (time.perf_counter() - started) * 1000

    estimate = estimate_proportion(
        values,
        lambda value: value >= 500_000,
        sample_fraction,
        seed=seed,
        exact_baseline_limit=10_000,
    )
    result = {
        "sorting": {
            "algorithm": "randomized_three_way_quicksort",
            "elapsed_ms": round(quicksort_ms, 4),
            "reference": "Python built-in sorted",
            "reference_elapsed_ms": round(builtin_sort_ms, 4),
            "output_matches_reference": quick_sorted == reference_sorted,
        },
        "sampling": {
            "algorithm": "finite_population_monte_carlo",
            "predicate": "value >= 500000",
            "estimate": estimate.estimate,
            "confidence_interval": list(estimate.confidence_interval),
            "confidence_level": estimate.confidence_level,
            "interval_method": estimate.interval_method,
            "sample_count": estimate.sample_count,
            "population_size": estimate.population_size,
            "requested_sample_fraction": estimate.requested_sample_fraction,
            "actual_sample_fraction": estimate.actual_sample_fraction,
            "sampled_successes": estimate.sampled_successes,
            "exact_baseline": estimate.exact_baseline,
            "baseline_status": estimate.baseline_status,
            "elapsed_ms": round(estimate.elapsed_ms, 4),
        },
    }
    run_id = uuid4()
    params = {
        "dataset_size": dataset_size,
        "seed": seed,
        "sample_fraction": sample_fraction,
        "synthetic_value_range": "[0, 1000000)",
    }
    with connection.cursor(row_factory=dict_row) as cursor:
        row = cursor.execute(
            """
            INSERT INTO benchmark_runs (id, actor_id, dataset_size, seed, sample_fraction, parameters, result)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, dataset_size, seed, sample_fraction, result
            """,
            (run_id, actor_id, dataset_size, seed, sample_fraction, Jsonb(params), Jsonb(result)),
        ).fetchone()
    record_audit_event(
        connection,
        actor_id=actor_id,
        action="analytics.benchmark_run",
        outcome="success",
        target_type="benchmark_run",
        target_id=str(run_id),
        safe_metadata={"dataset_size": dataset_size, "seed": seed},
    )
    return row


def get_benchmark_history(
    connection: Connection, *, cursor_value: tuple[datetime, UUID] | None, limit: int
) -> list[dict[str, Any]]:
    if cursor_value is None:
        query = """
            SELECT id, created_at, dataset_size, seed, sample_fraction, result
            FROM benchmark_runs ORDER BY created_at DESC, id DESC LIMIT %s
        """
        params: tuple[Any, ...] = (limit + 1,)
    else:
        query = """
            SELECT id, created_at, dataset_size, seed, sample_fraction, result
            FROM benchmark_runs WHERE (created_at, id) < (%s, %s)
            ORDER BY created_at DESC, id DESC LIMIT %s
        """
        params = (*cursor_value, limit + 1)
    with connection.cursor(row_factory=dict_row) as db_cursor:
        return db_cursor.execute(query, params).fetchall()


def alert_stream_batch(
    connection_factory: Callable[[], Connection],
    *,
    cursor_value: tuple[datetime, UUID] | None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    with connection_factory() as connection:
        if cursor_value is None:
            statement = """
                SELECT * FROM (
                    SELECT id, occurred_at, detected_at, log_id, signature_id, category,
                           severity, explanation, source_asset_id, destination_asset_id, safe_metadata
                    FROM alerts ORDER BY detected_at DESC, id DESC LIMIT %s
                ) recent ORDER BY detected_at, id
            """
            params: tuple[Any, ...] = (limit,)
        else:
            statement = """
                SELECT id, occurred_at, detected_at, log_id, signature_id, category,
                       severity, explanation, source_asset_id, destination_asset_id, safe_metadata
                FROM alerts WHERE (detected_at, id) > (%s, %s)
                ORDER BY detected_at, id LIMIT %s
            """
            params = (*cursor_value, limit)
        with connection.cursor(row_factory=dict_row) as db_cursor:
            return db_cursor.execute(statement, params).fetchall()
