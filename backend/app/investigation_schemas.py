"""Request and response models for analyst investigation and analytics APIs."""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


SafeIdentifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]


class LogSearchItem(BaseModel):
    occurred_at: datetime
    log_id: UUID
    source_asset_id: str | None
    destination_asset_id: str | None
    event_type: str
    ingestion_job_id: UUID | None
    severities: list[str]
    categories: list[str]


class LogSearchResponse(BaseModel):
    items: list[LogSearchItem]
    next_cursor: str | None


class AlertItem(BaseModel):
    id: UUID
    occurred_at: datetime
    detected_at: datetime
    log_id: UUID
    signature_id: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    explanation: str
    source_asset_id: str | None
    destination_asset_id: str | None
    safe_metadata: dict[str, Any]


class AlertSearchResponse(BaseModel):
    items: list[AlertItem]
    next_cursor: str | None


class TopologyNode(BaseModel):
    id: str
    label: str
    asset_type: str
    tier: str
    is_high_value: bool
    safe_metadata: dict[str, Any]


class TopologyEdge(BaseModel):
    source_id: str
    destination_id: str
    risk_score: int
    is_blocked: bool
    is_discovered: bool
    updated_at: datetime


class TopologyResponse(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


class PathRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: SafeIdentifier
    destination_id: SafeIdentifier


class PathResponse(BaseModel):
    source_id: str
    destination_id: str
    reachable: bool
    nodes: list[str]
    edge_count: int
    total_modeled_cost: float | None
    cost_interpretation: str


class ContainmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: SafeIdentifier
    destination_id: SafeIdentifier
    blocked: bool


class ContainmentResponse(BaseModel):
    source_id: str
    destination_id: str
    is_blocked: bool
    updated_at: datetime
    simulated_only: Literal[True] = True


class BenchmarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_size: int = Field(default=5_000, ge=100, le=20_000)
    seed: int = Field(default=42, ge=0, le=4_294_967_295)
    sample_fraction: float = Field(default=0.1, ge=0.01, le=0.30)


class BenchmarkResponse(BaseModel):
    run_id: UUID
    created_at: datetime
    dataset_size: int
    seed: int
    sample_fraction: float
    result: dict[str, Any]


class BenchmarkHistoryResponse(BaseModel):
    items: list[BenchmarkResponse]
    next_cursor: str | None = None
