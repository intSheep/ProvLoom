from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from provloom.domain.common import AccessScope, TimeRange


@dataclass(frozen=True)
class RetryReceipt:
    attempted: int
    succeeded: int
    failed: int


@dataclass(frozen=True)
class ReplayReceipt:
    replayed_raw_events: int
    rebuilt_entities: int
    rebuilt_relations: int


class PipelineOrchestrator(Protocol):
    def process_batch(self, batch_id: UUID) -> None: ...
    def retry_failures(
        self, scope: AccessScope, batch_id: UUID | None = None, limit: int = 500
    ) -> RetryReceipt: ...


class ReplayService(Protocol):
    """Re-parses immutable raw_events and deterministically rebuilds OCSF events and graph."""

    def rebuild_from_raw(
        self,
        scope: AccessScope,
        time_range: TimeRange | None = None,
        batch_ids: Sequence[UUID] | None = None,
    ) -> ReplayReceipt: ...
