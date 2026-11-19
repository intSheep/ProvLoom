from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from provloom.domain.raw_models import IngestBatchSpec, IngestReceipt, RawRecordInput


class Fingerprinter(Protocol):
    """Computes deterministic SHA-256 fingerprint for raw event deduplication."""

    def compute(self, tenant_scope: str, source_id: str, raw_payload: str) -> str: ...


class SourceAdapter(Protocol):
    @property
    def adapter_type(self) -> str: ...

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]: ...


class IngestionGateway(Protocol):
    def ingest_batch(
        self, batch_spec: IngestBatchSpec, adapter: SourceAdapter
    ) -> IngestReceipt: ...
