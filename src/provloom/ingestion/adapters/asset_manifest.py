from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from provloom.domain.raw_models import IngestBatchSpec, RawRecordInput
from provloom.ingestion.adapters.csv_file import CsvFileAdapter
from provloom.ingestion.adapters.json_file import JsonFileAdapter, JsonlFileAdapter
from provloom.ingestion.interfaces import SourceAdapter


class AssetManifestAdapter(SourceAdapter):
    @property
    def adapter_type(self) -> str:
        return "asset"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        suffix = Path(batch_spec.source_uri).suffix.lower()
        delegate: SourceAdapter
        if suffix == ".csv":
            delegate = CsvFileAdapter()
        elif suffix == ".jsonl":
            delegate = JsonlFileAdapter()
        else:
            delegate = JsonFileAdapter()
        yield from delegate.read_records(batch_spec)
