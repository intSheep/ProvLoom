from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from pathlib import Path

from provloom.domain.errors import AdapterReadError
from provloom.domain.raw_models import IngestBatchSpec, RawRecordInput
from provloom.ingestion.interfaces import SourceAdapter


class CsvFileAdapter(SourceAdapter):
    @property
    def adapter_type(self) -> str:
        return "csv"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        path = Path(batch_spec.source_uri)
        if not path.is_file():
            raise AdapterReadError(f"CSV source not found: {batch_spec.source_uri}")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise AdapterReadError(f"Failed to read CSV file: {exc}") from exc

        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return
        reader = csv.DictReader(io.StringIO("\n".join(lines)), restkey="__extra__", restval=None)
        if not reader.fieldnames:
            raise AdapterReadError("CSV file missing header row")

        for row_idx, (raw_line, row) in enumerate(zip(lines[1:], reader), start=2):
            has_column_mismatch = "__extra__" in row or any(v is None for v in row.values())
            clean_row = {k: v for k, v in row.items() if k != "__extra__" and k is not None}
            uid = None
            for key in ("event_uid", "id", "uid", "asset_id"):
                if clean_row.get(key):
                    uid = str(clean_row[key])
                    break
            yield RawRecordInput(
                raw_payload=raw_line,
                external_event_uid=uid,
                raw_metadata={
                    "line_no": row_idx,
                    "format": "csv",
                    "csv_fields": clean_row,
                    "csv_malformed": has_column_mismatch,
                },
            )
            _ = json.dumps(clean_row)
