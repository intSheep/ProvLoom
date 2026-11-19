from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from provloom.domain.errors import AdapterReadError
from provloom.domain.raw_models import IngestBatchSpec, RawRecordInput
from provloom.ingestion.interfaces import SourceAdapter


def _extract_uid(obj: dict[str, object]) -> str | None:
    for key in ("EventRecordID", "uid", "event_uid", "id", "asset_id"):
        val = obj.get(key)
        if val is not None and str(val).strip():
            return str(val)
    return None


class JsonFileAdapter(SourceAdapter):
    @property
    def adapter_type(self) -> str:
        return "json"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        path = Path(batch_spec.source_uri)
        if not path.is_file():
            raise AdapterReadError(f"JSON source not found: {batch_spec.source_uri}")
        try:
            content = path.read_text(encoding="utf-8")
            parsed = json.loads(content)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterReadError(f"Failed to read JSON file: {exc}") from exc

        items = parsed if isinstance(parsed, list) else [parsed]
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                raise AdapterReadError(f"JSON element at index {idx} is not an object")
            raw_text = json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            yield RawRecordInput(
                raw_payload=raw_text,
                external_event_uid=_extract_uid(item),
                raw_metadata={"index": idx, "format": "json"},
            )


class JsonlFileAdapter(SourceAdapter):
    @property
    def adapter_type(self) -> str:
        return "jsonl"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        path = Path(batch_spec.source_uri)
        if not path.is_file():
            raise AdapterReadError(f"JSONL source not found: {batch_spec.source_uri}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise AdapterReadError(f"Failed to decode JSONL file: {exc}") from exc

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            uid: str | None = None
            try:
                maybe_obj = json.loads(stripped)
                if isinstance(maybe_obj, dict):
                    uid = _extract_uid(maybe_obj)
            except json.JSONDecodeError:
                # Keep malformed line in raw_events so parser stage logs a traceable PARSE failure.
                uid = None
            yield RawRecordInput(
                raw_payload=stripped,
                external_event_uid=uid,
                raw_metadata={"line_no": line_no, "format": "jsonl"},
            )
