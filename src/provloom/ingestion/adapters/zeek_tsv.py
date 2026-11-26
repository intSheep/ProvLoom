from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from provloom.domain.errors import AdapterReadError
from provloom.domain.raw_models import IngestBatchSpec, RawRecordInput
from provloom.ingestion.interfaces import SourceAdapter


class ZeekTsvFileAdapter(SourceAdapter):
    """Reads Bro/Zeek tab-separated log files while preserving raw lines for traceability."""

    @property
    def adapter_type(self) -> str:
        return "zeek_tsv"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        path = Path(batch_spec.source_uri)
        if not path.is_file():
            raise AdapterReadError(f"Zeek TSV source not found: {batch_spec.source_uri}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise AdapterReadError(f"Failed to read Zeek TSV file: {exc}") from exc

        separator = "\t"
        unset_field = "-"
        empty_field = "(empty)"
        zeek_path: str | None = None
        field_names: list[str] | None = None

        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#separator "):
                    sep_raw = line.split(" ", 1)[1].strip()
                    separator = "\t" if sep_raw == "\\x09" else sep_raw
                elif line.startswith("#unset_field"):
                    parts = line.split(separator, 1)
                    if len(parts) == 2:
                        unset_field = parts[1].strip()
                elif line.startswith("#empty_field"):
                    parts = line.split(separator, 1)
                    if len(parts) == 2:
                        empty_field = parts[1].strip()
                elif line.startswith("#path"):
                    parts = line.split(separator, 1)
                    if len(parts) == 2:
                        zeek_path = parts[1].strip()
                elif line.startswith("#fields"):
                    field_names = line.split(separator)[1:]
                continue

            cols = line.split(separator)
            malformed = field_names is None or len(cols) != len(field_names)
            row_dict: dict[str, str] = {}
            if not malformed and field_names is not None:
                for k, v in zip(field_names, cols, strict=True):
                    if v in {unset_field, empty_field}:
                        continue
                    row_dict[k] = v
                if zeek_path and "_path" not in row_dict:
                    row_dict["_path"] = zeek_path

            yield RawRecordInput(
                raw_payload=line,
                external_event_uid=row_dict.get("uid"),
                raw_metadata={
                    "line_no": line_no,
                    "format": "zeek_tsv",
                    "zeek_path": zeek_path,
                    "tsv_fields": row_dict,
                    "tsv_malformed": malformed,
                },
            )
