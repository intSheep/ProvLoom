from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from provloom.domain.errors import AdapterReadError
from provloom.domain.raw_models import IngestBatchSpec, RawRecordInput
from provloom.ingestion.interfaces import SourceAdapter

_EVENT_BLOCK_RE = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL | re.IGNORECASE)
_REC_ID_RE = re.compile(r"<EventRecordID>([^<]+)</EventRecordID>", re.IGNORECASE)


class XmlEventFileAdapter(SourceAdapter):
    """Reads Windows XmlWinEventLog files containing <Event>...</Event> records."""

    @property
    def adapter_type(self) -> str:
        return "xml"

    def read_records(self, batch_spec: IngestBatchSpec) -> Iterable[RawRecordInput]:
        path = Path(batch_spec.source_uri)
        if not path.is_file():
            raise AdapterReadError(f"XML source not found: {batch_spec.source_uri}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise AdapterReadError(f"Failed to read XML file: {exc}") from exc

        blocks = _EVENT_BLOCK_RE.findall(content)
        if not blocks:
            for idx, line in enumerate(content.splitlines()):
                stripped = line.strip()
                if stripped:
                    yield RawRecordInput(
                        raw_payload=stripped,
                        external_event_uid=None,
                        raw_metadata={"index": idx, "format": "xml"},
                    )
            return

        for idx, block in enumerate(blocks):
            m = _REC_ID_RE.search(block)
            uid = m.group(1).strip() if m else None
            yield RawRecordInput(
                raw_payload=block.strip(),
                external_event_uid=uid,
                raw_metadata={"index": idx, "format": "xml"},
            )
